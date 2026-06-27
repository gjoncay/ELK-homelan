#!/usr/bin/env python3
"""Generate a Kibana saved-objects NDJSON for the Zeek threat-hunting dashboard.

Produces: a data view (logs-zeek.*) WITH a `device.name` runtime field
(source.ip -> friendly name, IP fallback) + one dashboard of by-reference Lens
panels covering notices, weird, DNS anomalies, TLS/cert hygiene, exfil/long
connections, geo, uncommon ports, and files+hashes.

Import with:  POST /api/saved_objects/_import?overwrite=true  (multipart 'file').
Reproducible / upgrade-safe: re-run + re-import to recreate.

Version stamps per kibana-saved-object-import notes:
  lens typeMigrationVersion 8.9.0, dashboard 10.3.0, coreMigrationVersion 8.8.0,
  index-pattern left unstamped.
"""
import json, os

DV_ID = "zeek-threat-data-view"
DV_TITLE = "logs-zeek.*"
LAN = "192.168.88.0/24"

# device.name runtime field: maps an internal source IP to a friendly name.
# Loaded from local devices.local configuration if present (which is ignored by Git).
DEVICE_MAP = {}
devices_file = os.path.join(os.path.dirname(__file__), "devices.local")
if os.path.exists(devices_file):
    try:
        with open(devices_file, "r") as f:
            DEVICE_MAP = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load local device map from {devices_file}: {e}")

if not DEVICE_MAP:
    # Generic template fallback if no local file exists
    DEVICE_MAP = {
        "192.168.88.251": "Laptop-1",
        "192.168.88.244": "Smart-TV",
    }

def build_device_script(device_map):
    lines = [
        "if (!doc.containsKey('source.ip') || doc['source.ip'].size()==0) { emit('unknown'); return; }",
        "String ip = doc['source.ip'].value;",
        "Map m = new HashMap();",
    ]
    for ip, name in device_map.items():
        lines.append("m.put('%s', '%s');" % (ip, name.replace("'", "")))
    lines.append("emit(m.containsKey(ip) ? (String) m.get(ip) : ip);")
    return "\n".join(lines)

DEVICE_SCRIPT = build_device_script(DEVICE_MAP)

# ---- column helpers --------------------------------------------------------
def count_col(col_id="m_count", label="Count"):
    return col_id, {
        "label": label, "dataType": "number", "operationType": "count",
        "sourceField": "___records___", "isBucketed": False, "scale": "ratio",
        "params": {"emptyAsNull": False},
    }

def sum_col(field, col_id="m_sum", label="Bytes", as_bytes=True):
    params = {"emptyAsNull": True}
    if as_bytes:
        params["format"] = {"id": "bytes", "params": {"decimals": 1}}
    return col_id, {
        "label": label, "dataType": "number", "operationType": "sum",
        "sourceField": field, "isBucketed": False, "scale": "ratio", "params": params,
    }

def max_col(field, col_id, label, suffix=None):
    col = {"label": label, "dataType": "number", "operationType": "max",
           "sourceField": field, "isBucketed": False, "scale": "ratio",
           "params": {"emptyAsNull": True}}
    return col_id, col

def avg_col(field, col_id, label):
    return col_id, {
        "label": label, "dataType": "number", "operationType": "average",
        "sourceField": field, "isBucketed": False, "scale": "ratio",
        "params": {"emptyAsNull": True,
                   "format": {"id": "number", "params": {"decimals": 2}}},
    }

def terms_col(field, col_id, metric_id, size=10, label=None, dtype="string",
              order="desc", other=True, missing=False):
    return col_id, {
        "label": label or f"Top {field}", "dataType": dtype,
        "operationType": "terms", "sourceField": field, "isBucketed": True,
        "scale": "ordinal",
        "params": {"size": size, "orderBy": {"type": "column", "columnId": metric_id},
                   "orderDirection": order, "otherBucket": other,
                   "missingBucket": missing, "parentFormat": {"id": "terms"}},
    }

def lens_attrs(title, vis_type, layer_id, columns, column_order, visualization, query=""):
    attrs = {
        "title": title, "visualizationType": vis_type,
        "state": {
            "visualization": visualization,
            "query": {"query": query, "language": "kuery"},
            "filters": [],
            "datasourceStates": {"formBased": {"layers": {
                layer_id: {"columns": columns, "columnOrder": column_order,
                           "incompleteColumns": {}}
            }}},
            "internalReferences": [], "adHocDataViews": {},
        },
    }
    refs = [{"type": "index-pattern", "id": DV_ID,
             "name": f"indexpattern-datasource-layer-{layer_id}"}]
    return attrs, refs

def datatable(title, lid, cols_in_order, query, page=10):
    """cols_in_order: list of (col_id, col_def, align_right_bool)."""
    columns = {cid: cdef for cid, cdef, _ in cols_in_order}
    order = [cid for cid, _, _ in cols_in_order]
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": cid, "isTransposed": False,
                        **({"alignment": "right"} if ar else {})}
                       for cid, _, ar in cols_in_order],
           "paging": {"size": page, "enabled": True}}
    return lens_attrs(title, "lnsDatatable", lid, columns, order, vis, query=query)

def pie(title, lid, term_field, dtype="string", size=8, query="", label=None):
    m_id, m_col = count_col(label="Count")
    t_id, t_col = terms_col(term_field, "b_t", m_id, size=size, label=label or term_field,
                            dtype=dtype)
    vis = {"shape": "pie", "layers": [{"layerId": lid, "layerType": "data",
            "primaryGroups": [t_id], "metrics": [m_id], "numberDisplay": "percent",
            "categoryDisplay": "default", "legendDisplay": "default",
            "nestedLegend": False}]}
    return lens_attrs(title, "lnsPie", lid, {t_id: t_col, m_id: m_col}, [t_id, m_id],
                      vis, query=query)

def metric(title, lid, col_tuple, query="", color=None):
    m_id, m_col = col_tuple
    vis = {"layerId": lid, "layerType": "data", "metricAccessor": m_id}
    return lens_attrs(title, "lnsMetric", lid, {m_id: m_col}, [m_id], vis, query=query)

# ---- panels ----------------------------------------------------------------
DS = lambda d: f'event.dataset: "{d}"'

def p_capture_loss():
    return metric("Capture loss % (avg)", "L_cl",
                  avg_col("zeek.capture_loss.percent_lost", "m_cl", "% packets lost"),
                  query=DS("zeek.capture_loss"))

def p_notice_count():
    return metric("Zeek notices", "L_nc", count_col(label="Notices"),
                  query=DS("zeek.notice"))

def p_weird_count():
    return metric("Weird events", "L_wc", count_col(label="Weird"),
                  query=DS("zeek.weird"))

def p_nxdomain_count():
    return metric("DNS NXDOMAIN responses", "L_nx", count_col(label="NXDOMAIN"),
                  query=f'{DS("zeek.dns")} and zeek.dns.rcode_name: "NXDOMAIN"')

def p_notices():
    lid = "L_notices"
    m_id, m_col = count_col()
    n_id, n_col = terms_col("zeek.notice.note", "b_note", m_id, size=20,
                            label="Notice type")
    msg_id, msg_col = terms_col("zeek.notice.msg", "b_msg", m_id, size=1,
                                label="Message", other=False, missing=True)
    return datatable("Zeek Notices (built-in detections)", lid,
                     [(n_id, n_col, False), (msg_id, msg_col, False),
                      (m_id, m_col, True)], DS("zeek.notice"))

def p_weird():
    lid = "L_weird"
    m_id, m_col = count_col()
    w_id, w_col = terms_col("zeek.weird.name", "b_w", m_id, size=20,
                            label="Weird name")
    d_id, d_col = terms_col("device.name", "b_wd", m_id, size=1, label="Device",
                            other=False, missing=True)
    return datatable("Weird / protocol anomalies (by type & device)", lid,
                     [(w_id, w_col, False), (d_id, d_col, False),
                      (m_id, m_col, True)], DS("zeek.weird"))

def p_nxdomain():
    lid = "L_nxd"
    m_id, m_col = count_col()
    d_id, d_col = terms_col("device.name", "b_d", m_id, size=15, label="Device")
    q_id, q_col = terms_col("zeek.dns.query", "b_q", m_id, size=1, label="Domain",
                            other=False, missing=True)
    return datatable("DNS NXDOMAIN by device (DGA / C2 indicator)", lid,
                     [(d_id, d_col, False), (q_id, q_col, False), (m_id, m_col, True)],
                     f'{DS("zeek.dns")} and zeek.dns.rcode_name: "NXDOMAIN"')

def p_top_dns():
    lid = "L_dns"
    m_id, m_col = count_col(label="Queries")
    q_id, q_col = terms_col("zeek.dns.query", "b_q2", m_id, size=20, label="Domain")
    d_id, d_col = terms_col("device.name", "b_dd", m_id, size=1, label="Top device",
                            other=False, missing=True)
    return datatable("Top DNS queries (by volume)", lid,
                     [(q_id, q_col, False), (d_id, d_col, False), (m_id, m_col, True)],
                     DS("zeek.dns"))

def p_cert_issues():
    lid = "L_cert"
    m_id, m_col = count_col()
    s_id, s_col = terms_col("zeek.ssl.server.name", "b_sni", m_id, size=20, label="SNI / server")
    v_id, v_col = terms_col("zeek.ssl.validation.status", "b_vs", m_id, size=1,
                            label="Validation status", other=False, missing=True)
    dev_id, dev_col = terms_col("device.name", "b_cd", m_id, size=1, label="Device",
                                other=False, missing=True)
    # Anything whose cert did not validate cleanly.
    q = f'{DS("zeek.ssl")} and zeek.ssl.validation.status: * and not zeek.ssl.validation.status: "ok"'
    return datatable("TLS certificate validation issues", lid,
                     [(s_id, s_col, False), (v_id, v_col, False),
                      (dev_id, dev_col, False), (m_id, m_col, True)], q)

def p_top_sni():
    lid = "L_sni"
    m_id, m_col = count_col(label="TLS conns")
    s_id, s_col = terms_col("zeek.ssl.server.name", "b_sni2", m_id, size=20, label="SNI / server name")
    d_id, d_col = terms_col("device.name", "b_sd", m_id, size=1, label="Top device",
                            other=False, missing=True)
    return datatable("Top TLS destinations (SNI)", lid,
                     [(s_id, s_col, False), (d_id, d_col, False), (m_id, m_col, True)],
                     DS("zeek.ssl"))

def p_tls_versions():
    return pie("TLS versions", "L_tlsv", "tls.version", size=8,
               query=DS("zeek.ssl"), label="TLS version")

def p_country():
    return pie("External destinations by country", "L_cc",
               "destination.geo.country_name", size=10,
               query=f'{DS("zeek.connection")} and not destination.ip: "{LAN}"',
               label="Country")

def p_uncommon_ports():
    lid = "L_ports"
    m_id, m_col = count_col(label="Connections")
    p_id, p_col = terms_col("destination.port", "b_p", m_id, size=20,
                            label="Destination port", dtype="number")
    q = (f'{DS("zeek.connection")} and not destination.ip: "{LAN}" '
         f'and not destination.port: (443 or 80 or 53 or 123 or 853 or 123)')
    return datatable("Connections to uncommon ports", lid,
                     [(p_id, p_col, False), (m_id, m_col, True)], q)

def p_exfil():
    lid = "L_exfil"
    m_id, m_col = sum_col("source.bytes", "m_sb", label="Bytes sent (out)")
    d_id, d_col = terms_col("device.name", "b_ed", m_id, size=10, label="Device")
    dst_id, dst_col = terms_col("destination.ip", "b_edst", m_id, size=1,
                                label="Top destination", dtype="ip",
                                other=False, missing=True)
    q = f'{DS("zeek.connection")} and source.ip: "{LAN}" and not destination.ip: "{LAN}"'
    return datatable("Data egress by device (bytes sent out)", lid,
                     [(d_id, d_col, False), (dst_id, dst_col, False),
                      (m_id, m_col, True)], q)

def p_long_conns():
    lid = "L_long"
    m_id, m_col = max_col("event.duration", "m_dur", "Max duration (ns)")
    d_id, d_col = terms_col("device.name", "b_ld", m_id, size=15, label="Device")
    dst_id, dst_col = terms_col("destination.ip", "b_ldst", m_id, size=1,
                                label="Destination", dtype="ip",
                                other=False, missing=True)
    pt_id, pt_col = terms_col("destination.port", "b_lp", m_id, size=1,
                              label="Port", dtype="number", other=False, missing=True)
    q = f'{DS("zeek.connection")} and source.ip: "{LAN}"'
    return datatable("Longest-lived connections (persistent / C2)", lid,
                     [(d_id, d_col, False), (dst_id, dst_col, False),
                      (pt_id, pt_col, False), (m_id, m_col, True)], q)

def p_files():
    lid = "L_files"
    m_id, m_col = count_col(label="Seen")
    mime_id, mime_col = terms_col("file.mime_type", "b_mime", m_id, size=20,
                                  label="MIME type")
    sha_id, sha_col = terms_col("file.hash.sha1", "b_sha", m_id, size=1,
                                label="SHA1", other=False, missing=True)
    dev_id, dev_col = terms_col("device.name", "b_fd", m_id, size=1, label="Device",
                                other=False, missing=True)
    return datatable("Files seen (MIME + SHA1 for lookup)", lid,
                     [(mime_id, mime_col, False), (sha_id, sha_col, False),
                      (dev_id, dev_col, False), (m_id, m_col, True)], DS("zeek.files"))

# ---- assemble --------------------------------------------------------------
LAYOUT = [
    ("cl",     p_capture_loss,   {"x": 0,  "y": 0,  "w": 12, "h": 7}),
    ("nc",     p_notice_count,   {"x": 12, "y": 0,  "w": 12, "h": 7}),
    ("wc",     p_weird_count,    {"x": 24, "y": 0,  "w": 12, "h": 7}),
    ("nx",     p_nxdomain_count, {"x": 36, "y": 0,  "w": 12, "h": 7}),
    ("notices", p_notices,       {"x": 0,  "y": 7,  "w": 24, "h": 14}),
    ("weird",  p_weird,          {"x": 24, "y": 7,  "w": 24, "h": 14}),
    ("nxd",    p_nxdomain,       {"x": 0,  "y": 21, "w": 24, "h": 14}),
    ("topdns", p_top_dns,        {"x": 24, "y": 21, "w": 24, "h": 14}),
    ("cert",   p_cert_issues,    {"x": 0,  "y": 35, "w": 24, "h": 14}),
    ("sni",    p_top_sni,        {"x": 24, "y": 35, "w": 24, "h": 14}),
    ("tlsv",   p_tls_versions,   {"x": 0,  "y": 49, "w": 12, "h": 14}),
    ("cc",     p_country,        {"x": 12, "y": 49, "w": 12, "h": 14}),
    ("ports",  p_uncommon_ports, {"x": 24, "y": 49, "w": 24, "h": 14}),
    ("exfil",  p_exfil,          {"x": 0,  "y": 63, "w": 24, "h": 14}),
    ("long",   p_long_conns,     {"x": 24, "y": 63, "w": 24, "h": 14}),
    ("files",  p_files,          {"x": 0,  "y": 77, "w": 48, "h": 14}),
]

panels, dash_refs, lens_objects = [], [], []
for key, builder, grid in LAYOUT:
    pidx = f"panel_{key}"
    lens_id = f"zeek-threat-{key}"
    attrs, refs = builder()
    lens_objects.append({
        "type": "lens", "id": lens_id, "attributes": attrs, "references": refs,
        "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "8.9.0",
    })
    dash_refs.append({"type": "lens", "id": lens_id, "name": pidx})
    panels.append({
        "type": "lens", "gridData": {**grid, "i": pidx}, "panelIndex": pidx,
        "embeddableConfig": {"enhancements": {}}, "panelRefName": pidx,
        "title": attrs["title"], "version": "8.19.11",
    })

dashboard = {
    "type": "dashboard", "id": "zeek-threat-overview",
    "attributes": {
        "title": "Zeek — Threat Hunting",
        "description": "Protocol-level threat signals from Zeek (WAN+LAN sniffer): "
                       "notices, weird, DNS anomalies, TLS/cert hygiene, exfil, geo, files.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                   "syncCursor": True, "syncTooltips": False,
                                   "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": dash_refs,
    "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.3.0",
}

data_view = {
    "type": "index-pattern", "id": DV_ID,
    "attributes": {
        "title": DV_TITLE, "name": "Zeek", "timeFieldName": "@timestamp",
        "runtimeFieldMap": json.dumps({
            "device.name": {"type": "keyword", "script": {"source": DEVICE_SCRIPT}}
        }),
    },
    "references": [],
}

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeek_threat_dashboard.ndjson")
with open(OUT, "w") as f:
    f.write(json.dumps(data_view) + "\n")
    for lo in lens_objects:
        f.write(json.dumps(lo) + "\n")
    f.write(json.dumps(dashboard) + "\n")

print("wrote", OUT, "with", len(panels), "panels +", len(lens_objects),
      "lens objects + 1 data view (device.name map has", len(DEVICE_MAP), "entries)")
