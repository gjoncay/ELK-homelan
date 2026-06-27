#!/usr/bin/env python3
"""Generate a Kibana saved-objects NDJSON for the MikroTik NetFlow overview dashboard.

Produces: a data view (logs-netflow.*) + one dashboard with by-value Lens panels.
Import with:  POST /api/saved_objects/_import?overwrite=true  (multipart 'file').
Reproducible / upgrade-safe: re-run + re-import to recreate.
"""
import json

DV_ID = "netflow-data-view"
DV_TITLE = "logs-netflow.*"
LAN = "192.168.88.0/24"

# ---- helpers ---------------------------------------------------------------
def sum_bytes(col_id="m_bytes", label="Total bytes"):
    return col_id, {
        "label": label, "dataType": "number", "operationType": "sum",
        "sourceField": "network.bytes", "isBucketed": False, "scale": "ratio",
        # "bytes" formatter renders human-readable units (KB/MB/GB/TB).
        "params": {"emptyAsNull": True,
                   "format": {"id": "bytes", "params": {"decimals": 1}}},
    }

def terms_col(field, col_id, metric_id, size=10, label=None, dtype="string"):
    return col_id, {
        "label": label or f"Top {size} {field}", "dataType": dtype,
        "operationType": "terms", "sourceField": field, "isBucketed": True,
        "scale": "ordinal",
        "params": {"size": size, "orderBy": {"type": "column", "columnId": metric_id},
                   "orderDirection": "desc", "otherBucket": True, "missingBucket": False,
                   "parentFormat": {"id": "terms"}},
    }

def date_col(col_id="b_time"):
    return col_id, {
        "label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
        "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }

def lens_attrs(title, vis_type, layer_id, columns, column_order, visualization, query="", filters=None):
    attrs = {
        "title": title,
        "visualizationType": vis_type,
        "state": {
            "visualization": visualization,
            "query": {"query": query, "language": "kuery"},
            "filters": filters or [],
            "datasourceStates": {"formBased": {"layers": {
                layer_id: {"columns": columns, "columnOrder": column_order, "incompleteColumns": {}}
            }}},
            "internalReferences": [],
            "adHocDataViews": {},
        },
    }
    refs = [{"type": "index-pattern", "id": DV_ID,
             "name": f"indexpattern-datasource-layer-{layer_id}"}]
    return attrs, refs

# ---- panel builders --------------------------------------------------------
def metric_total():
    lid = "L_metric"
    m_id, m_col = sum_bytes(label="Total traffic (bytes)")
    vis = {"layerId": lid, "layerType": "data", "metricAccessor": m_id}
    return lens_attrs("Total traffic (30d window)", "lnsMetric", lid,
                      {m_id: m_col}, [m_id], vis)

def xy_over_time():
    lid = "L_xy"
    b_id, b_col = date_col()
    s_id, s_col = terms_col("flow.locality", "b_split", "m_bytes", size=5,
                            label="flow.locality")
    m_id, m_col = sum_bytes()
    vis = {"legend": {"isVisible": True, "position": "right"}, "valueLabels": "hide",
           "fittingFunction": "None", "preferredSeriesType": "area_stacked",
           "layers": [{"layerId": lid, "accessors": [m_id], "position": "top",
                       "seriesType": "area_stacked", "showGridlines": False,
                       "layerType": "data", "xAccessor": b_id, "splitAccessor": s_id}]}
    return lens_attrs("Traffic over time (by locality)", "lnsXY", lid,
                      {b_id: b_col, s_id: s_col, m_id: m_col}, [b_id, s_id, m_id], vis)

def table_top_internal():
    lid = "L_int"
    m_id, m_col = sum_bytes(label="Bytes")
    t_id, t_col = terms_col("source.ip", "b_ip", m_id, size=15,
                            label="Internal device (source.ip)", dtype="ip")
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": t_id, "isTransposed": False},
                       {"columnId": m_id, "isTransposed": False, "alignment": "right"}],
           "paging": {"size": 10, "enabled": True}}
    return lens_attrs("Top internal talkers (outbound source)", "lnsDatatable", lid,
                      {t_id: t_col, m_id: m_col}, [t_id, m_id], vis,
                      query=f'source.ip: "{LAN}"')

def table_top_external():
    lid = "L_ext"
    m_id, m_col = sum_bytes(label="Bytes")
    t_id, t_col = terms_col("destination.ip", "b_dip", m_id, size=15,
                            label="External destination (destination.ip)", dtype="ip")
    # Nested: the top domain for each IP (from DNS enrichment). size=1 since an
    # IP usually maps to one recent domain; shows "(no domain yet)" when missing.
    d_id, d_col = terms_col("destination.domain", "b_ddom", m_id, size=1,
                            label="Domain", dtype="string")
    d_col["params"]["otherBucket"] = False
    d_col["params"]["missingBucket"] = True
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": t_id, "isTransposed": False},
                       {"columnId": d_id, "isTransposed": False},
                       {"columnId": m_id, "isTransposed": False, "alignment": "right"}],
           "paging": {"size": 10, "enabled": True}}
    return lens_attrs("Top external destinations", "lnsDatatable", lid,
                      {t_id: t_col, d_id: d_col, m_id: m_col}, [t_id, d_id, m_id], vis,
                      query=f'not destination.ip: "{LAN}"')

def table_top_domains():
    lid = "L_dom"
    m_id, m_col = sum_bytes(label="Bytes")
    t_id, t_col = terms_col("destination.domain", "b_dom", m_id, size=20,
                            label="Destination domain", dtype="string")
    vis = {"layerId": lid, "layerType": "data",
           "columns": [{"columnId": t_id, "isTransposed": False},
                       {"columnId": m_id, "isTransposed": False, "alignment": "right"}],
           "paging": {"size": 10, "enabled": True}}
    # Only rows that have been resolved to a domain via DNS enrichment.
    return lens_attrs("Top destination domains (by bytes)", "lnsDatatable", lid,
                      {t_id: t_col, m_id: m_col}, [t_id, m_id], vis,
                      query="destination.domain: *")

def pie_country():
    lid = "L_geo"
    m_id, m_col = sum_bytes(label="Bytes")
    t_id, t_col = terms_col("destination.geo.country_iso_code", "b_cc", m_id, size=10,
                            label="Destination country")
    vis = {"shape": "pie", "layers": [{"layerId": lid, "layerType": "data",
            "primaryGroups": [t_id], "metrics": [m_id], "numberDisplay": "percent",
            "categoryDisplay": "default", "legendDisplay": "default",
            "nestedLegend": False, "layerType": "data"}]}
    return lens_attrs("Bytes by destination country", "lnsPie", lid,
                      {t_id: t_col, m_id: m_col}, [t_id, m_id], vis)

def pie_proto():
    lid = "L_proto"
    m_id, m_col = sum_bytes(label="Bytes")
    t_id, t_col = terms_col("network.transport", "b_tr", m_id, size=10,
                            label="Transport")
    vis = {"shape": "pie", "layers": [{"layerId": lid, "layerType": "data",
            "primaryGroups": [t_id], "metrics": [m_id], "numberDisplay": "percent",
            "categoryDisplay": "default", "legendDisplay": "default",
            "nestedLegend": False, "layerType": "data"}]}
    return lens_attrs("Bytes by transport protocol", "lnsPie", lid,
                      {t_id: t_col, m_id: m_col}, [t_id, m_id], vis)

# ---- assemble dashboard ----------------------------------------------------
# grid is 48 columns wide
LAYOUT = [
    ("metric",   metric_total,        {"x": 0,  "y": 0,  "w": 12, "h": 8}),
    ("xy",       xy_over_time,        {"x": 12, "y": 0,  "w": 36, "h": 15}),
    ("proto",    pie_proto,           {"x": 0,  "y": 8,  "w": 12, "h": 15}),
    ("geo",      pie_country,         {"x": 12, "y": 15, "w": 18, "h": 15}),
    ("intl",     table_top_internal,  {"x": 30, "y": 15, "w": 18, "h": 15}),
    ("extl",     table_top_external,  {"x": 0,  "y": 30, "w": 24, "h": 15}),
    ("doml",     table_top_domains,   {"x": 24, "y": 30, "w": 24, "h": 15}),
]

panels = []
dash_refs = []
lens_objects = []
for key, builder, grid in LAYOUT:
    pidx = f"panel_{key}"
    lens_id = f"netflow-{key}"
    attrs, refs = builder()
    # each viz is its own saved object (by-reference)
    lens_objects.append({
        "type": "lens", "id": lens_id, "attributes": attrs, "references": refs,
        "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "8.9.0",
    })
    dash_refs.append({"type": "lens", "id": lens_id, "name": f"{pidx}"})
    panels.append({
        "type": "lens",
        "gridData": {**grid, "i": pidx},
        "panelIndex": pidx,
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": pidx,
        "title": attrs["title"],
        "version": "8.19.11",
    })

dashboard = {
    "type": "dashboard",
    "id": "mikrotik-netflow-overview",
    "attributes": {
        "title": "MikroTik NetFlow — Overview",
        "description": "Home-LAN traffic overview from MikroTik IPFIX flows.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False,
                                   "syncCursor": True, "syncTooltips": False,
                                   "hidePanelTitles": False}),
        "timeRestore": True,
        "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": dash_refs,
    "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.3.0",
}

data_view = {
    "type": "index-pattern",
    "id": DV_ID,
    "attributes": {"title": DV_TITLE, "name": "NetFlow", "timeFieldName": "@timestamp"},
    "references": [],
}

import os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netflow_dashboard.ndjson")
with open(OUT, "w") as f:
    f.write(json.dumps(data_view) + "\n")
    for lo in lens_objects:
        f.write(json.dumps(lo) + "\n")
    f.write(json.dumps(dashboard) + "\n")

print("wrote", OUT, "with", len(panels), "panels +",
      len(lens_objects), "lens objects + 1 data view")
