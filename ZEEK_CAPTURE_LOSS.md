# Zeek capture loss — what it is, why ours is high, how to fix it

> Reference note (no changes applied yet). Captures the diagnosis from 2026-06-20
> so we can act on it later if we decide to.

## What "capture loss %" means

Zeek estimates how many packets it **should** have seen but didn't. It watches TCP
**ACKs**: when a host acknowledges receiving a byte range that Zeek never saw the
data segment for, that range is counted as a **gap**. Per measurement interval
(~15 min, written to `capture_loss.log` → `logs-zeek.capture_loss-*`):

```
percent_lost ≈ gaps / acks
```

It is a **trust gauge**, not packet drops on your network. High loss means Zeek has
blind spots, so its logs are incomplete.

Dashboard panel: **"Capture loss % (avg)"** on the *Zeek — Threat Hunting* dashboard
(`zeek.capture_loss.percent_lost`).

## What we observed

- WAN-only sniffing (`ether1`): loss was lower (less traffic).
- After flipping to full-LAN (`bridge`) sniffing: **20–44%**, later seen at **17%**.
- It **fluctuates with LAN throughput** — bulk 4K video (Roku/streaming) spikes it;
  it drops when the LAN is quiet.

## Diagnosis (where the loss is NOT)

| Suspect | Evidence | Verdict |
|---|---|---|
| Zeek can't keep up | `zeek` container CPU = **0.07%**, host load ~1.3 on 22 cores | **Not it** — Zeek is idle |
| Host UDP receive buffer overflow | `/proc/net/snmp` in the zeek container: `RcvbufErrors = 568` out of `InDatagrams = 1,218,226` = **0.05%** | **Negligible** — not the cause |
| **Router-side capture incompleteness** | By elimination | **This is it** |

So the loss happens **before packets reach the host**:

1. **MikroTik can't mirror every packet** into the TZSP/UDP stream while sniffing the
   whole LAN bridge under load (router CPU / streaming limits).
2. **Hardware-offloaded traffic** (switch-chip fast-path, e.g. device-to-device on the
   same switch) may never hit the router CPU, so the sniffer never sees it. Zeek then
   sees one side of a flow (e.g. ACKs without data) → inflated "gaps".

This is the inherent cost of **TZSP-mirroring a busy home LAN through the router**,
which we accepted when switching from WAN-only to full-LAN to get per-device
attribution.

## What it affects (and what it doesn't)

The loss hits **bulk TCP reassembly hardest** — i.e. the big video flows. The signals
the threat dashboard is built around are **far less affected** because they're sparse,
small packets seen at connection start:

- **Largely intact / trustworthy:** DNS queries, TLS SNI (`ssl.server.name`),
  notices, weird events, connection existence, who-talked-to-whom.
- **Less reliable (under-counted):** per-connection byte totals, payload/file
  analysis (`files` log), anything needing full stream reassembly.

Bottom line: the dashboard is still useful — just don't treat exact byte counts as
ground truth.

## Potential solutions (ordered by effort/impact)

### 1. Accept it (zero effort)
For metadata threat-hunting, ~20–30% loss is tolerable; the key panels hold up.
Capture loss is normal for TZSP on a busy LAN.

### 2. Scope the sniffer to cut volume (best real lever)
Less mirrored traffic → the router keeps up → less loss. RouterOS sniffer filters are
**inclusive-only** (no easy "exclude"), so the practical approach is to capture only
the devices you want to watch, leaving the bandwidth hog (the Roku TV,
`192.168.88.244`) out. Example — watch just the laptops + phone:

```
/tool sniffer stop
/tool sniffer set filter-src-ip-address=192.168.88.243,192.168.88.246,192.168.88.247,192.168.88.251,192.168.88.253
/tool sniffer start
```

Trade-off: you lose visibility into the excluded device(s). (Adjust the IP list to
taste; these come from the DHCP leases — see device names in
`dashboards/build_zeek_threat_dashboard.py`.)

### 3. Raise the host UDP receive buffer (freebie hygiene)
Kills the minor 568 `RcvbufErrors` (won't move the 17–34%). On the ELK host:

```
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.rmem_default=33554432
# persist:
echo -e "net.core.rmem_max=33554432\nnet.core.rmem_default=33554432" | sudo tee /etc/sysctl.d/99-zeek-udp.conf
```

(`tzsp2pcap`/libpcap would also need to request a larger buffer to fully benefit; the
sysctl raises the ceiling.)

### 4. Hardware port mirror / SPAN to a dedicated NIC (ideal, not currently possible)
Zero router-CPU cost, full fidelity — but needs a spare wired NIC on the Zeek host.
The ELK host is a laptop with no spare NIC, so this is off the table unless the setup
changes (e.g. a mini-PC/Pi with two NICs as a dedicated sensor).

### 5. Reduce mirror load other ways
- Lower-bandwidth devices only, or sniff a specific VLAN/segment of interest.
- Some MikroTik models let you tune offload, but disabling fast-path to expose more
  traffic to the CPU will spike router CPU — usually a net loss.

## How to re-check the numbers later

Recent loss measurements:
```
source .env
docker exec mikrotik-elk-es01-1 curl -s --cacert config/certs/ca/ca.crt \
  -u "elastic:$ELASTIC_PASSWORD" \
  "https://localhost:9200/logs-zeek.capture_loss-default/_search" -H 'Content-Type: application/json' \
  -d '{"size":5,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","zeek.capture_loss.percent_lost","zeek.capture_loss.gaps","zeek.capture_loss.acks"]}'
```

Host-side UDP drops (run inside the zeek container's netns):
```
docker exec mikrotik-elk-zeek-1 cat /proc/net/snmp | grep -A1 '^Udp:'
```

Confirm Zeek isn't CPU-bound:
```
docker stats --no-stream mikrotik-elk-zeek-1
```

## Recommendation

Leave it as-is unless you specifically need accurate connection/byte data. If you want
to drive the loss down, **option 2 (scope to specific devices)** is the most effective,
with **option 3** as cheap cleanup. Revisit option 4 only if you move Zeek to dedicated
sensor hardware.
