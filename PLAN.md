# MikroTik → ELK Traffic Analysis — Build Plan

Analyze home-LAN traffic from a MikroTik router (RouterOS 7) in an ELK stack.

## Decisions (locked)

| Decision | Choice |
|---|---|
| ELK host | Docker on a Linux box/VM |
| Host RAM | 16 GB+ |
| First data source | Flows (IPFIX) first |
| Ingestion | Elastic Agent + Fleet |
| Elastic version | Current stable 8.x (pin at build time) |

## Architecture

```
MikroTik (RouterOS 7)                          ELK host (Docker)
┌──────────────────────┐                       ┌─────────────────────────────────┐
│ Traffic Flow (IPFIX) │──IPFIX / UDP 2055────▶│ Elastic Agent                    │
│                      │                       │   • NetFlow integration          │
│ Port mirror (SPAN)   │──mirror──▶ Zeek NIC ─┐│   • Zeek integration             │
│   OR                 │                      ││           │                      │
│ Sniffer (TZSP)       │··UDP 37008·▶ tzsp2pcap┴▶ Zeek ──▶ JSON logs              │
└──────────────────────┘                       │           │                      │
                                               │           ▼                      │
                                               │   Elasticsearch ──▶ Kibana       │
                                               └─────────────────────────────────┘
```

## Data sources (detail spectrum)

| Source | What you get | Weight |
|---|---|---|
| Traffic Flow (IPFIX) | src/dst IP, ports, protocol, bytes, packets | Tiny |
| Zeek | Structured protocol logs: DNS, HTTP/TLS SNI, certs, files, conn summaries | Medium |
| pcap | Full packet payloads | Heavy |

---

## Phases

### Phase 1 — Stand up ELK
- `docker-compose.yml` + `.env` (pinned version, passwords, JVM heap ~4 GB).
- Services: Elasticsearch (single-node), Kibana, Fleet Server + Elastic Agent.
- Bring up ES → verify health → Kibana loads → set up Fleet Server → enroll local agent.

### Phase 2 — Flow ingestion
- Add **NetFlow integration** to the agent policy (listens UDP 2055).
- MikroTik RouterOS 7 config:
  - `/ip/traffic-flow set enabled=yes`
  - `/ip/traffic-flow target add dst-address=<ELK-IP> port=2055 version=ipfix`
  - tune `active-flow-timeout` / `inactive-flow-timeout`
- Verify `logs-netflow.*` data stream populating; open prebuilt NetFlow dashboard.

### Phase 3 — Make it useful for a home LAN
- Map devices (IP/MAC → friendly names) via enrich pipeline or lookup.
- Custom Kibana dashboards: top talkers, per-device bandwidth over time, external
  destinations (GeoIP), port/protocol breakdown, off-hours/unexpected traffic.
- ILM policy for rollover + retention (disk safety).

### Phase 3.5 — Zeek (protocol-level visibility)
Zeek analyzes **packets**, not flows, so it needs traffic delivered to it. Pick one:

- **Option A — Port mirror / SPAN (preferred if hardware allows).**
  Mirror LAN/WAN port via `/interface ethernet switch` (mirror-source / mirror-target)
  to a spare NIC on the Zeek host. Zeek sniffs that NIC directly. Full fidelity, no
  router streaming CPU cost. Requires switch-chip support + spare NIC.
- **Option B — TZSP sniffer streaming (any RouterOS, no extra hardware).**
  `/tool sniffer` streams TZSP (UDP 37008) to the host → `tzsp2pcap` decapsulates →
  pipe into Zeek. Scope with filters (specific interfaces/hosts); runs through router CPU.

Then:
1. Run Zeek (container `zeek/zeek` or host install), emit **JSON logs**.
2. Add the **Zeek integration** to the Elastic Agent policy → tails Zeek logs, maps to
   ECS, ships to Elasticsearch.
3. Use prebuilt Zeek/Corelight dashboards in Kibana alongside NetFlow.

**Decision to make at this phase:** Option A (port mirror) vs Option B (TZSP) — driven by
MikroTik model's mirror support and whether the Zeek box has a spare NIC.

### Phase 4 (optional) — Targeted raw pcap
- TZSP sniffer → Packetbeat, or on-demand pcap files for deep dives.

---

## Needed at build time
- ELK host IP; Docker + Compose confirmed installed.
- MikroTik LAN IP / management access.
- LAN subnet(s) (e.g. `192.168.88.0/24`) for internal-vs-external tagging.
- Retention target (e.g. keep 30 days of flows).
- For Zeek: MikroTik model (mirror support?) + whether Zeek host has a spare NIC.

## Resource notes
- 16 GB comfortably runs flows + Zeek together. Zeek CPU scales with throughput; home LAN is light.
- ES heap ≈ half of allocated RAM, leave the rest for OS page cache.
