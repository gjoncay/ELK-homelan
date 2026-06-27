# Keeping the Zeek sniffer working after a MikroTik reboot

The MikroTik `/tool sniffer` streams WAN packets (TZSP, UDP 37008) to the ELK host,
where the `zeek` container turns them into logs. This is the source of all
`logs-zeek.*` data and the Zeek-based IP→domain enrichment.

**The catch:** the sniffer's *configuration* survives a reboot, but its *running
state* does not. After the router reboots, streaming is configured but **stopped**
until something runs `/tool sniffer start` again. Nothing on the ELK side needs
touching — the `zeek` container just sits idle (no packets) until the stream
resumes.

---

## 1. Check whether it's currently running

### On the MikroTik
```
/tool sniffer print
```
Look for `running: yes` and the streaming settings:
```
streaming-enabled: yes
streaming-server: 192.168.88.253:37008      (the ELK host)
filter-interface: ether1                     (the WAN interface)
filter-stream: yes
```
If `running: no`, the sniffer is configured but stopped — start it (Option A below).

### On the ELK host (is data actually flowing?)
```
docker exec mikrotik-elk-zeek-1 ls -la /logs
```
You should see `conn.log`, `dns.log`, `ssl.log`, etc. with recent timestamps and
growing sizes.

Or confirm fresh events are reaching Elasticsearch (run from the project dir):
```
source .env
docker exec mikrotik-elk-es01-1 curl -s --cacert config/certs/ca/ca.crt \
  -u "elastic:$ELASTIC_PASSWORD" \
  "https://localhost:9200/logs-zeek.*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"last":{"max":{"field":"@timestamp"}}}}' \
  | python3 -c 'import sys,json;print("most recent zeek event:",json.load(sys.stdin)["aggregations"]["last"]["value_as_string"])'
```
If "most recent zeek event" is within the last minute or two, you're good.

---

## 2. Option A — Restart manually after a reboot (simplest)

After any router reboot, run this once on the MikroTik:
```
/tool sniffer start
```
That's it — streaming resumes immediately and `logs-zeek.*` starts filling again.

Home routers reboot rarely, so this one command is usually all you need. No
device-mode changes, nothing physical.

---

## 3. Option B — Auto-start on boot (fire-and-forget)

This makes the sniffer restart itself on every boot, but RouterOS 7's
**device-mode** gates the `scheduler` feature and requires a one-time **physical
confirmation** to enable it.

1. Request the change on the MikroTik:
   ```
   /system/device-mode/update scheduler=yes
   ```
   It will say the change must be confirmed within a few minutes.

2. **Confirm it with a cold power-cycle:** physically unplug the router and plug it
   back in (or press the device's mode/reset button during boot, depending on
   model).
   > ⚠️ A software `/system reboot` does **not** count — it must be a real power cut.

3. After it boots back up, add the startup scheduler:
   ```
   /system scheduler add name=zeek-sniffer on-event="/tool sniffer start" start-time=startup
   ```

Now the sniffer auto-starts on every future reboot. Verify the rule with:
```
/system scheduler print
```
And check what device-mode currently allows with:
```
/system/device-mode/print
```

---

## 4. If it still isn't working after starting

Walk these in order:

1. **Sniffer running?** `/tool sniffer print` → `running: yes`.
2. **Right target?** `streaming-server` must be the ELK host `192.168.88.253:37008`
   and `filter-interface` the WAN (`ether1`).
3. **Host firewall open?** On the ELK host: `sudo ufw status | grep 37008`
   (should show `37008/udp ALLOW`). If missing: `sudo ufw allow 37008/udp`.
4. **zeek container up?** `docker ps --filter name=mikrotik-elk-zeek`
   (status `Up`). Logs: `docker logs --tail 20 mikrotik-elk-zeek-1`.
5. **Packets arriving but no logs?** Confirm `/logs` is growing
   (`docker exec mikrotik-elk-zeek-1 ls -la /logs`). If files exist but
   Elasticsearch is empty, check the Elastic Agent (fleet-server) is online in
   Kibana → Fleet.

---

## Reference

| Thing | Value |
|---|---|
| WAN interface (sniffed) | `ether1` |
| Stream target (ELK host) | `192.168.88.253:37008` (TZSP/UDP) |
| Zeek container | `mikrotik-elk-zeek-1` |
| Log volume (on disk) | Docker volume `zeeklogs` → `/logs` (rotated hourly, swept after 2h) |
| Elasticsearch data | `logs-zeek.*` data streams (30-day retention) |

Scope note: the sniffer captures **WAN traffic only**, so Zeek sees internet-bound
traffic — not device-to-device LAN chatter.
