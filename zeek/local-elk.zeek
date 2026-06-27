# Site customizations loaded on top of Zeek's stock `local` policy.

# Emit one JSON object per line (sets LogAscii::use_json=T). The Elastic Zeek
# integration's ingest pipelines parse this JSON; leave timestamps as the
# default epoch floats — the pipelines expect that, not ISO8601.
@load policy/tuning/json-logs

# Home LAN. Lets Zeek label connection direction (local_orig / local_resp) and
# the conn.log "local" flags correctly even though we only sniff the WAN side.
redef Site::local_nets += { 192.168.88.0/24 };

# Rotate each log hourly. Rotation is driven by Zeek's network time, which here
# advances with the live packet stream, so it fires ~once an hour. The active
# files (conn.log, dns.log, ...) keep their names for the Elastic Agent to tail;
# rotated files get a timestamp suffix (conn-YY-MM-DD_HH.MM.SS.log) and are
# swept by the cleanup loop in docker-compose once the agent has shipped them.
# This bounds on-disk usage — Elasticsearch is the real system of record.
redef Log::default_rotation_interval = 1 hr;
