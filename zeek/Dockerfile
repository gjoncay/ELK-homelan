# Zeek + tzsp2pcap in one image.
#
# MikroTik /tool sniffer streams TZSP (UDP 37008) to this container. tzsp2pcap
# decapsulates the TZSP frames into a raw pcap stream on stdout, which is piped
# into `zeek -r -` (offline reader on a never-ending pipe = pseudo-live source).
# Zeek emits ECS-friendly JSON logs into /logs, which is a volume the Elastic
# Agent (fleet-server) also mounts at /opt/zeek/logs/current to ship to ES.
FROM zeek/zeek:lts

# tzsp2pcap isn't packaged anywhere standard, so build it from source.
# libpcap0.8 (Zeek's own runtime dep) stays after the build for linking.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libpcap-dev git ca-certificates \
 && git clone --depth 1 https://github.com/thefloweringash/tzsp2pcap.git /tmp/tzsp2pcap \
 && make -C /tmp/tzsp2pcap \
 && install -m 0755 /tmp/tzsp2pcap/tzsp2pcap /usr/local/bin/tzsp2pcap \
 && rm -rf /tmp/tzsp2pcap \
 && apt-get purge -y build-essential git \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY local-elk.zeek /usr/local/zeek/share/zeek/site/local-elk.zeek

WORKDIR /logs
