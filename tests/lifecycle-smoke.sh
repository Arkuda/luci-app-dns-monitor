#!/bin/sh
# SPDX-License-Identifier: ISC
# Run only in a disposable Linux chroot/container with dnsmasq 2.90 and UCI.
# Exercises the installed helper against a real dnsmasq, not a mocked DNS response.
set -eu
[ -f /tmp/dns-monitor-test-root ] || { echo 'Refusing to modify a non-test root' >&2; exit 1; }
PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
ROOT=${1:-/work}
mkdir -p /etc/config /etc/init.d /usr/libexec /var/etc /var/run/dnsmasq /tmp/ruantiblock-fixture.d
cp "$ROOT/root/usr/libexec/dns-monitor-lifecycle" /usr/libexec/dns-monitor-lifecycle
chmod 0755 /usr/libexec/dns-monitor-lifecycle
command -v uci >/dev/null
# Production helper uses the standard OpenWrt PATH.
[ -x /sbin/uci ] || ln -s /usr/local/bin/uci /sbin/uci
cat > /etc/config/dns-monitor <<'EOF'
config dns-monitor 'config'
 option dnsmasq_instance 'main'
EOF
cat > /etc/config/dhcp <<'EOF'
config dnsmasq 'main'
 option noresolv '1'
 option logqueries '0'
 option cachesize '1000'
 option dnsforwardmax '3000'
 option confdir '/tmp/ruantiblock-fixture.d'
 list server '127.0.0.1#10054'
 list server '127.0.0.1#10055'
EOF
cat > /tmp/ruantiblock-fixture.d/01-user.dnsmasq <<'EOF'
address=/ruantiblock.example/192.0.2.45
EOF
# The fixture init implements only OpenWrt's researched logging translation;
# dnsmasq itself performs all actual logging, forwarding, and resolution.
cat > /etc/init.d/dnsmasq <<'EOF'
#!/bin/sh
set -eu
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
section=${2:-main}
pidfile="/var/run/dnsmasq/dnsmasq.$section.pid"
if [ -f "$pidfile" ]; then
 pid=$(cat "$pidfile")
 kill "$pid" 2>/dev/null || true
 n=0
 while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 20 ]; do sleep 0.05; n=$((n+1)); done
 rm -f "$pidfile"
fi
conf="/var/etc/dnsmasq.conf.$section"
{
 echo 'port=10053'
 echo 'listen-address=127.0.0.1'
 echo 'bind-interfaces'
 echo 'no-resolv'
 echo 'no-hosts'
 echo 'user=dnsmasq'
 echo "pid-file=$pidfile"
 echo "conf-dir=$(uci -q get "dhcp.$section.confdir")"
 for server in $(uci -q get "dhcp.$section.server"); do echo "server=$server"; done
 [ "$(uci -q get "dhcp.$section.logqueries" || true)" != 1 ] || echo 'log-queries=extra'
 facility=$(uci -q get "dhcp.$section.logfacility" || true)
 [ -z "$facility" ] || echo "log-facility=$facility"
} > "$conf"
exec /usr/sbin/dnsmasq --conf-file="$conf"
EOF
chmod 0755 /etc/init.d/dnsmasq
UPSTREAM_PID=/tmp/dns-monitor-upstream.pid
cleanup() {
 for f in "$UPSTREAM_PID" /var/run/dnsmasq/dnsmasq.main.pid; do
  [ ! -f "$f" ] || kill "$(cat "$f")" 2>/dev/null || true
 done
}
trap cleanup EXIT HUP INT TERM
/usr/sbin/dnsmasq --conf-file=/dev/null --port=10054 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --no-hosts --address=/example.com/192.0.2.10 --address=/example.com/2001:db8::10 --pid-file="$UPSTREAM_PID"
/etc/init.d/dnsmasq restart main
# Preserve all upstream/config values, not just a checksum of a copied file.
BEFORE=$(uci export dhcp)
assert_dns() {
 result=$(nslookup "$1" 127.0.0.1:10053 2>&1)
 printf '%s\n' "$result" | grep -q "$2" || { printf '%s\n' "$result"; exit 1; }
}
assert_dns api.example.com 192.0.2.10
/usr/libexec/dns-monitor-lifecycle start
assert_dns api.example.com 192.0.2.10
assert_dns ruantiblock.example 192.0.2.45
grep -q 'query\[A\] api.example.com from 127.0.0.1' /tmp/dns-monitor/queries.log
grep -q 'query\[AAAA\] api.example.com from 127.0.0.1' /tmp/dns-monitor/queries.log
# In-place truncation must retain logging on the same inode, no DNS restart.
PID=$(cat /var/run/dnsmasq/dnsmasq.main.pid)
: > /tmp/dns-monitor/queries.log
assert_dns auth.example.com 192.0.2.10
grep -q 'query\[A\] auth.example.com from 127.0.0.1' /tmp/dns-monitor/queries.log
[ "$PID" = "$(cat /var/run/dnsmasq/dnsmasq.main.pid)" ]
/usr/libexec/dns-monitor-lifecycle stop
[ "$BEFORE" = "$(uci export dhcp)" ]
[ ! -e /tmp/dns-monitor/queries.log ]
assert_dns api.example.com 192.0.2.10
assert_dns ruantiblock.example 192.0.2.45
# Stop/recover on inactive state must not restart DNS.
PID=$(cat /var/run/dnsmasq/dnsmasq.main.pid)
/usr/libexec/dns-monitor-lifecycle stop
/usr/libexec/dns-monitor-lifecycle recover
[ "$PID" = "$(cat /var/run/dnsmasq/dnsmasq.main.pid)" ]
# Crash/service-start recovery restores persistent options and stops logging.
/usr/libexec/dns-monitor-lifecycle start
/usr/libexec/dns-monitor-lifecycle recover
[ "$BEFORE" = "$(uci export dhcp)" ]
assert_dns api.example.com 192.0.2.10
# A committed config change during capture must survive logging restoration.
# A changed confdir has observable DNS behavior, not just copied file contents.
mkdir -p /tmp/ruantiblock-updated-fixture.d
cp /tmp/ruantiblock-fixture.d/01-user.dnsmasq /tmp/ruantiblock-updated-fixture.d/
printf '%s\n' 'address=/preserved.example.com/192.0.2.99' > /tmp/ruantiblock-updated-fixture.d/02-preserved.dnsmasq
/usr/libexec/dns-monitor-lifecycle start
uci set dhcp.main.confdir=/tmp/ruantiblock-updated-fixture.d
uci commit dhcp
/usr/libexec/dns-monitor-lifecycle stop
[ "$(uci -q get dhcp.main.confdir)" = /tmp/ruantiblock-updated-fixture.d ]
assert_dns preserved.example.com 192.0.2.99
assert_dns ruantiblock.example 192.0.2.45
uci set dhcp.main.confdir=/tmp/ruantiblock-fixture.d
uci commit dhcp
# Refuse pending changes rather than applying somebody else's DHCP settings.
uci set dhcp.main.cachesize=1234
if /usr/libexec/dns-monitor-lifecycle start; then echo 'Pending DHCP change was incorrectly applied'; exit 1; fi
[ "$(uci -q get dhcp.main.cachesize)" = 1234 ]
uci revert dhcp
# Refuse an existing query-to-syslog configuration; don't restore it later.
uci set dhcp.main.logqueries=1
uci commit dhcp
if /usr/libexec/dns-monitor-lifecycle start; then echo 'Existing query logging incorrectly accepted'; exit 1; fi
uci set dhcp.main.logqueries=0
uci commit dhcp
printf '%s\n' 'PASS: real dnsmasq 2.90 A/AAAA, dedicated client logs, upstream/confdir preservation, truncation without restart, start/stop/recovery/idempotent stop, pending-change refusal, DNS after stop'
