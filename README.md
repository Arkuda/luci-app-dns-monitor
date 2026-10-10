# luci-app-dns-monitor

Per-client DNS monitoring for **OpenWrt 24.10 / LuCI JavaScript**, with a small native ubus collector and optional ruantiblock 2.1.12 user-list editing. Intended target: Orange Pi R1 Plus LTS, `rockchip/armv8`, `aarch64_generic`, OpenWrt 24.10.5, dnsmasq-full 2.90.

This application does not replace dnsmasq, HTTPS DNS Proxy, ruantiblock, or OpenVPN. It does not depend on AdGuard Home, PBR, a database, Node.js, Python, or an external service. Node/Python may be used for development tests only.

Current release **1.0.0-r2** artifacts are in `dist/`: the `aarch64_generic` application IPK, the architecture-independent Russian IPK, a complete source archive, and `SHA256SUMS`. The supplied native binary was built with the official OpenWrt 24.10.5 rockchip/armv8 SDK; it is not a host executable. Release r2 corrects the required `coreutils-stat` dependency, reusing the unchanged SDK-built binary and frontend.

## Research and compatibility decisions

* [OpenWrt 24.10 dnsmasq init](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/network/services/dnsmasq/files/dnsmasq.init) translates `logqueries=1` to **`log-queries=extra`**, not plain query logging, and `logfacility` to `log-facility`. It also grants the dnsmasq jail a writable **file bind mount** for an absolute log path. The extra format includes the request serial and client address. `query[A] ... from CLIENT` is the request, while `forwarded`, `cached`, and `reply` lines must not be counted as new queries.
* [dnsmasq 2.90 signal handling](https://github.com/imp/dnsmasq/blob/v2.90/src/dnsmasq.c) does not dynamically toggle query logging: `SIGHUP` reloads DNS/hosts data, not startup options; `SIGUSR2` only reopens the log. See also the [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
* [dnsmasq 2.90 file logger](https://github.com/imp/dnsmasq/blob/v2.90/src/log.c) disables its asynchronous queue for a file destination and opens it without `O_NONBLOCK`. **Do not substitute a FIFO**: a reader crash or full pipe can block DNS itself. On an output write error, upstream dnsmasq can fall back to syslog. A writable RAM file and free-memory checks avoid deliberately introducing that failure mode; they cannot eliminate every OS/storage failure.
* The existing dnsmasq jail pins the log's inode. Normal size rotation therefore **truncates in place**, rather than renaming/replacing it or repeatedly restarting DNS. File-replacement anomalies must not silently turn into an unbounded detached log.
* [LuCI 24.10 build conventions](https://github.com/openwrt/luci/blob/openwrt-24.10/luci.mk), its JS `view`/`rpc`/`poll` modules, and [rpcd ucode plugins](https://github.com/openwrt/luci/blob/openwrt-24.10/modules/luci-base/root/usr/share/rpcd/ucode/luci) are used directly.
* HTTPS DNS Proxy **2025.12.29-r1** was checked at [OpenWrt packages commit `fe1e1d8bf141a93f9bfefc0f779b2dfac71a59ec`](https://github.com/openwrt/packages/commit/fe1e1d8bf141a93f9bfefc0f779b2dfac71a59ec). Its [init script](https://github.com/openwrt/packages/blob/fe1e1d8bf141a93f9bfefc0f779b2dfac71a59ec/net/https-dns-proxy/files/etc/init.d/https-dns-proxy) commits its DHCP UCI changes before restarting dnsmasq. Monitoring preserves its server/backup/force-DNS settings and does not disable or replace the proxy.
* ruantiblock was inspected at **commit `52cc2e314d8f546878269e3c5d197946d9f3d28d`**, whose [Makefile](https://github.com/gSpotx2f/ruantiblock_openwrt/blob/52cc2e314d8f546878269e3c5d197946d9f3d28d/ruantiblock/Makefile) identifies **2.1.12-r1**. Its [main script](https://github.com/gSpotx2f/ruantiblock_openwrt/blob/52cc2e314d8f546878269e3c5d197946d9f3d28d/ruantiblock/files/usr/bin/ruantiblock) reads `/etc/ruantiblock/user_lists/list1` through `list5` for named UCI `user_instance` sections. Its supported `update` action reparses user entries but can also download blacklists and restart dnsmasq. `reload` is not a user-list-only apply API.

## Capture architecture and lifecycle

LuCI calls the native `dns-monitor` ubus object through authenticated rpcd. A single procd-owned collector owns the selected client, expiry, cursor, and bounded in-memory history. Closing the browser does not stop capture or create another collector.

1. **Inactive:** query logging is off; no log polling. History from the last stopped session remains in daemon RAM until Clear, a new session, service restart, or reboot.
2. **Start:** validate the client address and configuration; save only the original `logqueries`/`logfacility` values in a root-only recovery journal; set those two logging options; restart the selected dnsmasq instance once; verify the generated dedicated extra-logging configuration. No upstream, HTTPS DNS Proxy, confdir, DHCP, routing, VPN, or generated ruantiblock setting is changed.
3. **Active:** incrementally read `/tmp/dns-monitor/queries.log` every 100 ms, parse only request lines, retain only the selected client in a fixed-capacity ring. LuCI refreshes every two seconds with cursor-based batches, not full-log reads. Raw logging applies to the dnsmasq instance, so the temporary raw log can contain other clients; only selected-client records enter the history exposed by the monitor.
4. **Stop / expiry:** restore the original logging options and restart that dnsmasq instance once; delete the raw log only after successful restoration. Repeated native start for the same active client and repeated stop are idempotent. Stop first to select a different client.
5. **Crash / service restart / reboot:** procd respawns the daemon; startup recovery restores logging and starts inactive. The enabled init script runs at priority 18, before dnsmasq's priority 19, so a persistent configuration-only journal is also restored after power loss. Sessions never automatically resume after reboot.

**Start and Stop each cause a short DNS/DHCP service interruption.** dnsmasq 2.90 cannot avoid this while actually disabling query logging when inactive. Ordinary polling, clearing history, and size truncation do not restart DNS. Use short diagnostic sessions, not permanent surveillance. A new session clears the old history; copy/export before starting another.

The default history cap is **10,000 requests**, the raw-log **rotation threshold is 5 MiB**, and a session expires after **one hour**. The record ring is a hard count bound. The regular-file size threshold is **not a hard byte quota**: it can overshoot by writes between collector checks or during lifecycle work. Under overload, truncation can drop unread raw lines. No heavy database or historical file rotations are retained. The raw logfile and request history live in RAM; only logging configuration/recovery metadata and explicitly confirmed ruantiblock additions are written to flash.

## Build with the exact 24.10.5 SDK

Use an x86-64 Linux build host with the [OpenWrt build prerequisites](https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem). Keep the SDK on a Linux filesystem, not a Windows/network-mounted checkout. Never build this ARM package with a host `gcc` and label the result as an OpenWrt package.

On Ubuntu 24.04, install `python3-pyelftools` in addition to the linked prerequisites. The SDK checks the rockchip U-Boot prerequisites even for a standalone package build.

```sh
wget https://downloads.openwrt.org/releases/24.10.5/targets/rockchip/armv8/openwrt-sdk-24.10.5-rockchip-armv8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
printf '%s\n' '5ba3db732cb1ad0dc723c9428360c18c03ae346b961ec7102aaf3466501834de  openwrt-sdk-24.10.5-rockchip-armv8_gcc-13.3.0_musl.Linux-x86_64.tar.zst' | sha256sum -c -
tar --zstd -xf openwrt-sdk-24.10.5-rockchip-armv8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
cd openwrt-sdk-24.10.5-rockchip-armv8_gcc-13.3.0_musl.Linux-x86_64
./scripts/feeds update base packages luci
./scripts/feeds install -a -p base
./scripts/feeds install -a -p packages
./scripts/feeds install -a -p luci
cp -a /path/to/luci-app-dns-monitor package/luci-app-dns-monitor
cat >> .config <<'EOF'
CONFIG_PACKAGE_luci-app-dns-monitor=m
CONFIG_LUCI_LANG_ru=y
CONFIG_PACKAGE_luci-i18n-dns-monitor-ru=m
EOF
make defconfig
make package/luci-app-dns-monitor/compile -j2 V=s
```

The SDK's release-pinned `feeds.conf.default` should be retained. Resulting packages are under `bin/packages/aarch64_generic/`, normally the `base` directory for the directly copied package. The collector is native ARMv8 code, so the main package is **not architecture-independent**. The generated Russian translation package is `all` architecture. The source `src/Makefile` is also usable for native host tests, but that does not produce an installable router binary.

## Install

Back up `/etc/config/dhcp`, `/etc/config/dns-monitor` if already present, and the ruantiblock list you intend to edit. Copy the built `.ipk` files to `/tmp` on the router. Install through LuCI **System → Software → Upload Package**, or:

```sh
opkg update
opkg install /tmp/luci-app-dns-monitor_1.0.0-r2_aarch64_generic.ipk
opkg install /tmp/luci-i18n-dns-monitor-ru_1.0.0-r2_all.ipk   # optional Russian interface
```

Existing `dnsmasq-full` satisfies the dnsmasq dependency; do not replace it with a different dnsmasq variant. `coreutils-stat` is required: stock OpenWrt BusyBox may omit `stat`, which the lifecycle helper uses for ownership/mode checks. The package enables/starts its inactive procd service and reloads rpcd permissions. Reload the browser if the menu is cached. Open **Services → DNS Monitor**. Package installation alone does not enable query logging or alter your DNS upstreams.

Select the discovered device, or enter its IPv4/IPv6 address manually. Start monitoring, open the mobile app on that client, then stop and inspect requests. Search/filter, choose Raw requests or Unique domains, select domains, copy, or export TXT/CSV. Counts in grouping refer to retained, filtered requests, not all-time traffic. Names are grouped case-insensitively without collapsing subdomains. Exports and “all visible” operate on the complete filtered dataset, not just the current table page. CSV exports raw requests with `timestamp,client_ip,domain,record_type` and proper CSV quoting.

DHCP leases and neighbour information are discovery hints, not a list of exclusively Wi-Fi clients. A lease does not prove connection; absent reliable neighbour information, status is unknown. Devices behind another access point or on Ethernet are supported as long as dnsmasq receives queries with their real address. Refresh discovery or use manual entry for static/IPv6 clients.

### Upgrading r1 / missing menu or API

Release r1 omitted `coreutils-stat`. On the Orange Pi's stock 24.10.5 image, the helper failed with `stat: not found`; procd still showed a running collector, but the `dns-monitor` ubus object was withheld until recovery succeeded. Install r2 to get the dependency automatically. For an already installed r1, the immediate repair is:

```sh
opkg install coreutils-stat
/usr/libexec/dns-monitor-lifecycle recover
```

The inactive collector retries recovery every five seconds; then `ubus call dns-monitor status` should report `"active": false`. With no recovery journal, this operation does not restart dnsmasq. Do not remove a recovery journal to bypass a real restoration error.

The menu entry is independent of collector availability. If it is not visible after installation, hard-refresh LuCI (Ctrl+F5); if permissions are stale, log out and back in. The direct authenticated page is `/cgi-bin/luci/admin/services/dns-monitor`. The translation package depends on the main application; install the main IPK first or supply both local IPK paths to one `opkg install` command. The router's CPU label `ARMv8 Processor rev 4` corresponds to this target's `aarch64_generic` package architecture, not a separate package architecture.

## Configuration

`/etc/config/dns-monitor`:

```uci
config dns-monitor 'config'
    option max_records '10000'
    option max_log_bytes '5242880'
    option session_seconds '3600'
    option dnsmasq_instance ''
```

Accepted ranges: `max_records` **1–10,000**, `max_log_bytes` **4,096–67,108,864 bytes**, and `session_seconds` **1–86,400 seconds**. `max_log_bytes` is the truncation threshold described above, not a filesystem quota. Adjust only while inactive and restart `/etc/init.d/dns-monitor` to load changes. The daemon rejects invalid numeric settings rather than launching with unbounded storage.

For multiple dnsmasq instances, explicitly set `dnsmasq_instance` to the **UCI section name**, for example `cfg01411c`; do not put an interface, `@dnsmasq[0]`, or a filesystem path there. An empty value is accepted only when one dnsmasq section exists. The monitor rejects pre-existing enabled query logging so it will never deliberately restore query logging to the main system log. Apply or revert pending LuCI DHCP changes before starting or stopping capture; the helper will not commit another administrator's uncommitted settings.

HTTPS DNS Proxy may continue managing its `server`/`noresolv` configuration. The monitor only changes two logging options and preserves committed concurrent changes to unrelated settings on restoration. If an administrator changes the logging destination or deletes the monitored dnsmasq section while capture is active, the recovery journal is retained and an error is reported rather than overwriting that configuration blindly. Do not edit the two logging options or rotate/replace the raw logfile during capture.

## ubus API

The native object is `dns-monitor`; the optional rpcd ucode object is `dns-monitor.ruantiblock`. No direct HTTP endpoint is installed. LuCI uses the router's authenticated ubus transport and the package ACL.

| Method | Parameters | Result |
|---|---|---|
| `status` | None | Active state, selected client, captured/retained counts, limits, expiry, epoch and error diagnostics |
| `start` | `client`: IPv4/IPv6 string | Shared status after logging configuration and dnsmasq health checks |
| `stop` | None | Shared status after restoration; retained history remains |
| `get_clients` | None | DHCP/ARP discovery hints with hostname, IP, MAC and evidence-based status |
| `get_queries` | Optional `epoch`, `cursor`, `limit` (1–500) | Incremental raw records, cursor, epoch, `more`, `reset`, history boundaries and shared status |
| `clear` | None | Cleared history and new epoch; rejected during a pending lifecycle operation |
| `export` | `format`: `txt`/`csv`; optional `epoch`, `cursor`, `limit` (1–500) | Paginated export text plus the same cursor/reset metadata |
| `dns-monitor.ruantiblock lists` | None | Optional list availability, enable state, VPN interface and proxy mode |
| `dns-monitor.ruantiblock add` | `list`: `list1`–`list5`; `domains`: array, at most 500 | Added/duplicate counts and explicit pending-apply status, or an actionable error |

`get_queries` and `export` are bounded to 500 records per response, including long DNS names, to stay below stock ubus message limits. Begin at cursor zero; reuse the returned epoch/cursor while `more` is true. On `reset`, discard an accumulated snapshot and start with the returned page: a new session, clear, or history eviction invalidated the old cursor. This is a live bounded window, not an immutable export snapshot. Native TXT pages contain one domain per request; consumers deduplicate across pages. CSV emits its header on the initial/reset page and escapes text fields. LuCI deduplicates TXT and applies filters/selections to its complete currently loaded table dataset.

`error` in status can retain the last lifecycle failure even after safe restoration; always inspect `active`. The raw log is removed only when logging is confirmed restored. Backend diagnostics are English; the LuCI interface has a Russian translation.

## ruantiblock integration

Integration is optional; ruantiblock is not a package dependency. Available lists are read from committed `ruantiblock` UCI configuration. Only existing **enabled VPN-mode** lists (`u_enabled=1`, `u_proxy_mode=2`) are eligible for addition; the existing `u_if_vpn`, such as `tun0`, is displayed and preserved.

Select domains and click **Add to ruantiblock**. A confirmation explains the selected list and persistent write. The backend:

* accepts only fixed named list1–list5 sections and their regular, safely owned files;
* validates normal DNS hostnames/punycode, lowercases them, removes an optional final dot, and rejects IPs, URLs, shell syntax, underscores, wildcards, overlong labels, and path-like values;
* appends only new domains, comparing the first existing token case-insensitively, preserving comments, IP/CIDR entries, per-domain DNS overrides, ownership, and permissions;
* serializes its own writers with a persistent advisory lock, checks for external changes, and atomically replaces the source user list;
* never writes `/tmp/dnsmasq.cfg*.d/` files or directly changes nftables, routing tables, or VPN state.

**Added domains are saved but not automatically applied.** Use the existing ruantiblock LuCI **Update** button; the supported command is `/usr/bin/ruantiblock update` while ruantiblock is running. It can update global blacklists and restart dnsmasq, so applying is a separate deliberate action. OpenVPN/network restart is not requested by this application.

Integration is disabled for custom/dynamic shell configuration that cannot be safely interpreted, nonstandard `USER_LISTS_DIR`, missing/unsafe files, and unsupported list instances. Export remains available. At most 500 domains are accepted per add and existing list files are limited to 1 MiB. ucode 24.10 has no `fsync` API: replacement is atomic but cannot promise power-loss durability. Root writers that ignore the advisory lock retain a small final check-to-rename race; avoid simultaneous manual edits. Do not delete `.dns-monitor.lock` while editing lists. A crash may leave a reserved `.dns-monitor-*.tmp` file, which is never used as a list source.

## Security and privacy

* No new HTTP listener, unauthenticated API, firewall rule, or WAN exposure. LuCI/rpcd enforce the installed read/write ACLs; do not grant `luci-app-dns-monitor` to untrusted rpcd accounts. Root access to the local ubus socket remains administrative access.
* The native API validates addresses/cursors/limits/formats; privileged lifecycle operations use fixed executable arguments, not interpolated shell commands. The optional editor accepts no arbitrary filenames.
* Log/history are volatile. The raw log is protected; browser rendering uses text nodes. Clearing history affects all concurrent LuCI sessions. Sessions share the monitored IP and lifecycle; domain selections and filters are local to each browser.
* Normal dnsmasq output, including non-query service messages, is redirected into the dedicated file while active. Startup/configuration failures and non-query diagnostics can still use the system log; the monitor does not consume `logread`.
* Observe LAN-only access policy and use HTTPS for LuCI. DNS history reveals sensitive application/hostname information; copy/export only when intended.

## Uninstall and rollback

Stop monitoring in LuCI **first**. Uninstall through System → Software, or:

```sh
/etc/init.d/dns-monitor stop
/usr/libexec/dns-monitor-lifecycle recover
opkg remove luci-i18n-dns-monitor-ru luci-app-dns-monitor
/etc/init.d/rpcd reload
```

The removal hook aborts if logging cannot be safely restored. Do not force-remove an active installation. The monitor's config may remain as an opkg conffile; request history is not stored there. Removing the monitor does **not** remove domains you explicitly added to ruantiblock. Restore the backed-up list or remove those entries using ruantiblock's own editor, then explicitly Update ruantiblock.

If recovery is blocked, inspect `/etc/dns-monitor-recovery/section`, `logqueries`, `logqueries.present`, `logfacility`, and `logfacility.present`. These are original **configuration values**, not executable shell snippets. Correct the missing/conflicting dnsmasq section and apply/revert pending DHCP changes, then run the recovery helper again. If manual recovery is unavoidable, restore only those two options to their journalled original values (delete an option when its `.present` file is absent), restart only that dnsmasq instance, verify DNS resolution, and only then remove the journal/raw log. Do not blindly replace the whole DHCP config with an old backup when other settings have changed.

## Verification and known limits

Tests and observed build results are recorded in `TESTING.md`; untested physical-router behavior is explicitly separated from host checks.

* Queries bypassing dnsmasq (application DoH/DoT, a device VPN, another resolver, local application DNS cache, or hardcoded IPs) are not visible. Capturing DNS cannot prove which application generated a request; background services on the same client can add traffic.
* Monitoring matches one exact IP, not a MAC identity. A dual-stack device may need separate IPv4 and IPv6 sessions; temporary IPv6 address changes require reselection. NAT/AP DNS forwarding may hide original clients.
* This is a bounded diagnostic window, not a lossless audit trail. Counts may decrease as old records are evicted. Saturated logging/collector overload, external truncation, or service interruptions can lose requests.
* The regular logfile size is a rotation threshold, not a guaranteed byte cap under arbitrary process starvation. A prolonged collector/service restoration failure can allow further growth; errors and the retained journal require administrator attention. Upstream dnsmasq's syslog fallback on a log-write failure cannot be removed by a LuCI package without patching dnsmasq.
* On the physical Orange Pi, r2 installation, inactive recovery/API, authenticated LuCI menu navigation and subsequent DNS resolution were verified; DNS/VPN process IDs and six configuration checksums were unchanged. Active start/stop, procd reboot recovery, ujail logfile mounts, HTTPS DNS Proxy callbacks and actual ruantiblock apply remain untested on that hardware. See `TESTING.md`; these checks are not a full physical-router certification.
