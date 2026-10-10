# Validation record — 1.0.0-r2

## Executed checks

| Check | Observed result |
|---|---|
| `node tests/frontend-model.js` | Passed bounded history, cursor/reset handling, case-insensitive grouping, filtering, selection and TXT/CSV export behavior. |
| `node --check htdocs/luci-static/resources/view/dns-monitor/overview.js` | Passed JavaScript syntax check. |
| `msgfmt --check-format po/ru/dns-monitor.po` | Passed; SDK also generated and packaged `dns-monitor.ru.lmo`. |
| `tests/backend.c` with `collector.c`, `-Wall -Wextra -Werror` | Passed parser, client/domain/type extraction, ring, cursor, stream and file boundaries. |
| The same collector test with AddressSanitizer and UndefinedBehaviorSanitizer | Passed on the Ubuntu/glibc host, with no sanitizer diagnostics. |
| `tests/backend_smoke.py` against real ubusd and the compiled native daemon | Passed native API/state transitions, paginated 10,000-record export, helper failure, session expiry, inode replacement fail-stop, crash recovery and TERM handling. This test uses an isolated lifecycle-helper fixture, not a real dnsmasq restart. |
| `tests/ruantiblock-regression.py --real-uci` with release-pinned ucode | **18 tests passed**, including invalid domains/list identifiers, unsupported configurations, unsafe filesystem objects, locking/conflicts, preservation of entries/comments/DNS overrides and no automatic apply. Uses real UCI and filesystem operations in isolated test directories. |
| `tests/lifecycle-smoke.sh` with real dnsmasq **2.90** and UCI | Passed A/AAAA resolution and dedicated client-IP logging, preservation of upstreams/confdir, truncation with unchanged dnsmasq PID, start/stop/recovery/idempotent stop, refusal of pending DHCP changes/existing query logging, and DNS resolution after stop. A committed confdir change during capture survived restoration and produced the new expected DNS answer. |
| Live Chromium/LuCI 24.10 browser smoke against real ubus, native daemon, UCI and dnsmasq 2.90 | Passed start/stop confirmation, raw/unique display, case-insensitive grouping, filters, count sorting, selection, clipboard copy, TXT/CSV file downloads, confirmed ruantiblock source-list addition, shared clear/stop across two sessions, and capture while every browser tab was closed. A hostile DHCP hostname remained literal text; no SVG node or injected script appeared. |
| Responsive browser surface | A 390-pixel viewport had a 390-pixel document width. The DNS table scrolled inside its container; the page did not overflow horizontally. |
| Original SDK cross-build (r1) | Produced both IPKs with OpenWrt **24.10.5 rockchip/armv8**, GCC **13.3.0**, musl and release-pinned feeds. Main package architecture is `aarch64_generic`; Russian package is `all`. |
| SDK-built IPK runtime smoke (r1; identical runtime payload in r2) | Extracted the **stripped ARM executable from the SDK-built IPK**, ran it with QEMU aarch64 and the SDK's OpenWrt libraries, and served the IPK's minified frontend with real LuCI 24.10 resources. Through the UI, start captured a real A/AAAA pair and grouped it into one domain with count 2; native CSV export returned both records; stop restored DNS and a subsequent A/AAAA lookup succeeded. No browser runtime errors occurred. |
| IPK payload inspection | Confirmed native ARM ELF/interpreter, dependency metadata, install/removal hooks, config/menu/ACL/ucode/frontend/translation payloads, root ownership, 0755 executable modes and 0644 configuration/ACL modes. |

The browser's transport fixture supplied only LuCI framework discovery/session plumbing; monitoring RPCs invoked real ubus, and the ruantiblock editor used real filesystem/UCI operations. The fixture server is **not included in the package** and is not a new router endpoint. The ruantiblock executable was deliberately not invoked: additions are pending until the user selects Update in the existing ruantiblock application.

## Coverage of the requested scenarios

1. **DNS parsing, IP/domain extraction, A/AAAA:** collector tests plus real dnsmasq queries.
2. **Duplicate grouping:** model tests and a live mixed-case query sequence. Ten raw A/AAAA requests produced four unique domains; the repeated domain had count 4.
3. **Invalid input:** native API and editor regressions; a live invalid-IP request was rejected without changing the active client or history.
4. **Truncation/rotation:** stream/file tests cover truncation, truncation followed by regrowth, partial/malformed lines and inode replacement. Real dnsmasq continued writing to the same truncated inode without a restart. Replacement is treated as a fail-stop condition, not ordinary rename-based rotation.
5. **Start/stop, repeated operations, concurrency:** API/lifecycle smoke plus two real browser sessions. They saw the same monitoring state and clear/stop transitions. Independent cursors returned the same retained records without consuming another session's data.
6. **Browser closure:** after closing every tab, the daemon remained active; another real A/AAAA request was captured, and reopening the page showed 12 retained requests.
7. **Empty/malformed logs:** parser/stream tests and the initial empty live history.
8. **ruantiblock safety:** 18 filesystem/UCI regressions plus confirmed addition of `api.example.com`, preserving a pre-existing entry and comment. The UI reported pending changes rather than claiming routing had been applied.
9. **DNS after stopping:** real dnsmasq lookups before/after restoration, including the final packaged ARM runtime smoke.

## Re-running the retained tests

Use a Linux development environment. Node.js, Python, gettext, CMake and compilers are **test/build tools only**, not router runtime dependencies.

Unprivileged collector/model checks:

```sh
node tests/frontend-model.js
node --check htdocs/luci-static/resources/view/dns-monitor/overview.js
msgfmt --check-format -o /tmp/dns-monitor-ru.mo po/ru/dns-monitor.po
cc -std=c11 -O2 -g -Wall -Wextra -Werror \
  tests/backend.c src/collector.c -o /tmp/dns-monitor-backend
/tmp/dns-monitor-backend
cc -std=c11 -O1 -g -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  tests/backend.c src/collector.c -o /tmp/dns-monitor-backend-sanitized
/tmp/dns-monitor-backend-sanitized
```

Native ubus smoke requires matching **host-architecture** libubox/libubus/json-c development libraries and a host ubusd executable. Do not link a host test against ARM SDK libraries. Ucode regressions additionally require fs/uci modules and UCI; the executed ucode revision was `3f64c8089bf3ea4847c96b91df09fbfcaec19e1d` from the OpenWrt 24.10 release package.

```sh
# Example for host dependencies installed under /usr/local:
PATH=/usr/local/bin:/usr/local/sbin:$PATH \
CPPFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib \
LD_LIBRARY_PATH=/usr/local/lib python3 tests/backend_smoke.py

PATH=/usr/local/bin:/usr/local/sbin:$PATH \
LD_LIBRARY_PATH=/opt/ucode24/lib:/usr/local/lib \
python3 tests/ruantiblock-regression.py \
  --ucode /opt/ucode24/bin/ucode --real-uci
```

**Run the lifecycle smoke only in a disposable root filesystem/container/chroot, never on a production router or ordinary workstation root.** It intentionally creates `/etc/config/dhcp`, a fixture dnsmasq init script, services on ports 10053/10054 and a fixed-address upstream. It requires dnsmasq 2.90, UCI, flock, BusyBox-compatible shell utilities and `nslookup`. Its safety marker must be created deliberately inside that disposable environment:

```sh
touch /tmp/dns-monitor-test-root
/bin/sh /path/to/luci-app-dns-monitor/tests/lifecycle-smoke.sh \
  /path/to/luci-app-dns-monitor
```

Build commands, SDK checksum and installation/rollback procedure are in [README.md](README.md).

## Build environment and corrected failures

The development workstation was Windows; builds/tests ran in disposable Linux chroots under WSL. Native tests used Alpine/musl and real dnsmasq 2.90; sanitizer and SDK work used Ubuntu 24.04. The release SDK's LuCI feed revision was `d88390be4ec9722cb427fee03368fc8c8582627d`.

Initial checks exposed and corrected:

* missing SDK `python3-pyelftools` prerequisite;
* missing OpenWrt `BuildPackage` scan signature, and LuCI naming/hook ordering when building through a symlink;
* missing semicolons in generated test-only ucode fixture functions;
* LuCI scalar HTML children and boolean attributes: rendering uses literal text nodes, and disabled options are set through their DOM property. The live before/after browser check verified working selectors;
* export pagination required to stay within stock ubus message limits for large histories.

The original SDK build completed successfully. It emitted unrelated feed/Kconfig warnings for absent packages and type redefinitions; these did not prevent producing the application or translation IPKs. The Alpine sanitizer link initially lacked sanitizer runtime libraries; the successful sanitizer run was performed on Ubuntu instead.

## Executed on the physical Orange Pi — r2

SSH public-key access reached the user's **Xunlong Orange Pi R1 Plus LTS**, OpenWrt **24.10.5 r29087-d9c5716d1d**, kernel **6.6.119**, target **rockchip/armv8**.

* Before the fix, procd reported the collector running but `ubus call dns-monitor status` failed. Executing the actual recovery helper printed `stat: not found` and returned 1: the original package omitted `coreutils-stat`, and this firmware's BusyBox does not provide `stat`.
* Installing `coreutils-stat` made recovery succeed. The existing collector's retry published the native API, reporting inactive state, zero captured/retained queries and the configured bounds.
* Built r2 IPKs by updating version/dependency control metadata in the SDK-built r1 packages. Both compressed runtime payloads were verified byte-for-byte unchanged. The original disposable SDK was no longer available; no new cross-compilation is claimed.
* Uploaded both r2 IPKs into router RAM and installed them with the router's real `opkg`. The main package's installed dependency metadata includes `coreutils-stat`; both main and Russian packages report `1.0.0-r2`. Upgrade emitted a non-fatal `service delete ... (Not found)` diagnostic during repeated generated/custom service cleanup; opkg completed, and the final procd instance and native API were running.
* Used a temporary authenticated administrative session over an SSH-forwarded, loopback-only LuCI connection. Chromium opened the actual router's status overview, followed **Services → DNS Monitor**, and rendered the native view. No JavaScript errors occurred. A valid manually entered IP enabled Start; an empty IP disabled it. Start was not clicked, and monitoring stayed inactive.
* Actual `nslookup example.com 127.0.0.1` returned IPv4 and IPv6 answers after the upgrade.
* Before/after SHA-256 values of `/etc/config/dhcp`, `network`, `firewall`, `openvpn`, `https-dns-proxy`, and `ruantiblock` were identical. The dnsmasq, OpenVPN and HTTPS DNS Proxy process IDs were unchanged. No DNS/network/VPN restart or ruantiblock apply was performed.
* The server-side menu cache contained a satisfied DNS Monitor node, and the user's existing root session had its read/write access group. Collector startup failure and browser menu visibility are separate issues; the fresh authenticated menu worked, but the user's previously missing browser menu was not reproduced.

## Remaining physical-hardware limits

These inactive-state checks are **not a full physical-router certification**. Still unexercised on this device:

* actual procd reboot/respawn/shutdown recovery under active capture;
* ujail logfile bind mounts, router power-loss recovery and real start/stop logging transitions;
* HTTPS DNS Proxy **2025.12.29-r1** callbacks during capture, ruantiblock's actual Update/download/apply operation, and changes to an active VPN tunnel;
* firewall4/nftables runtime effects under capture, RAM/CPU overhead under real LAN load, and worst-case DNS interruption duration;
* DNS continuity during an actual dnsmasq restart. A brief interruption is expected and explicitly confirmed in the UI.

Upstream source for these interfaces was inspected, and the implementation avoids changing DNS upstreams, generated ruantiblock files, nftables/routing/VPN state or the proxy configuration. Before relying on it in production, verify start/stop and expiry with a LAN client, confirm unchanged DoH upstreams and generated confdir, check normal DNS after stop/reboot, and deliberately apply a small exported domain set through ruantiblock's existing Update workflow.

The 5 MiB regular-file threshold is not an absolute filesystem quota. Catastrophic log-write failures can cause upstream dnsmasq to fall back to syslog; the package cannot honestly guarantee suppression of that upstream behavior without modifying dnsmasq. See the stability/privacy limits in README.
