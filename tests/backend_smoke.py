#!/usr/bin/env python3
"""Linux integration test: real daemon/libubus/ubusd; isolated lifecycle fixture.
The fixture tests the fork/exec contract, NOT real dnsmasq/UCI restoration.
Run: python3 tests/backend_smoke.py (requires cc, ubusd, ubus, native libraries).
"""
import csv
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (subprocess.SubprocessError, OSError, ValueError):
            pass
        time.sleep(0.05)
    raise AssertionError(f"condition timed out: {last!r}")


def main():
    for executable in ["ubus", "ubusd"]:
        if not shutil.which(executable):
            raise RuntimeError(f"missing native dependency: {executable}")
    with tempfile.TemporaryDirectory(prefix="dns-monitor-smoke-") as temp:
        base = Path(temp)
        runtime = base / "runtime"
        runtime.mkdir(mode=0o711)
        socket = base / "ubus.sock"
        helper = base / "lifecycle"
        state = base / "enabled"
        failure = base / "fail-stop"
        fail_start = base / "fail-start"
        calls = base / "calls"
        leases = base / "leases"
        arp = base / "arp"
        leases.write_text(f"{int(time.time()) + 1000} aa:bb:cc:dd:ee:ff 192.168.1.2 laptop *\n0 123 2001:db8::1 ipv6-client duid\n")
        arp.write_text("IP address HW type Flags HW address Mask Device\n192.168.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * br-lan\n192.168.1.3 0x1 0x2 aa:bb:cc:dd:ee:01 * br-lan\n")
        helper.write_text("#!/bin/sh\n"
                          'printf "%s\\n" "$1" >> "$DM_TEST_CALLS"\n'
                          'case "$1" in\n'
                          'start) : > "$DM_TEST_LOG"; : > "$DM_TEST_STATE"; [ ! -e "$DM_TEST_FAIL_START" ] || exit 8 ;;\n'
                          'stop|recover) [ ! -e "$DM_TEST_FAIL" ] || exit 9; rm -f "$DM_TEST_STATE" ;;\n'
                          '*) exit 2 ;;\n'
                          'esac\n')
        helper.chmod(0o755)
        binary = base / "dns-monitor"
        command = shlex.split(os.environ.get("CC", "cc"))
        command += shlex.split(os.environ.get("CPPFLAGS", ""))
        command += shlex.split(os.environ.get("CFLAGS", "-O2 -g -Wall -Wextra -Werror"))
        for key, value in {"DM_DIRECTORY": runtime, "DM_HELPER": helper,
                           "DM_UBUS_SOCKET": socket, "DM_LEASES": leases, "DM_ARP": arp}.items():
            command += [f'-D{key}="{value}"']
        command += [str(ROOT / "src/dns-monitor.c"), str(ROOT / "src/collector.c"), "-o", str(binary)]
        command += shlex.split(os.environ.get("LDFLAGS", ""))
        command += ["-lubus", "-lubox", "-ljson-c", "-lm"]
        subprocess.run(command, check=True)
        env = os.environ.copy()
        env.update(DM_TEST_CALLS=str(calls), DM_TEST_LOG=str(runtime / "queries.log"),
                   DM_TEST_STATE=str(state), DM_TEST_FAIL=str(failure), DM_TEST_FAIL_START=str(fail_start))
        broker = subprocess.Popen(["ubusd", "-s", str(socket)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        daemon = None

        def launch(records=3, seconds=3):
            return subprocess.Popen([str(binary), "--max-records", str(records), "--max-log-bytes", "4096", "--session-seconds", str(seconds)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        def call(method, arguments=None):
            result = subprocess.run(["ubus", "-s", str(socket), "-t", "40", "call", "dns-monitor", method,
                                     json.dumps(arguments or {})], capture_output=True, text=True, check=True)
            return json.loads(result.stdout)

        def status():
            return call("status")

        def append(domain, ip="192.168.1.2", kind="A"):
            with (runtime / "queries.log").open("a") as stream:
                stream.write(f"Oct 10 05:06:07 dnsmasq[123]: query[{kind}] {domain} from {ip}\n")

        try:
            until(socket.exists)
            failure.touch()
            state.touch()
            (runtime / "queries.log").write_text("Oct 10 05:06:07 dnsmasq[123]: query[A] old.test from 192.168.1.2\n" * 300)
            daemon = launch()
            until(lambda: (runtime / "queries.log").exists() and (runtime / "queries.log").stat().st_size == 0)
            unavailable = subprocess.run(["ubus", "-s", str(socket), "call", "dns-monitor", "status", "{}"], capture_output=True)
            assert unavailable.returncode != 0 and state.exists()
            failure.unlink()
            initial = until(lambda: status())
            assert not initial["active"] and not state.exists()
            assert calls.read_text().splitlines() == ["recover", "recover"]
            collision = subprocess.run([str(binary)], env=env, capture_output=True, text=True)
            assert collision.returncode != 0 and "another instance" in collision.stderr
            clients = call("get_clients")["clients"]
            assert {c["ip"]: c["status"] for c in clients} == {
                "192.168.1.2": "lease+neighbour", "192.168.1.3": "neighbour", "2001:db8::1": "lease"}
            running = call("start", {"client": "192.168.1.2"})
            assert running["active"] and running["epoch"] != initial["epoch"] and state.exists()
            assert call("start", {"client": "192.168.1.2"})["epoch"] == running["epoch"]
            assert "error" in call("start", {"client": "192.168.1.3"})
            append("Example.COM"); append('q"uote.test'); append("ignored.test", "192.168.1.3")
            until(lambda: status()["captured"] == 2)
            first = call("get_queries", {"epoch": running["epoch"], "cursor": 0, "limit": 1})
            assert not first["reset"] and first["more"] and first["records"][0]["domain"] == "Example.COM"
            second = call("get_queries", {"epoch": running["epoch"], "cursor": first["cursor"], "limit": 500})
            assert not second["more"] and second["records"][0]["domain"] == 'q"uote.test'
            exported = call("export", {"format": "csv"})
            rows = list(csv.reader(io.StringIO(exported["data"])))
            assert rows[0] == ["timestamp", "client_ip", "domain", "record_type"] and rows[2][2] == 'q"uote.test'
            assert call("export", {"format": "txt"})["data"] == 'Example.COM\nq"uote.test\n'
            export_first = call("export", {"format": "csv", "epoch": running["epoch"], "cursor": 0, "limit": 1})
            assert export_first["more"] and not export_first["reset"]
            export_second = call("export", {"format": "csv", "epoch": export_first["epoch"], "cursor": export_first["cursor"], "limit": 1})
            assert not export_second["more"] and not export_second["data"].startswith("timestamp,")
            assert len(list(csv.reader(io.StringIO(export_first["data"] + export_second["data"])))) == 3
            failure.touch()
            failed = call("stop")
            assert failed["active"] and "error" in failed and state.exists() and (runtime / "queries.log").exists()
            failure.unlink()
            stopped = call("stop")
            assert not stopped["active"] and stopped["retained"] == 2 and not state.exists() and not (runtime / "queries.log").exists()
            assert call("get_queries", {"epoch": running["epoch"], "cursor": 0})["records"]
            cleared = call("clear")
            assert cleared["epoch"] != running["epoch"] and cleared["retained"] == 0
            fail_start.touch(); failure.touch()
            fault = call("start", {"client": "192.168.1.2"})
            assert fault["active"] and "error" in fault and state.exists()
            append("failed-start.test")
            until(lambda: status()["captured"] == 1)
            fail_start.unlink(); failure.unlink()
            until(lambda: not status()["active"], timeout=10)
            ipv6 = call("start", {"client": "2001:0db8:0:0::1"})
            assert ipv6["client"] == "2001:db8::1"
            append("v6.test", "2001:db8::1", "AAAA")
            until(lambda: status()["captured"] == 1)
            until(lambda: not status()["active"], timeout=8)
            assert not state.exists()
            again = call("start", {"client": "192.168.1.2"})
            for index in range(7): append(f"n{index}.test")
            until(lambda: status()["captured"] == 7)
            evicted = call("get_queries", {"epoch": again["epoch"], "cursor": 1})
            assert evicted["reset"] and [r["id"] for r in evicted["records"]] == [5, 6, 7]
            export_evicted = call("export", {"format": "csv", "epoch": again["epoch"], "cursor": 1})
            assert export_evicted["reset"] and export_evicted["cursor"] == 7 and export_evicted["data"].startswith("timestamp,")
            # External inode replacement must request safe stop, never follow.
            os.rename(runtime / "queries.log", runtime / "old.log")
            (runtime / "queries.log").touch()
            until(lambda: not status()["active"])
            assert "inode replaced" in status().get("error", "")
            # SIGKILL leaves helper state; a fresh process must recover before API.
            call("start", {"client": "192.168.1.2"})
            daemon.kill(); daemon.wait(timeout=5)
            assert state.exists()
            daemon = launch()
            until(lambda: status()["epoch"] != again["epoch"] and not status()["active"])
            assert not state.exists()
            call("start", {"client": "192.168.1.2"})
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=10)
            assert daemon.returncode == 0 and not state.exists() and not (runtime / "queries.log").exists()
            # A full 10k ring of long names exceeds a single ubus message;
            # cursor-consumed export must return every record without overflow.
            daemon = launch(records=10000, seconds=60)
            until(lambda: not status()["active"])
            large = call("start", {"client": "192.168.1.2"})
            for batch in range(40):
                with (runtime / "queries.log").open("a") as stream:
                    for index in range(batch * 250, (batch + 1) * 250):
                        domain = f"n{index}." + ("a" * 60 + ".") * 3 + "example.test"
                        stream.write(f"Oct 10 05:06:07 dnsmasq[123]: query[A] {domain} from 192.168.1.2\n")
                until(lambda: status()["captured"] == (batch + 1) * 250)
            call("stop")
            assert status()["retained"] == 10000
            cursor, chunks = 0, []
            while True:
                part = call("export", {"format": "csv", "epoch": large["epoch"], "cursor": cursor, "limit": 500})
                assert not part["reset"] and part["oldest"] == 1 and part["newest"] == 10000
                chunks.append(part["data"])
                cursor = part["cursor"]
                if not part["more"]:
                    break
            content = "".join(chunks)
            assert len(content) > 1048576 and len(chunks) == 20
            assert len(list(csv.reader(io.StringIO(content)))) == 10001 and cursor == 10000
            daemon.terminate(); daemon.wait(timeout=10)
            print("backend smoke: native ubus API, paginated 10k export, helper failure, expiry, inode fail-stop, crash recovery, TERM passed")
        finally:
            if daemon and daemon.poll() is None:
                daemon.terminate()
                try: daemon.wait(timeout=10)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait()
            broker.terminate()
            try: broker.wait(timeout=5)
            except subprocess.TimeoutExpired: broker.kill(); broker.wait()


if __name__ == "__main__":
    main()
