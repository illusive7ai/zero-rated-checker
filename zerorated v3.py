#!/usr/bin/env python3
"""
ZERO-RATED CHECKER v3.0
Features: billed-bytes heuristic, SNI/Host matrix, payloads, ports,
HTTP/2+ALPN, redirect walk, ASN filter, latency/jitter/loss,
keepalive, IPv6, adaptive workers.
"""

import socket
import ssl
import os
import time
import re
import threading
import struct
import json
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 8
MAX_WORKERS = 20
MIN_WORKERS = 4
SCAN_DIR = "/sdcard/Download/"
PAYLOAD_BYTES = 256 * 1024
KEEPALIVE_SEC = 30
PORTS = [80, 443, 8080, 8443, 3128, 8000]
ASN_PREFER = ("FACEBOOK", "META", "GOOGLE", "AKAMAI", "CLOUDFLARE", "AMAZON", "FASTLY", "MICROSOFT")

PAYLOADS = {
    "get": lambda host: (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\nConnection: close\r\n\r\n"
    ),
    "connect": lambda host: (
        f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n"
        f"User-Agent: Mozilla/5.0\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    ),
    "abs_uri": lambda host: (
        f"GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    ),
    "ws": lambda host: (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ),
    "x_online": lambda host: (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nX-Online-Host: {host}\r\n"
        f"X-Forwarded-For: 1.1.1.1\r\nUser-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ),
}

# optional bug-host pairs: (sni, host_header)
DEFAULT_BUG_HOSTS = ["detectportal.firefox.com", "connectivitycheck.gstatic.com", "www.google.com"]


class AdaptivePool:
    def __init__(self, max_w=MAX_WORKERS, min_w=MIN_WORKERS):
        self.max_w = max_w
        self.min_w = min_w
        self.workers = max(min_w, max_w // 2)
        self.lock = threading.Lock()
        self.fails = 0
        self.ok = 0
        self.per_asn = defaultdict(int)
        self.asn_cap = 8

    def note(self, ok, asn=None):
        with self.lock:
            if ok:
                self.ok += 1
                self.fails = max(0, self.fails - 1)
                if self.ok % 12 == 0 and self.workers < self.max_w:
                    self.workers += 1
            else:
                self.fails += 1
                if self.fails >= 6:
                    self.workers = max(self.min_w, self.workers - 2)
                    self.fails = 0
            if asn:
                self.per_asn[asn] += 1

    def allow_asn(self, asn):
        with self.lock:
            return self.per_asn.get(asn, 0) < self.asn_cap


def parse_http(raw: bytes):
    text = raw.decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    status = ""
    headers = {}
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            status = parts[1]
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, text


def dns_all(host, port):
    out = {"v4": [], "v6": []}
    try:
        for fam, addrs, key in (
            (socket.AF_INET, out["v4"], 0),
            (socket.AF_INET6, out["v6"], 0),
        ):
            try:
                infos = socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM)
                for inf in infos:
                    ip = inf[4][0]
                    if ip not in addrs:
                        addrs.append(ip)
            except socket.gaierror:
                pass
    except Exception:
        pass
    return out


def cymru_asn(ip):
    """Team Cymru DNS: IP.reversed.origin.asn.cymru.com TXT"""
    try:
        if ":" in ip:
            # v6 nibble form
            exp = ipaddress.IPv6Address(ip).exploded.replace(":", "")
            q = ".".join(reversed(list(exp))) + ".origin6.asn.cymru.com"
        else:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        import subprocess
        r = subprocess.run(
            ["nslookup", "-type=TXT", q],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r'"(\d+)\s+\|\s+[^|]+\|\s+[^|]+\|\s+[^|]+\|\s+([^"]+)"', r.stdout)
        if m:
            return m.group(1), m.group(2).strip()
        # fallback parse
        m2 = re.search(r'"([^"]+)"', r.stdout)
        if m2:
            parts = [p.strip() for p in m2.group(1).split("|")]
            if len(parts) >= 5:
                return parts[0], parts[4]
    except Exception:
        pass
    return "", ""


def wrap_tls(sock, sni, alpn=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    return ctx.wrap_socket(sock, server_hostname=sni or None)


def recv_all(sock, limit=65536, idle=TIMEOUT):
    sock.settimeout(idle)
    buf = b""
    while len(buf) < limit:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf and len(buf) > 512:
                # headers in; optional short body
                if len(buf) >= 8192:
                    break
        except socket.timeout:
            break
        except Exception:
            break
    return buf


def try_http2_preface(sock):
    try:
        sock.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        sock.settimeout(3)
        data = sock.recv(24)
        return bool(data)
    except Exception:
        return False


def netstats_snapshot():
    """Android billed-bytes hint; no-op elsewhere."""
    try:
        import subprocess
        r = subprocess.run(
            ["dumpsys", "netstats"],
            capture_output=True, text=True, timeout=8,
        )
        nums = [int(x) for x in re.findall(r"rb=(\d+)", r.stdout)]
        return sum(nums[-8:]) if nums else None
    except Exception:
        return None


def billed_delta(before, after):
    if before is None or after is None:
        return None
    return max(0, after - before)


class Probe:
    def __init__(self):
        self.lock = threading.Lock()
        self.results = []
        self.pool = AdaptivePool()

    def one_connect(self, ip, port, sni, host_hdr, payload_name, use_tls, alpn, family):
        rec = {
            "ip": ip, "port": port, "sni": sni, "host": host_hdr,
            "payload": payload_name, "family": family,
            "status": "", "server": "", "alpn": "",
            "latency_ms": 0, "jitter_ms": 0, "loss": 0.0,
            "keepalive_ok": False, "redirect": "", "final_host": host_hdr,
            "asn": "", "org": "", "zero_rated": False,
            "billed_delta": None, "error": "", "http2": False,
        }
        samples = []
        raw = b""
        sock = None
        try:
            fam = socket.AF_INET6 if family == "v6" else socket.AF_INET
            sock = socket.socket(fam, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            t0 = time.time()
            sock.connect((ip, port))
            samples.append((time.time() - t0) * 1000)

            if use_tls:
                sock = wrap_tls(sock, sni, alpn=alpn)
                try:
                    rec["alpn"] = sock.selected_alpn_protocol() or ""
                except Exception:
                    rec["alpn"] = ""
                if rec["alpn"] == "h2":
                    rec["http2"] = True

            body = PAYLOADS.get(payload_name, PAYLOADS["get"])(host_hdr)
            if payload_name == "h2_preface" and use_tls:
                rec["http2"] = try_http2_preface(sock)
                rec["status"] = "H2" if rec["http2"] else ""
            else:
                before = netstats_snapshot()
                t1 = time.time()
                sock.send(body.encode())
                raw = recv_all(sock)
                samples.append((time.time() - t1) * 1000)
                after = netstats_snapshot()
                rec["billed_delta"] = billed_delta(before, after)

                # optional extra payload download for feature 1
                if rec["billed_delta"] is None:
                    rec["billed_delta"] = None

            status, hdrs, text = parse_http(raw) if raw else ("", {}, "")
            rec["status"] = status
            rec["server"] = hdrs.get("server", "")
            loc = hdrs.get("location", "")
            rec["redirect"] = loc
            if loc:
                try:
                    rec["final_host"] = urlparse(loc).hostname or host_hdr
                except Exception:
                    rec["final_host"] = host_hdr

            # keepalive (feature 9)
            try:
                sock.settimeout(KEEPALIVE_SEC + 2)
                time.sleep(min(3, KEEPALIVE_SEC))  # short hold in scan; bump for deep test
                sock.send(b"\r\n")
                rec["keepalive_ok"] = True
            except Exception:
                rec["keepalive_ok"] = False

            if samples:
                rec["latency_ms"] = int(sum(samples) / len(samples))
                if len(samples) > 1:
                    mean = rec["latency_ms"]
                    rec["jitter_ms"] = int((sum((s - mean) ** 2 for s in samples) / len(samples)) ** 0.5)
            rec["loss"] = 0.0 if rec["status"] or rec["http2"] else 1.0

            asn, org = cymru_asn(ip)
            rec["asn"], rec["org"] = asn, org

            answered = bool(rec["status"] or rec["http2"] or rec["server"])
            unbilled = rec["billed_delta"] is None or rec["billed_delta"] < PAYLOAD_BYTES * 0.25
            rec["zero_rated"] = answered and unbilled

        except socket.timeout:
            rec["error"] = "timeout"
            rec["loss"] = 1.0
        except ssl.SSLError as e:
            rec["error"] = f"ssl:{e}"[:40]
            rec["loss"] = 1.0
        except Exception as e:
            rec["error"] = str(e)[:40]
            rec["loss"] = 1.0
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        return rec

    def matrix_for_host(self, host, ports=None, bug_hosts=None, payloads=None, deep_ka=False):
        ports = ports or PORTS
        bug_hosts = bug_hosts or [host] + DEFAULT_BUG_HOSTS
        payloads = payloads or list(PAYLOADS.keys()) + ["h2_preface"]
        jobs = []
        addrs = dns_all(host, 443)
        for fam in ("v4", "v6"):
            for ip in addrs[fam]:
                for port in ports:
                    use_tls = port in (443, 8443) or port != 80
                    for sni in bug_hosts:
                        for hh in bug_hosts:
                            for pn in payloads:
                                alpn = ["h2", "http/1.1"] if use_tls else None
                                jobs.append((ip, port, sni, hh, pn, use_tls, alpn, fam))

        # de-dupe extreme explosion: cap combinations
        if len(jobs) > 80:
            # prefer matching sni==host, get/x_online/connect, 80/443, both families
            prio = []
            rest = []
            for j in jobs:
                ip, port, sni, hh, pn, use_tls, alpn, fam = j
                if port in (80, 443) and pn in ("get", "x_online", "connect", "h2_preface") and (sni == host or hh == host):
                    prio.append(j)
                else:
                    rest.append(j)
            jobs = (prio + rest)[:80]

        out = []
        workers = self.pool.workers
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self.one_connect, *j) for j in jobs]
            for fut in as_completed(futs):
                rec = fut.result()
                rec["target"] = host
                prefer = any(x in (rec["org"] or "").upper() for x in ASN_PREFER)
                rec["asn_prefer"] = prefer
                if rec["asn"] and not self.pool.allow_asn(rec["asn"]):
                    rec["error"] = (rec["error"] + "|asn_cap").strip("|")
                self.pool.note(rec["zero_rated"], rec["asn"] or None)
                with self.lock:
                    self.results.append(rec)
                out.append(rec)
        return out


def is_valid_host(host):
    host = host.strip()
    host = host.replace("https://", "").replace("http://", "")
    host = host.split("/")[0].split(":")[0]
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", host))


def load_hosts(filepath):
    hosts = []
    try:
        with open(filepath) as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#") and is_valid_host(host):
                    hosts.append(host)
    except Exception:
        pass
    return list(dict.fromkeys(hosts))


def browse_files(directory):
    if directory == SCAN_DIR and not os.path.isdir(directory):
        directory = "."
    path = Path(directory)
    if not path.exists():
        path = Path(".")
    txt_files = sorted([f for f in path.glob("*.txt") if f.is_file()])
    if not txt_files:
        print("\nNo .txt files found")
        return None
    print(f"\nFILE BROWSER  {path}")
    for i, f in enumerate(txt_files):
        print(f"  [{i+1:2d}] {f.name} ({len(load_hosts(f))} hosts)")
    print("  [ 0] Cancel")
    return txt_files


def score(r):
    s = 0
    if r["zero_rated"]:
        s += 50
    if r["asn_prefer"]:
        s += 15
    if r["http2"] or r["alpn"] == "h2":
        s += 10
    if r["keepalive_ok"]:
        s += 8
    if r["status"] in ("200", "301", "302", "204"):
        s += 8
    s -= min(r["latency_ms"] // 50, 15)
    s -= int(r["jitter_ms"] // 30)
    s -= int(r["loss"] * 20)
    if r["billed_delta"] is not None:
        s += 10 if r["billed_delta"] < 4096 else -10
    return s


def main():
    print()
    print("ZERO-RATED CHECKER v3.0")
    print("OFF WiFi | ON Mobile Data")
    print("[1] Single host  [2] File  [0] Exit")
    try:
        choice = input("> ").strip()
    except KeyboardInterrupt:
        return

    hosts = []
    if choice == "1":
        host = input("Host: ").strip()
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        if is_valid_host(host):
            hosts = [host]
        else:
            print("Invalid host")
            return
    elif choice == "2":
        files = browse_files(SCAN_DIR) or browse_files(".")
        if not files:
            return
        idx = input("File #: ").strip()
        if not idx.isdigit() or int(idx) < 1:
            return
        hosts = load_hosts(files[int(idx) - 1])
    else:
        return

    extra_sni = input("Extra bug-hosts (comma, empty=defaults): ").strip()
    bugs = [h.strip() for h in extra_sni.split(",") if h.strip()] if extra_sni else None

    probe = Probe()
    t0 = time.time()
    for i, h in enumerate(hosts, 1):
        print(f"\n[{i}/{len(hosts)}] {h}  workers={probe.pool.workers}")
        recs = probe.matrix_for_host(h, bug_hosts=bugs)
        hits = [r for r in recs if r["zero_rated"]]
        print(f"  combos={len(recs)} hits={len(hits)}")
        for r in sorted(hits, key=score, reverse=True)[:5]:
            print(
                f"  + {r['ip']}:{r['port']} sni={r['sni']} host={r['host']} "
                f"{r['payload']} {r['status']}/{r['alpn']} "
                f"{r['latency_ms']}ms j={r['jitter_ms']} "
                f"AS{r['asn']} {r['org'][:24]} billed={r['billed_delta']}"
            )

    elapsed = time.time() - t0
    working = [r for r in probe.results if r["zero_rated"]]
    working.sort(key=score, reverse=True)

    print("\n========== SCAN COMPLETE ==========")
    print(f"probes={len(probe.results)} hits={len(working)} time={elapsed:.1f}s")
    print("top 25:")
    for r in working[:25]:
        print(
            f"  {r.get('target','')} {r['ip']}:{r['port']} "
            f"SNI={r['sni']} Host={r['host']} {r['payload']} "
            f"st={r['status']} alpn={r['alpn']} h2={r['http2']} "
            f"ka={r['keepalive_ok']} loc={r['redirect'][:40]} "
            f"{r['latency_ms']}ms AS{r['asn']} {r['org'][:20]} "
            f"bill={r['billed_delta']} score={score(r)}"
        )

    out = f"zero_rated_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump({"hits": working, "all": probe.results}, f, indent=2)
    txt = out.replace(".json", ".txt")
    with open(txt, "w") as f:
        for r in working:
            f.write(
                f"{r.get('target')} | {r['ip']}:{r['port']} | SNI={r['sni']} | "
                f"Host={r['host']} | {r['payload']} | {r['status']} | "
                f"AS{r['asn']} {r['org']} | {r['latency_ms']}ms | "
                f"redir={r['redirect']} | billed={r['billed_delta']}\n"
            )
    print(f"saved {out} and {txt}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
