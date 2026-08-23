#!/usr/bin/env python3
"""
ZERO-RATED CHECKER v3.1
Features: billed-bytes heuristic, SNI/Host matrix, payloads, ports,
HTTP/2+ALPN, redirect walk, ASN filter, latency/jitter/loss,
keepalive, IPv6, adaptive workers.
Enhanced with neon colors and loading animations.
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
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== COLOR DEFINITIONS ====================
class Colors:
    """Neon color palette for terminal output"""
    # Foreground colors
    NEON_PINK = '\033[38;5;198m'
    NEON_BLUE = '\033[38;5;51m'
    NEON_GREEN = '\033[38;5;46m'
    NEON_PURPLE = '\033[38;5;165m'
    NEON_YELLOW = '\033[38;5;226m'
    NEON_ORANGE = '\033[38;5;208m'
    NEON_CYAN = '\033[38;5;87m'
    NEON_RED = '\033[38;5;196m'
    NEON_WHITE = '\033[38;5;231m'
    
    # Effects
    FLASH = '\033[5m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_BLUE = '\033[44m'
    BG_PURPLE = '\033[45m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'

# Check if terminal supports colors
if not sys.stdout.isatty():
    for attr in dir(Colors):
        if not attr.startswith('__'):
            setattr(Colors, attr, '')

# ==================== ANIMATION FUNCTIONS ====================
def cyber_scan(operation, duration=2):
    """Display a cyber-style loading animation"""
    chars = "⣾⣽⣻⢿⡿⣟⣯⣷"
    progress = ["░" * i + "█" * (10-i) for i in range(11)]
    
    print(f"\n{Colors.NEON_BLUE}[>] {Colors.FLASH}{Colors.BOLD}INITIATING {operation} SEQUENCE{Colors.NC}")
    
    for i in range(11):
        spin = chars[i % len(chars)]
        perc = i * 10
        prog = progress[i] if i < len(progress) else progress[-1]
        sys.stdout.write(f"\r{Colors.NEON_CYAN}[{spin}]{Colors.NC} {Colors.NEON_PURPLE}{prog}{Colors.NC} {Colors.NEON_ORANGE}{perc:3d}%{Colors.NC} {Colors.NEON_YELLOW}|{Colors.NC} {Colors.NEON_GREEN}Processing...{Colors.NC}")
        sys.stdout.flush()
        time.sleep(duration / 11)
    
    print(f"\n{Colors.NEON_GREEN}{Colors.BOLD}[✓] {operation} COMPLETE{Colors.NC}\n")

def loading_animation(message, duration=1.5):
    """Simple loading animation with dots"""
    dots = ["   ", ".  ", ".. ", "..."]
    for i in range(int(duration * 10)):
        dot = dots[i % len(dots)]
        sys.stdout.write(f"\r{Colors.NEON_CYAN}[*]{Colors.NC} {Colors.NEON_PURPLE}{message}{Colors.NEON_YELLOW}{dot}{Colors.NC}")
        sys.stdout.flush()
        time.sleep(0.1)
    print()

def progress_bar(current, total, prefix="", suffix=""):
    """Display a progress bar with percentage"""
    bar_length = 30
    if total == 0:
        percent = 0
    else:
        percent = current / total
    
    filled = int(bar_length * percent)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    sys.stdout.write(f"\r{Colors.NEON_CYAN}[{Colors.NEON_GREEN}{bar}{Colors.NEON_CYAN}]{Colors.NC} {Colors.NEON_ORANGE}{percent*100:6.2f}%{Colors.NC} {prefix}{Colors.NEON_YELLOW}{suffix}{Colors.NC}")
    sys.stdout.flush()

def status_box(title, content, color=Colors.NEON_PURPLE):
    """Display a status box with borders"""
    width = 50
    print(f"{color}{'═' * width}{Colors.NC}")
    print(f"{color}║ {Colors.BOLD}{title:^46}{Colors.NC}{color} ║{Colors.NC}")
    print(f"{color}{'─' * width}{Colors.NC}")
    for line in content:
        print(f"{color}║ {Colors.NC}{line[:46]:<46}{color} ║{Colors.NC}")
    print(f"{color}{'═' * width}{Colors.NC}")

def glitch_text(text, repeats=3):
    """Display text with glitch effect"""
    colors = [Colors.NEON_PINK, Colors.NEON_BLUE, Colors.NEON_CYAN]
    for _ in range(repeats):
        for color in colors:
            sys.stdout.write(f"\r{color}{text}{Colors.NC}")
            sys.stdout.flush()
            time.sleep(0.07)
    print(f"\r{Colors.NEON_GREEN}{Colors.BOLD}{text}{Colors.NC}")

# ==================== CONFIGURATION ====================
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

DEFAULT_BUG_HOSTS = ["detectportal.firefox.com", "connectivitycheck.gstatic.com", "www.google.com"]

# ==================== MAIN CLASSES ====================
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
        for fam, addrs in ((socket.AF_INET, out["v4"]), (socket.AF_INET6, out["v6"])):
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

            try:
                sock.settimeout(KEEPALIVE_SEC + 2)
                time.sleep(min(3, KEEPALIVE_SEC))
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

        if len(jobs) > 80:
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
        total = len(jobs)
        
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self.one_connect, *j) for j in jobs]
            completed = 0
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
                completed += 1
                progress_bar(completed, total, prefix=f"Scanning {host[:20]}... ")
        
        print()  # New line after progress bar
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
        print(f"\n{Colors.NEON_RED}[!] No .txt files found{Colors.NC}")
        return None
    
    print(f"\n{Colors.NEON_CYAN}╔{'═' * 48}╗{Colors.NC}")
    print(f"{Colors.NEON_CYAN}║{Colors.NC} {Colors.BOLD}FILE BROWSER{Colors.NC} {' ' * 36}{Colors.NEON_CYAN}║{Colors.NC}")
    print(f"{Colors.NEON_CYAN}╠{'═' * 48}╣{Colors.NC}")
    for i, f in enumerate(txt_files):
        host_count = len(load_hosts(f))
        color = Colors.NEON_GREEN if host_count > 0 else Colors.NEON_RED
        print(f"{Colors.NEON_CYAN}║{Colors.NC} [{i+1:2d}] {f.name[:35]:35s} ({color}{host_count:4d}{Colors.NC} hosts) {Colors.NEON_CYAN}║{Colors.NC}")
    print(f"{Colors.NEON_CYAN}║{Colors.NC} [ 0] Cancel{' ' * 38}{Colors.NEON_CYAN}║{Colors.NC}")
    print(f"{Colors.NEON_CYAN}╚{'═' * 48}╝{Colors.NC}")
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

def print_result(result, is_zero_rated=False):
    """Print a result with appropriate coloring"""
    host = result.get('target', '')[:25]
    ip = result['ip']
    port = result['port']
    status = result['status'] or result['error'] or 'N/A'
    latency = result['latency_ms']
    asn = result['asn'] or 'N/A'
    org = result['org'][:20] if result['org'] else 'N/A'
    
    if is_zero_rated:
        status_color = Colors.NEON_GREEN
        prefix = f"{Colors.NEON_GREEN}[+]"
        status_display = f"{Colors.NEON_GREEN}{status}{Colors.NC}"
    else:
        status_color = Colors.NEON_RED
        prefix = f"{Colors.NEON_RED}[-]"
        status_display = f"{Colors.NEON_RED}{status}{Colors.NC}"
    
    print(f"{prefix} {Colors.NEON_CYAN}{host}{Colors.NC} "
          f"{Colors.NEON_YELLOW}{ip}:{port}{Colors.NC} "
          f"{status_display} "
          f"{Colors.NEON_PURPLE}{latency}ms{Colors.NC} "
          f"{Colors.NEON_BLUE}AS{asn}{Colors.NC} "
          f"{Colors.DIM}{org}{Colors.NC}")

# ==================== MAIN FUNCTION ====================
def main():
    # Clear screen and show header
    os.system('clear' if os.name == 'posix' else 'cls')
    
    print()
    print(f"{Colors.NEON_PURPLE}{'═' * 52}{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}║{Colors.NC}  {Colors.NEON_CYAN}{Colors.BOLD}ZERO-RATED CHECKER v3.1{Colors.NC}  {Colors.NEON_YELLOW}⚡{Colors.NC}  {Colors.NEON_GREEN}Advanced Network Scanner{Colors.NC}   {Colors.NEON_PURPLE}║{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}║{Colors.NC}  {Colors.NEON_RED}{Colors.DIM}┃{Colors.NC} {Colors.NEON_BLUE}OFF WiFi{Colors.NC} ┃ {Colors.NEON_ORANGE}ON Mobile Data{Colors.NC} {Colors.NEON_RED}┃{Colors.NC}               {Colors.NEON_PURPLE}║{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}{'═' * 52}{Colors.NC}")
    print()
    
    cyber_scan("SYSTEM CHECK", 1.5)
    
    print(f"{Colors.NEON_CYAN}╔{'═' * 48}╗{Colors.NC}")
    print(f"{Colors.NEON_CYAN}║{Colors.NC}  {Colors.NEON_GREEN}[1]{Colors.NC} Single Host  {Colors.NEON_YELLOW}[2]{Colors.NC} File Scan  {Colors.NEON_RED}[0]{Colors.NC} Exit  {Colors.NEON_CYAN}║{Colors.NC}")
    print(f"{Colors.NEON_CYAN}╚{'═' * 48}╝{Colors.NC}")
    print()
    
    try:
        choice = input(f"{Colors.NEON_PURPLE}[❯]{Colors.NC} ").strip()
    except KeyboardInterrupt:
        print(f"\n{Colors.NEON_YELLOW}[!] Interrupted{Colors.NC}")
        return

    hosts = []
    if choice == "1":
        host = input(f"{Colors.NEON_CYAN}[*] Host: {Colors.NC}").strip()
        host = host.replace("https://", "").replace("http://", "").split("/")[0]
        if is_valid_host(host):
            hosts = [host]
        else:
            print(f"{Colors.NEON_RED}[!] Invalid host{Colors.NC}")
            return
    elif choice == "2":
        files = browse_files(SCAN_DIR) or browse_files(".")
        if not files:
            return
        idx = input(f"{Colors.NEON_PURPLE}[❯] File #: {Colors.NC}").strip()
        if not idx.isdigit() or int(idx) < 1:
            return
        hosts = load_hosts(files[int(idx) - 1])
        if hosts:
            print(f"\n{Colors.NEON_GREEN}[+] Loaded {len(hosts)} hosts from {files[int(idx)-1].name}{Colors.NC}")
    else:
        return

    if not hosts:
        print(f"{Colors.NEON_RED}[!] No hosts to scan{Colors.NC}")
        return

    extra_sni = input(f"{Colors.NEON_CYAN}[*] Extra bug-hosts (comma, empty=defaults): {Colors.NC}").strip()
    bugs = [h.strip() for h in extra_sni.split(",") if h.strip()] if extra_sni else None

    print(f"\n{Colors.NEON_BLUE}[>] Starting scan...{Colors.NC}")
    print(f"{Colors.NEON_ORANGE}[i] Hosts: {len(hosts)} | Workers: {MAX_WORKERS}{Colors.NC}")
    
    probe = Probe()
    t0 = time.time()
    
    for i, h in enumerate(hosts, 1):
        print(f"\n{Colors.NEON_YELLOW}[{i}/{len(hosts)}] {Colors.NEON_CYAN}{h}{Colors.NC}  {Colors.DIM}workers={probe.pool.workers}{Colors.NC}")
        recs = probe.matrix_for_host(h, bug_hosts=bugs)
        hits = [r for r in recs if r["zero_rated"]]
        
        if hits:
            print(f"{Colors.NEON_GREEN}[+] {len(hits)} zero-rated found{Colors.NC}")
            for r in sorted(hits, key=score, reverse=True)[:5]:
                print_result(r, True)
        else:
            print(f"{Colors.NEON_RED}[-] No zero-rated found{Colors.NC}")

    elapsed = time.time() - t0
    working = [r for r in probe.results if r["zero_rated"]]
    working.sort(key=score, reverse=True)

    # Results summary
    print(f"\n{Colors.NEON_PURPLE}{'═' * 52}{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}║{Colors.NC}  {Colors.NEON_CYAN}{Colors.BOLD}SCAN COMPLETE{Colors.NC}  {' ' * 34}{Colors.NEON_PURPLE}║{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}╠{'═' * 52}╣{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}║{Colors.NC}  {Colors.NEON_YELLOW}Total probes:{Colors.NC} {len(probe.results):>4}         {Colors.NEON_GREEN}Hits:{Colors.NC} {len(working):>4}  {Colors.NEON_PURPLE}║{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}║{Colors.NC}  {Colors.NEON_ORANGE}Time elapsed:{Colors.NC} {elapsed:>6.1f}s      {Colors.NEON_RED}Blocked:{Colors.NC} {len(probe.results) - len(working):>4}  {Colors.NEON_PURPLE}║{Colors.NC}")
    print(f"{Colors.NEON_PURPLE}{'═' * 52}{Colors.NC}")

    if working:
        print(f"\n{Colors.NEON_GREEN}{Colors.BOLD}TOP 25 ZERO-RATED HOSTS:{Colors.NC}")
        print(f"{Colors.NEON_CYAN}{'─' * 50}{Colors.NC}")
        for r in working[:25]:
            print_result(r, True)
        
        # Save results
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
        print(f"\n{Colors.NEON_GREEN}[+] Saved: {out} and {txt}{Colors.NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.NEON_YELLOW}[!] Interrupted by user{Colors.NC}")
    except Exception as e:
        print(f"\n{Colors.NEON_RED}[!] Error: {e}{Colors.NC}")
