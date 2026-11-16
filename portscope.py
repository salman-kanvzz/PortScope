#!/usr/bin/env python3
"""
PortScope - Lightweight TCP Port Scanner & Banner Grabber (Educational OffSec Tool)

For authorized security testing and educational use only.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional


APP_NAME = "PortScope"
APP_VERSION = "1.0.0"
BANNER = r"""
 ____            _   ____                       
|  _ \ ___  _ __| |_/ ___|  ___ ___  _ __   ___ 
| |_) / _ \| '__| __\___ \ / __/ _ \| '_ \ / _ \
|  __/ (_) | |  | |_ ___) | (_| (_) | |_) |  __/
|_|   \___/|_|   \__|____/ \___\___/| .__/ \___|
                                    |_|         
Lightweight TCP Port Scanner & Banner Grabber
""".strip("\n")


@dataclass
class ScanResult:
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_ports(ports_str: str) -> List[int]:
    """Parse ports like '22,80,443' or '1-1024' or mixed '22,80,100-110'."""
    ports: set[int] = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ValueError("No valid ports specified (1-65535).")
    return sorted(ports)


def guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, port: int, timeout: float, grab_banner: bool) -> ScanResult:
    service = guess_service(port)
    banner = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            state = "open"
            if grab_banner:
                try:
                    # Try passive read first (some services send banners)
                    sock.settimeout(min(timeout, 1.0))
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()
                    else:
                        # Try a simple probe for HTTP-like services
                        if port in (80, 8080, 8000, 443, 8443):
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            data = sock.recv(1024)
                            banner = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = banner or ""
            return ScanResult(port=port, state=state, service=service, banner=banner[:300])
        # On Linux, non-zero can mean closed/refused; filtered often times out
        return ScanResult(port=port, state="closed", service=service, banner="")
    except socket.timeout:
        return ScanResult(port=port, state="filtered", service=service, banner="")
    except OSError:
        return ScanResult(port=port, state="filtered", service=service, banner="")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def resolve_host(target: str) -> str:
    return socket.gethostbyname(target)


def run_scan(
    target: str,
    ports: Iterable[int],
    timeout: float,
    threads: int,
    grab_banner: bool,
) -> dict:
    ip = resolve_host(target)
    ports_list = list(ports)
    results: List[ScanResult] = []
    lock = threading.Lock()

    def worker(p: int) -> ScanResult:
        return scan_port(ip, p, timeout, grab_banner)

    max_workers = max(1, min(threads, len(ports_list)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(worker, p): p for p in ports_list}
        for future in as_completed(future_map):
            res = future.result()
            with lock:
                results.append(res)

    results.sort(key=lambda r: r.port)
    open_ports = [r for r in results if r.state == "open"]
    summary = {
        "target": target,
        "resolved_ip": ip,
        "scanned_ports": len(results),
        "open": len(open_ports),
        "closed": sum(1 for r in results if r.state == "closed"),
        "filtered": sum(1 for r in results if r.state == "filtered"),
    }
    return {
        "tool": {"name": APP_NAME, "version": APP_VERSION},
        "timestamp_utc": utc_now_iso(),
        "summary": summary,
        "results": [r.to_dict() for r in results],
        "open_results": [r.to_dict() for r in open_ports],
    }


def print_report(data: dict, show_closed: bool = False) -> None:
    s = data["summary"]
    print(f"\nTarget:      {s['target']} ({s['resolved_ip']})")
    print(f"Scanned:     {s['scanned_ports']} ports")
    print(f"Open:        {s['open']} | Closed: {s['closed']} | Filtered: {s['filtered']}")
    print("-" * 72)
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} BANNER")
    print("-" * 72)
    for r in data["results"]:
        if r["state"] == "closed" and not show_closed:
            continue
        if r["state"] == "filtered" and not show_closed:
            continue
        banner = (r.get("banner") or "").replace("\n", " ")[:40]
        print(f"{r['port']:<8} {r['state']:<10} {r.get('service',''):<15} {banner}")
    if not show_closed and s["open"] == 0:
        print("(No open ports found in scanned range; use --show-all to include closed/filtered.)")
    print("-" * 72)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscope",
        description="PortScope - Lightweight TCP port scanner and banner grabber (authorized/educational use only).",
    )
    p.add_argument("target", help="Target hostname or IP address (authorized targets only).")
    p.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan: '22,80,443', '1-1024', or mixed '22,80,100-110' (default: 1-1024).",
    )
    p.add_argument("-t", "--timeout", type=float, default=0.5, help="Connection timeout in seconds (default: 0.5).")
    p.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100).")
    p.add_argument("-b", "--banner", action="store_true", help="Attempt basic banner grabbing on open ports.")
    p.add_argument("--show-all", action="store_true", help="Show closed/filtered ports in terminal output.")
    p.add_argument("-o", "--output", help="Write full JSON results to file.")
    p.add_argument("--no-banner-art", action="store_true", help="Suppress ASCII banner.")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.no_banner_art:
        print(BANNER)
        print(f"v{APP_VERSION}\n")

    try:
        ports = parse_ports(args.ports)
        if args.timeout <= 0:
            raise ValueError("Timeout must be > 0.")
        if args.threads < 1:
            raise ValueError("Threads must be >= 1.")

        print(f"[*] Resolving target: {args.target}")
        data = run_scan(args.target, ports, args.timeout, args.threads, args.banner)
        print_report(data, show_closed=args.show_all)

        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[+] JSON report saved to: {out}")

        print(f"\nDisclaimer: Use only on systems you own or have explicit permission to test.")
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except socket.gaierror as e:
        print(f"Error: Could not resolve target '{args.target}': {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        return 130
    except PermissionError as e:
        print(f"Error: Permission denied: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
