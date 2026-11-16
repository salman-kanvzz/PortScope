# PortScope Overview

## Purpose
PortScope is a small educational offensive-security (OffSec) project that demonstrates how a basic **TCP connect port scanner** works. It is designed to be readable and easy to extend for learning in authorized lab environments.

## Core concepts

### 1. TCP connect scanning
PortScope attempts to establish a TCP connection to each target port using `socket.connect_ex()`:
- **Open:** connection succeeds (service is accepting connections).
- **Closed:** connection is actively refused/unreachable in a way reported as closed.
- **Filtered:** connection times out or is otherwise blocked/dropped (common with firewalls/filters).

This is the same fundamental approach as a "connect scan" (e.g. Nmap `-sT` conceptually), but implemented simply in Python.

### 2. Service identification
For open ports, PortScope tries to map the port number to a common service name via `socket.getservbyport()` (best-effort; not definitive).

### 3. Banner grabbing (basic)
With `--banner`, PortScope attempts a minimal, non-invasive banner read on open ports:
- Reads any initial data sent by the service, or
- Sends a simple `HEAD / HTTP/1.0` probe for common HTTP ports to elicit a response header.

Banners can reveal service/version hints but may be absent, misleading, or truncated.

### 4. Concurrency
Scanning ports sequentially is slow. PortScope uses `concurrent.futures.ThreadPoolExecutor` to scan multiple ports in parallel, improving speed while keeping the implementation straightforward. Thread count and timeout should be tuned to avoid inaccurate results or unnecessary network load.

### 5. Reporting
Results are collected, sorted by port, summarized (open/closed/filtered counts), printed to the terminal, and optionally exported as structured JSON for later review or tooling.

## Limitations and notes
- **TCP only:** no UDP scanning, no SYN/half-open scanning, and no OS fingerprinting.
- **Accuracy depends on network conditions:** packet loss, rate limiting, IDS/IPS, and firewalls can cause false filtered/open interpretations.
- **Privileges:** connect scans do not require raw-socket privileges, but your environment/network policies still apply.
- **Ethics/legal:** use only with explicit authorization. Unauthorized scanning can be illegal and harmful.

## Possible extensions (ideas)
- UDP scanning support (with careful timeout/retry handling)
- Rate limiting and randomized port order
- Configurable probe payloads per port/service
- CSV/HTML report output
- Async I/O (`asyncio`) implementation for comparison
- Basic CIDR/host-list input for authorized scope files
