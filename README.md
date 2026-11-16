# PortScope

**PortScope** is a lightweight, educational **TCP port scanner and banner grabber** written in Python. It helps demonstrate core offensive security and network enumeration concepts—socket connections, port states, service identification, concurrency, and structured reporting—in a small, easy-to-understand codebase.

> **Authorized use only.** Scan only systems you own or have explicit permission to test.

## Features
- TCP connect scanning for a target host/IP
- Flexible port selection: single ports, lists, ranges, or mixed (e.g. `22,80,443`, `1-1024`, `22,80,100-110`)
- Port state detection: **open**, **closed**, **filtered** (timeout/blocked)
- Basic service name lookup (common TCP services)
- Optional basic banner grabbing on open ports (`--banner`)
- Multithreaded scanning for speed (`--threads`)
- Terminal summary and optional JSON report export (`--output`)
- Standard library only (no third-party dependencies)

## Project structure
```text
PortScope/
├── portscope.py        # Main CLI tool (scanner + banner grabber)
├── README.md           # Project documentation
├── LICENSE             # MIT License
├── .gitignore          # Git ignore rules
├── requirements.txt    # Dependencies (stdlib-only note)
├── docs/
│   └── overview.md     # How it works and limitations
└── examples/
    └── sample_output.md# Example usage/output
```

## Requirements
- Python 3.8+ (tested with Python 3.x)
- Network access to **authorized** targets
- No external Python packages required

## Installation
```bash
git clone <your-repo-url>
cd PortScope
python3 --version
```

(Optional, for isolation)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
```

## Usage
```bash
# Show help
python3 portscope.py --help

# Scan common ports (default 1-1024) on an authorized target
python3 portscope.py 127.0.0.1

# Scan specific ports with banner grabbing
python3 portscope.py 127.0.0.1 -p 22,80,443,8080 --banner

# Scan a range with custom timeout/threads and save JSON
python3 portscope.py scanme.nmap.org -p 1-200 -t 0.7 --threads 50 -b -o results.json

# Show closed/filtered ports too
python3 portscope.py 127.0.0.1 -p 20-100 --show-all
```

### CLI options
| Option | Description |
|---|---|
| `target` | Target hostname or IP (authorized targets only) |
| `-p, --ports` | Ports/ranges/list (default: `1-1024`) |
| `-t, --timeout` | Socket timeout in seconds (default: `0.5`) |
| `--threads` | Worker threads (default: `100`) |
| `-b, --banner` | Attempt basic banner grabbing on open ports |
| `--show-all` | Include closed/filtered ports in terminal output |
| `-o, --output` | Write full JSON results to file |
| `--no-banner-art` | Suppress ASCII banner |
| `--version` | Show version |

## Example output
```text
Target:      127.0.0.1 (127.0.0.1)
Scanned:     1024 ports
Open:        1 | Closed: 1023 | Filtered: 0
------------------------------------------------------------------------
PORT     STATE      SERVICE         BANNER
------------------------------------------------------------------------
22       open       ssh             SSH-2.0-OpenSSH_...
------------------------------------------------------------------------
```
(Actual results depend on the target and environment.)

## How it works (high level)
1. Resolves the target hostname to an IP address.
2. Parses the requested port set (ranges/lists).
3. Uses TCP `connect_ex()` attempts per port with a timeout:
   - successful connect → **open**
   - timeout → **filtered** (or dropped/blocked)
   - refused/unreachable error → typically **closed/filtered** depending on response
4. Optionally reads an initial banner (or sends a minimal probe for common HTTP ports).
5. Aggregates results concurrently with a thread pool and outputs a summary (+ optional JSON).

See [`docs/overview.md`](docs/overview.md) for more detail and limitations.

## Limitations
- **TCP connect scan only** (no SYN/UDP/stealth scanning; those require raw sockets/privileges and different tooling).
- Port state inference is best-effort; firewalls/IDS and network conditions can affect accuracy.
- Banner grabbing is basic and may not identify all services/versions.
- High thread counts or low timeouts can cause missed results or network noise—tune responsibly.
- Not a replacement for professional tools (e.g. Nmap) in full assessments.

## Ethical and legal disclaimer
This project is for **educational purposes** and **authorized security testing** only. Do not scan networks, hosts, or services without explicit permission from the owner. Unauthorized scanning may be illegal or violate policies/terms of service. The author assumes no liability for misuse.

## License
MIT License. See [LICENSE](LICENSE).