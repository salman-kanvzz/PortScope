# PortScope Sample Output

## Command
```bash
python3 portscope.py 127.0.0.1 -p 22,80,443,8000 -b --no-banner-art
```

## Example terminal output
```text
[*] Resolving target: 127.0.0.1

Target:      127.0.0.1 (127.0.0.1)
Scanned:     4 ports
Open:        1 | Closed: 3 | Filtered: 0
------------------------------------------------------------------------
PORT     STATE      SERVICE         BANNER
------------------------------------------------------------------------
22       open       ssh             SSH-2.0-OpenSSH_9.6p1 Debian-1
------------------------------------------------------------------------
[+] JSON report saved to: (only when -o is used)

Disclaimer: Use only on systems you own or have explicit permission to test.
```

## Example JSON excerpt (`-o results.json`)
```json
{
  "tool": { "name": "PortScope", "version": "1.0.0" },
  "timestamp_utc": "2026-11-17T00:00:00+00:00",
  "summary": {
    "target": "127.0.0.1",
    "resolved_ip": "127.0.0.1",
    "scanned_ports": 4,
    "open": 1,
    "closed": 3,
    "filtered": 0
  },
  "open_results": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_9.6p1 Debian-1"
    }
  ]
}
```

*Note: Actual results vary by host, services running, firewall rules, and environment.* 
