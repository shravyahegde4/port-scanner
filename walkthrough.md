# Walkthrough - Asynchronous Python Port Scanner

We have built a fast, concurrent, and highly customizable TCP Port Scanner in Python using asynchronous sockets (`asyncio`). It has no external dependencies and works natively on Windows, macOS, and Linux.

## Changes Made

### Port Scanner Component
- **[port_scanner.py](file:///c:/Users/Hegde/Downloads/Projects/port%20scanner/port_scanner.py)**: The main script implementing the asynchronous scan logic, service dictionary lookup, banner grabbing, command-line arguments parsing, and report writing.
- **Service definitions**: Included details for over 40 common ports (FTP, SSH, HTTP, MSSQL, MySQL, RDP, etc.).
- **Encoding compatibility**: Designed without emoji characters or custom checkmarks to avoid `UnicodeEncodeError` in standard Windows terminal configurations.

---

## Validation Results

### 1. Help Menu Verification
We validated the argument parser and help outputs:
```powershell
python port_scanner.py --help
```
Output:
```
usage: port_scanner.py [-h] -t TARGET [-p PORTS] [-c CONCURRENCY]
                       [--timeout TIMEOUT] [-v] [-o OUTPUT] [-f {txt,json}]
                       [--no-color]

High-Performance Asynchronous Python Port Scanner

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target host (domain or IP address) to scan
  -p, --ports PORTS     Ports to scan. Options: 'common' (default list), 'all'
                        (1-65535), specific range (e.g. '1-1000'), or comma-
                        separated list (e.g. '22,80,443')
  -c, --concurrency CONCURRENCY
                        Number of concurrent connection workers (default: 100)
  --timeout TIMEOUT     Connection timeout in seconds (default: 1.0)
  -v, --verbose         Enable verbose outputs (displays closed ports)
  -o, --output OUTPUT   Filepath to write results report
  -f, --format {txt,json}
                        Format of the output report file (default: txt)
  --no-color            Disable colored console outputs

Examples:
  python port_scanner.py -t localhost -p common
  python port_scanner.py -t 192.168.1.1 -p 1-1000 -c 200
  python port_scanner.py -t google.com -p 80,443,8080 --timeout 1.5
  python port_scanner.py -t localhost -p 22,80,443 -o results.json
```

---

### 2. Scanning Localhost
We scanned localhost for common ports:
```powershell
python port_scanner.py -t localhost -p common
```
Output:
```
   ___               _     ___                                      
  / _ \___  _ __ ___| |_  / __\ ___ __ _ _ __  _ __   ___ _ __ 
 / /_)/ _ \| '__/ __| __|/ _\  / __/ _` | '_ \| '_ \ / _ \ '__|
/ ___/ (_) | |  \__ \ |_/ /   | (_| (_| | | | | | | |  __/ |   
\/    \___/|_|  |___/\__\/\_/  \___\__,_|_| |_|_| |_|\___|_|   
                                                               
       -- Asynchronous TCP Scanner in Python --

[*] Resolving host: localhost...
[+] Host resolved to: 127.0.0.1

Starting scan...
Target: 127.0.0.1
Total ports to scan: 43
Concurrency level: 100
Timeout duration: 1.0s

[+] Port 445   (MICROSOFT-DS): OPEN
[i] Progress: 9% completed (4/43 ports checked)...
[i] Progress: 18% completed (8/43 ports checked)...
...
[+] Port 135   (MSRPC): OPEN

================= Scan Report Summary =================
Scan duration      : 1.62 seconds
Total ports scanned: 43
Open ports found   : 2
=======================================================

Open Ports Details:
PORT     SERVICE         STATE      BANNER / DESCRIPTION                    
135      MSRPC           OPEN       Microsoft RPC Endpoint Mapper           
445      MICROSOFT-DS    OPEN       SMB over TCP (Microsoft Directory Services)
```

---

### 3. Report Exporting Verification
We verified saving reports to JSON and TXT format:
```powershell
python port_scanner.py -t localhost -p 135,445 -o scan_results.json -f json
```

Generated **[scan_results.json](file:///c:/Users/Hegde/Downloads/Projects/port%20scanner/scan_results.json)** output:
```json
{
    "target": "localhost",
    "resolved_ip": "127.0.0.1",
    "scan_timestamp": "2026-06-15T23:27:19.009711",
    "scan_duration_seconds": 1.64,
    "total_open_ports": 2,
    "open_ports": [
        {
            "port": 135,
            "state": "OPEN",
            "service": "MSRPC",
            "description": "Microsoft RPC Endpoint Mapper",
            "banner": null
        },
        {
            "port": 445,
            "state": "OPEN",
            "service": "MICROSOFT-DS",
            "description": "SMB over TCP (Microsoft Directory Services)",
            "banner": null
        }
    ]
}
```

And the text report **[scan_results.txt](file:///c:/Users/Hegde/Downloads/Projects/port%20scanner/scan_results.txt)** formatting matches perfectly.
