import asyncio
import socket
import argparse
import sys
import time
import json
from datetime import datetime

# Common ports dictionary mapping port numbers to service names and descriptions
COMMON_PORTS = {
    20: ("FTP-DATA", "File Transfer Protocol (Data)"),
    21: ("FTP", "File Transfer Protocol (Control)"),
    22: ("SSH", "Secure Shell"),
    23: ("TELNET", "Telnet (Unencrypted text communications)"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    67: ("DHCP", "Dynamic Host Configuration Protocol (Server)"),
    68: ("DHCP", "Dynamic Host Configuration Protocol (Client)"),
    69: ("TFTP", "Trivial File Transfer Protocol"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    88: ("KERBEROS", "Kerberos authentication system"),
    110: ("POP3", "Post Office Protocol v3"),
    111: ("RPCBIND", "ONC RPC Bind / Portmapper"),
    123: ("NTP", "Network Time Protocol"),
    135: ("MSRPC", "Microsoft RPC Endpoint Mapper"),
    137: ("NETBIOS-NS", "NetBIOS Name Service"),
    138: ("NETBIOS-DGM", "NetBIOS Datagram Service"),
    139: ("NETBIOS-SSN", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    161: ("SNMP", "Simple Network Management Protocol"),
    389: ("LDAP", "Lightweight Directory Access Protocol"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    445: ("MICROSOFT-DS", "SMB over TCP (Microsoft Directory Services)"),
    465: ("SMTPS", "SMTP over SSL/TLS"),
    514: ("SYSLOG", "Syslog protocol"),
    587: ("SMTP-SUBMIT", "SMTP mail submission"),
    636: ("LDAPS", "LDAP over SSL/TLS"),
    993: ("IMAPS", "IMAP over SSL/TLS"),
    995: ("POP3S", "POP3 over SSL/TLS"),
    1433: ("MSSQL", "Microsoft SQL Server database engine"),
    1521: ("ORACLE", "Oracle database listener"),
    2049: ("NFS", "Network File System"),
    3306: ("MYSQL", "MySQL database system"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5000: ("UPNP/FLASK", "Universal Plug and Play / Flask Dev Server"),
    5432: ("POSTGRESQL", "PostgreSQL database system"),
    5900: ("VNC", "Virtual Network Computing (Remote desktop)"),
    6379: ("REDIS", "Redis key-value store"),
    8000: ("HTTP-ALT", "Alternative HTTP port (often development web servers)"),
    8080: ("HTTP-PROXY", "HTTP Proxy / Apache Tomcat"),
    8443: ("HTTPS-ALT", "Alternative HTTPS port"),
    9000: ("SONARQUBE/PHP-FPM", "SonarQube / PHP-FPM default port"),
    27017: ("MONGODB", "MongoDB database server")
}

# ANSI escape codes for styling
class Style:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Fallback style if standard stream is not a TTY or OS doesn't support ANSI
def disable_styling():
    Style.CYAN = ''
    Style.GREEN = ''
    Style.YELLOW = ''
    Style.RED = ''
    Style.BLUE = ''
    Style.BOLD = ''
    Style.UNDERLINE = ''
    Style.RESET = ''

class PortScanner:
    def __init__(self, target, ports, concurrency=100, timeout=1.0, verbose=False):
        self.target = target
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.verbose = verbose
        self.target_ip = None
        self.open_ports = []
        self.semaphore = asyncio.Semaphore(concurrency)
        self.scanned_count = 0

    def resolve_target(self):
        """Resolves target hostname to IP address."""
        print(f"{Style.CYAN}[*] Resolving host: {Style.BOLD}{self.target}{Style.RESET}...")
        try:
            self.target_ip = socket.gethostbyname(self.target)
            print(f"{Style.GREEN}[+] Host resolved to: {Style.BOLD}{self.target_ip}{Style.RESET}")
            return True
        except socket.gaierror as e:
            print(f"{Style.RED}[-] Error resolving host '{self.target}': {e}{Style.RESET}")
            return False

    async def grab_banner(self, reader, writer):
        """Attempts to perform a banner grab on an open port."""
        try:
            # 1. Try to read a greeting message (e.g. SSH, FTP greets upon connection)
            banner = await asyncio.wait_for(reader.read(1024), timeout=0.8)
            if banner:
                return banner.decode(errors='ignore').strip()
        except asyncio.TimeoutError:
            # 2. If no greeting, try to send a basic probe (HTTP request or just carriage return)
            try:
                writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                if banner:
                    # Return the first line of the HTTP response header
                    first_line = banner.decode(errors='ignore').split('\r\n')[0].strip()
                    if first_line:
                        return first_line
            except Exception:
                pass
        except Exception:
            pass
        return None

    async def scan_port(self, port):
        """Scans a single port and updates internal state."""
        async with self.semaphore:
            try:
                # Attempt standard TCP handshake
                conn = asyncio.open_connection(self.target_ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # Connection succeeded -> Port is open
                service_name, desc = COMMON_PORTS.get(port, ("UNKNOWN", "Unknown Service"))
                
                # Attempt banner grabbing
                banner = await self.grab_banner(reader, writer)
                
                # Close connection
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                result = {
                    "port": port,
                    "state": "OPEN",
                    "service": service_name,
                    "description": desc,
                    "banner": banner
                }
                
                self.open_ports.append(result)
                
                # Display finding immediately
                banner_str = f" | Banner: {Style.CYAN}{banner}{Style.RESET}" if banner else ""
                print(f"{Style.GREEN}[+] Port {port:<5} ({service_name}): OPEN{banner_str}{Style.RESET}")
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Connection failed -> Port is closed/filtered
                if self.verbose:
                    print(f"{Style.RED}[-] Port {port:<5}: CLOSED/FILTERED{Style.RESET}")
            finally:
                self.scanned_count += 1
                # Periodically display progress in verbose mode or every 10%
                total_ports = len(self.ports)
                if total_ports >= 10 and self.scanned_count % (total_ports // 10) == 0:
                    percent = int((self.scanned_count / total_ports) * 100)
                    print(f"{Style.BLUE}[i] Progress: {percent}% completed ({self.scanned_count}/{total_ports} ports checked)...{Style.RESET}")

    async def run(self):
        """Orchestrates the asynchronous scanning process."""
        if not self.resolve_target():
            return False

        print(f"\n{Style.CYAN}Starting scan...{Style.RESET}")
        print(f"Target: {Style.BOLD}{self.target_ip}{Style.RESET}")
        print(f"Total ports to scan: {Style.BOLD}{len(self.ports)}{Style.RESET}")
        print(f"Concurrency level: {Style.BOLD}{self.concurrency}{Style.RESET}")
        print(f"Timeout duration: {Style.BOLD}{self.timeout}s{Style.RESET}\n")

        start_time = time.time()
        
        # Create asynchronous tasks for all ports
        tasks = [self.scan_port(port) for port in self.ports]
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Sort findings by port number
        self.open_ports.sort(key=lambda x: x["port"])
        
        # Print Scan Summary
        print(f"\n{Style.BOLD}{Style.CYAN}================= Scan Report Summary ================={Style.RESET}")
        print(f"Scan duration      : {duration:.2f} seconds")
        print(f"Total ports scanned: {len(self.ports)}")
        print(f"Open ports found   : {len(self.open_ports)}")
        print(f"{Style.BOLD}{Style.CYAN}======================================================={Style.RESET}\n")
        
        if self.open_ports:
            print(f"{Style.BOLD}{Style.GREEN}Open Ports Details:{Style.RESET}")
            print(f"{Style.UNDERLINE}{'PORT':<8} {'SERVICE':<15} {'STATE':<10} {'BANNER / DESCRIPTION':<40}{Style.RESET}")
            for item in self.open_ports:
                banner_or_desc = item["banner"] if item["banner"] else item["description"]
                # Truncate long descriptions / banners
                if len(banner_or_desc) > 50:
                    banner_or_desc = banner_or_desc[:47] + "..."
                print(f"{item['port']:<8} {item['service']:<15} {item['state']:<10} {banner_or_desc:<40}")
            print()
        else:
            print(f"{Style.YELLOW}[!] No open ports were found.{Style.RESET}\n")
            
        return True

def parse_ports(ports_arg):
    """Parses port argument into a list of integers."""
    ports = set()
    
    if ports_arg.lower() == 'common':
        return sorted(list(COMMON_PORTS.keys()))
    
    if ports_arg.lower() == 'all':
        return list(range(1, 65536))
        
    for part in ports_arg.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: '{part}'. Ports must be between 1 and 65535.")
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError
                ports.add(port)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: '{part}'. Ports must be between 1 and 65535.")
                
    return sorted(list(ports))

def save_to_file(filepath, format_type, target, resolved_ip, open_ports, scan_time):
    """Saves scan results to a file in TXT or JSON format."""
    try:
        report_data = {
            "target": target,
            "resolved_ip": resolved_ip,
            "scan_timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": round(scan_time, 2),
            "total_open_ports": len(open_ports),
            "open_ports": open_ports
        }
        
        if format_type.lower() == 'json' or filepath.endswith('.json'):
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=4)
        else:
            # Default to text format
            with open(filepath, 'w') as f:
                f.write("=====================================================\n")
                f.write("             PORT SCANNER REPORT\n")
                f.write("=====================================================\n")
                f.write(f"Target Host      : {target}\n")
                f.write(f"Resolved IP      : {resolved_ip}\n")
                f.write(f"Scan Timestamp   : {report_data['scan_timestamp']}\n")
                f.write(f"Scan Duration    : {report_data['scan_duration_seconds']} seconds\n")
                f.write(f"Open Ports Found : {report_data['total_open_ports']}\n")
                f.write("-----------------------------------------------------\n\n")
                
                if open_ports:
                    f.write(f"{'PORT':<8} {'SERVICE':<15} {'STATE':<10} {'BANNER / DESCRIPTION':<50}\n")
                    f.write("-" * 85 + "\n")
                    for p in open_ports:
                        detail = p["banner"] if p["banner"] else p["description"]
                        f.write(f"{p['port']:<8} {p['service']:<15} {p['state']:<10} {detail:<50}\n")
                else:
                    f.write("No open ports found.\n")
                    
        print(f"{Style.GREEN}[+] Report successfully saved to: {Style.BOLD}{filepath}{Style.RESET}")
    except Exception as e:
        print(f"{Style.RED}[-] Error saving report to file: {e}{Style.RESET}")

def main():
    # Attempt to enable virtual terminal processing on Windows for ANSI styling
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            # Fall back to no styles if failed
            disable_styling()

    parser = argparse.ArgumentParser(
        description="High-Performance Asynchronous Python Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t localhost -p common
  python port_scanner.py -t 192.168.1.1 -p 1-1000 -c 200
  python port_scanner.py -t google.com -p 80,443,8080 --timeout 1.5
  python port_scanner.py -t localhost -p 22,80,443 -o results.json
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target host (domain or IP address) to scan")
    parser.add_argument("-p", "--ports", default="common", 
                        help="Ports to scan. Options: 'common' (default list), 'all' (1-65535), specific range (e.g. '1-1000'), or comma-separated list (e.g. '22,80,443')")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Number of concurrent connection workers (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose outputs (displays closed ports)")
    parser.add_argument("-o", "--output", help="Filepath to write results report")
    parser.add_argument("-f", "--format", choices=['txt', 'json'], default='txt', help="Format of the output report file (default: txt)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored console outputs")

    args = parser.parse_args()

    if args.no_color:
        disable_styling()

    # ASCII Art Banner
    print(fr"""{Style.CYAN}{Style.BOLD}
   ___               _     ___                                      
  / _ \___  _ __ ___| |_  / __\ ___ __ _ _ __  _ __   ___ _ __ 
 / /_)/ _ \| '__/ __| __|/ _\  / __/ _` | '_ \| '_ \ / _ \ '__|
/ ___/ (_) | |  \__ \ |_/ /   | (_| (_| | | | | | | |  __/ |   
\/    \___/|_|  |___/\__\/\_/  \___\__,_|_| |_|_| |_|\___|_|   
                                                               
       -- Asynchronous TCP Scanner in Python --
{Style.RESET}""")

    try:
        ports_list = parse_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        print(f"{Style.RED}[-] Argument Error: {e}{Style.RESET}")
        sys.exit(1)

    scanner = PortScanner(
        target=args.target,
        ports=ports_list,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose
    )

    start_time = time.time()
    try:
        success = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(f"\n{Style.RED}[!] Scan interrupted by user. Exiting...{Style.RESET}")
        sys.exit(1)
        
    duration = time.time() - start_time

    if success and args.output:
        save_to_file(
            filepath=args.output,
            format_type=args.format,
            target=args.target,
            resolved_ip=scanner.target_ip,
            open_ports=scanner.open_ports,
            scan_time=duration
        )

if __name__ == "__main__":
    main()
