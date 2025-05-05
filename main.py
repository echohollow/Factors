import socket
import sys
import concurrent.futures
import ipaddress
import time
import argparse
import os
from datetime import datetime
import struct

# Define color codes for terminal output
GREEN = "\033[92m"    # Green for open ports
RED = "\033[91m"      # Red for closed ports
YELLOW = "\033[93m"   # Yellow for warnings/medium risk
BLUE = "\033[94m"     # Blue for headers
CYAN = "\033[96m"     # Cyan for information
MAGENTA = "\033[95m"  # Magenta for high value targets
RESET = "\033[0m"     # Reset color
BOLD = "\033[1m"      # Bold text

# Enhanced common services with access types and attack methods
COMMON_SERVICES = {
    # File Sharing Services - Primary vectors for lateral movement
    "SMB": {
        "ports": [445], 
        "risk": "HIGH", 
        "description": "Windows file sharing, most abused lateral path",
        "access_type": "FILE_SHARING|EXEC",
        "attack_methods": "EternalBlue, SMBGhost, PsExec, Relay"
    },
    "NetBIOS": {
        "ports": [139, 137, 138], 
        "risk": "HIGH", 
        "description": "Legacy file/printer sharing",
        "access_type": "FILE_SHARING|EXEC",
        "attack_methods": "NTLM Relay, Session Hijacking"
    },
    "NFS": {
        "ports": [2049], 
        "risk": "HIGH", 
        "description": "Network File System (Linux)",
        "access_type": "FILE_SHARING",
        "attack_methods": "NFS Export Misconfig, UID Mapping"
    },
    "FTP": {
        "ports": [21], 
        "risk": "HIGH", 
        "description": "File transfer, often unauthenticated",
        "access_type": "FILE_SHARING",
        "attack_methods": "Anon Access, Brute Force, MitM"
    },
    "WebDAV": {
        "ports": [80, 443], 
        "risk": "MEDIUM", 
        "description": "Web file sharing & collaboration",
        "access_type": "FILE_SHARING",
        "attack_methods": "Auth Bypass, PUT Method"
    },
    "AFP": {
        "ports": [548], 
        "risk": "MEDIUM", 
        "description": "Apple Filing Protocol",
        "access_type": "FILE_SHARING",
        "attack_methods": "Brute Force, CVE-2018-1160"
    },
    
    # Remote Access Services - Command execution vectors
    "RPC/DCOM": {
        "ports": [135], 
        "risk": "HIGH", 
        "description": "Used for WMI, PowerShell Remoting",
        "access_type": "EXEC|ADMIN",
        "attack_methods": "DCOM Execution, PrintNightmare"
    },
    "WMI": {
        "ports": [135], 
        "risk": "HIGH", 
        "description": "Windows Management Instrumentation",
        "access_type": "EXEC|ADMIN",
        "attack_methods": "WMI Exec, Lateral Movement"
    },
    "RDP": {
        "ports": [3389], 
        "risk": "HIGH", 
        "description": "Remote Desktop Protocol",
        "access_type": "GUI|ADMIN",
        "attack_methods": "BlueKeep, Brute Force, MitM"
    },
    "SSH": {
        "ports": [22], 
        "risk": "MEDIUM", 
        "description": "Secure shell, used in *nix devices",
        "access_type": "EXEC|ADMIN",
        "attack_methods": "Brute Force, Key Theft"
    },
    "Telnet": {
        "ports": [23], 
        "risk": "CRITICAL", 
        "description": "Insecure shell, common on IoT",
        "access_type": "EXEC|ADMIN",
        "attack_methods": "Cleartext Sniffing, Brute Force"
    },
    "VNC": {
        "ports": [5900, 5901, 5902, 5903], 
        "risk": "HIGH", 
        "description": "Remote control interface",
        "access_type": "GUI|ADMIN",
        "attack_methods": "Auth Bypass, Brute Force"
    },
    "TeamViewer": {
        "ports": [5938], 
        "risk": "MEDIUM", 
        "description": "Remote support tool",
        "access_type": "GUI|ADMIN",
        "attack_methods": "CVE-2019-18988, Password Reuse"
    },
    "AnyDesk": {
        "ports": [7070], 
        "risk": "MEDIUM", 
        "description": "Remote support tool",
        "access_type": "GUI|ADMIN",
        "attack_methods": "Phishing, Social Engineering"
    },
    "Windows RA": {
        "ports": [49152, 49153, 49154], 
        "risk": "HIGH", 
        "description": "Windows Remote Assistance",
        "access_type": "GUI|ADMIN",
        "attack_methods": "Social Engineering, Session Hijack"
    },
    
    # Database Services - Data theft and command execution
    "MySQL": {
        "ports": [3306], 
        "risk": "HIGH", 
        "description": "Database server, often reused creds",
        "access_type": "DATA|EXEC",
        "attack_methods": "UDF Injection, Password Reuse"
    },
    "PostgreSQL": {
        "ports": [5432], 
        "risk": "HIGH", 
        "description": "Database server",
        "access_type": "DATA|EXEC",
        "attack_methods": "Trust Authentication, Extension Loading"
    },
    "MSSQL": {
        "ports": [1433, 1434], 
        "risk": "HIGH", 
        "description": "Microsoft SQL server",
        "access_type": "DATA|EXEC|ADMIN",
        "attack_methods": "xp_cmdshell, NTLM Relay, UNC Path Injection"
    },
    "Redis": {
        "ports": [6379], 
        "risk": "CRITICAL", 
        "description": "In-memory database, often no auth",
        "access_type": "DATA|EXEC",
        "attack_methods": "Unauth Access, Malicious Config"
    },
    "MongoDB": {
        "ports": [27017], 
        "risk": "HIGH", 
        "description": "NoSQL database, often no auth",
        "access_type": "DATA",
        "attack_methods": "NoAuth Default, JS Injection"
    },
    
    # Web Applications - Multiple attack vectors
    "HTTP": {
        "ports": [80, 8080], 
        "risk": "MEDIUM", 
        "description": "Web UI on devices (printers, routers)",
        "access_type": "WEB|UPLOAD",
        "attack_methods": "Default Creds, Upload Vulnerabilities"
    },
    "HTTPS": {
        "ports": [443, 8443], 
        "risk": "MEDIUM", 
        "description": "Secure web panels",
        "access_type": "WEB|UPLOAD",
        "attack_methods": "Default Creds, Outdated Software"
    },
    
    # Management Interfaces - Administrative access
    "IPMI": {
        "ports": [623], 
        "risk": "CRITICAL", 
        "description": "Out-of-band management, known vulns",
        "access_type": "ADMIN|HARDWARE",
        "attack_methods": "Cipher Zero, Default Creds, RAKP Auth Bypass"
    },
    "SNMP": {
        "ports": [161, 162], 
        "risk": "HIGH", 
        "description": "Network management, info leakage",
        "access_type": "INFO|CONFIG",
        "attack_methods": "Public Community Strings, Write Access"
    },
    
    # Container Services - Root-level access
    "Docker API": {
        "ports": [2375, 2376], 
        "risk": "CRITICAL", 
        "description": "Docker remote API, root equiv access",
        "access_type": "CONTAINER|ROOT",
        "attack_methods": "Unauth API, Host Filesystem Mount"
    },
    "Kubernetes": {
        "ports": [6443, 8080, 10250], 
        "risk": "CRITICAL", 
        "description": "Container orchestration",
        "access_type": "CONTAINER|ROOT",
        "attack_methods": "Unauth Kubelet API, Pod Creation"
    },
    
    # Directory Services - Authentication and user data
    "LDAP": {
        "ports": [389, 636], 
        "risk": "HIGH", 
        "description": "Directory services, often AD integration",
        "access_type": "AUTH|INFO",
        "attack_methods": "LDAP Injection, Null Bind"
    },
    "Kerberos": {
        "ports": [88], 
        "risk": "HIGH", 
        "description": "Authentication protocol for Windows domains",
        "access_type": "AUTH",
        "attack_methods": "AS-REP Roasting, Kerberoasting"
    },
    
    # Service Discovery - Network scanning facilitators
    "mDNS": {
        "ports": [5353], 
        "risk": "LOW", 
        "description": "Multicast DNS (device discovery)",
        "access_type": "INFO",
        "attack_methods": "Network Enumeration, DNS Spoofing"
    },
    "UPnP": {
        "ports": [1900], 
        "risk": "MEDIUM", 
        "description": "Auto-device discovery, often abused",
        "access_type": "INFO|CONFIG",
        "attack_methods": "SSDP Reflection, Port Mapping"
    },
    "LLMNR": {
        "ports": [5355], 
        "risk": "MEDIUM", 
        "description": "Name resolution fallback, can be poisoned",
        "access_type": "INFO",
        "attack_methods": "Poisoning, NTLM Capture"
    },
    
    # Other Important Services
    "DNS": {
        "ports": [53], 
        "risk": "MEDIUM", 
        "description": "Domain name resolution, tunneling risk",
        "access_type": "INFO|TUNNEL",
        "attack_methods": "DNS Tunneling, Cache Poisoning"
    },
    "DHCP": {
        "ports": [67, 68], 
        "risk": "MEDIUM", 
        "description": "Address assignment, rogue DHCP risk",
        "access_type": "NETWORK|MitM",
        "attack_methods": "Rogue DHCP, IP Assignment Control"
    },
    "Jenkins": {
        "ports": [8080, 50000], 
        "risk": "CRITICAL", 
        "description": "CI/CD, often default creds",
        "access_type": "EXEC|FILES",
        "attack_methods": "Script Console, Job Creation, Default Creds"
    },
    "Elasticsearch": {
        "ports": [9200, 9300], 
        "risk": "HIGH", 
        "description": "Search/analytics, often no auth",
        "access_type": "DATA",
        "attack_methods": "Unauth Access, RCE via Groovy"
    },
    "Printer": {
        "ports": [9100, 515, 631], 
        "risk": "MEDIUM", 
        "description": "Printer services, raw socket",
        "access_type": "PRINT|INFO",
        "attack_methods": "PRET, Printer Languages Abuse"
    },
}

# Define access type categories for reporting
ACCESS_TYPES = {
    "FILE_SHARING": "File Transfer Capability",
    "EXEC": "Command Execution",
    "ADMIN": "Administrative Access",
    "GUI": "Graphical Interface",
    "DATA": "Data Access/Theft",
    "WEB": "Web Interface",
    "UPLOAD": "File Upload Capability",
    "HARDWARE": "Hardware-Level Control",
    "INFO": "Information Disclosure",
    "CONFIG": "Configuration Access",
    "CONTAINER": "Container Access",
    "ROOT": "Root/System Access",
    "AUTH": "Authentication Services",
    "NETWORK": "Network Control",
    "MitM": "Man-in-the-Middle Position",
    "TUNNEL": "Data Tunneling",
    "PRINT": "Print Capabilities"
}

def check_port(ip, port, timeout=0.5):
    """Check if a specific port is open on a target IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # If result is 0, the port is open
    except (socket.error, socket.timeout, OSError):
        return False

def get_banner(ip, port, timeout=1):
    """Attempt to get service banner with customized probes for better results"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Service-specific probes
        if port == 22:
            # SSH typically sends banner immediately
            data = sock.recv(1024)
        elif port == 80 or port == 443 or port == 8080 or port == 8443:
            # HTTP/HTTPS request
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = sock.recv(1024)
        elif port == 21:
            # FTP typically sends welcome banner
            data = sock.recv(1024)
        elif port == 25 or port == 587 or port == 465:
            # SMTP typically sends banner
            data = sock.recv(1024)
            sock.send(b"EHLO test\r\n")
            data += sock.recv(1024)
        elif port == 445 or port == 139:
            # SMB protocol negotiation
            data = b"SMB Session - No Banner Sent"
        elif port == 3306:
            # MySQL handshake
            data = sock.recv(1024)
        elif port == 5432:
            # PostgreSQL handshake
            data = sock.recv(1024)
        elif port == 1433:
            # MSSQL handshake
            data = sock.recv(1024)
        elif port == 6379:
            # Redis INFO command
            sock.send(b"INFO\r\n")
            data = sock.recv(1024)
        elif port == 27017:
            # MongoDB ismaster command
            data = b"MongoDB - No Banner Test"
        else:
            # Generic approach for other services
            sock.send(b"\r\n")
            data = sock.recv(1024)
        
        sock.close()
        
        # Try to decode banner as text
        try:
            return data.decode('utf-8', errors='ignore').strip()
        except:
            return data.hex()
    except:
        return None

def scan_target(ip, ports_to_scan=None, get_banners=False, timeout=0.5):
    """Scan a single target for open ports"""
    if ports_to_scan is None:
        # Scan all services defined in COMMON_SERVICES
        ports_to_scan = []
        for service in COMMON_SERVICES.values():
            ports_to_scan.extend(service["ports"])
        ports_to_scan = list(set(ports_to_scan))  # Remove duplicates
    
    open_ports = {}
    for port in ports_to_scan:
        if check_port(ip, port, timeout):
            banner = None
            if get_banners:
                banner = get_banner(ip, port)
            open_ports[port] = banner
    
    return ip, open_ports

def get_service_info(port):
    """Get the service info for a specific port"""
    for service_name, service_info in COMMON_SERVICES.items():
        if port in service_info["ports"]:
            return service_name, service_info
    return "Unknown", {"risk": "UNKNOWN", "description": "Unknown service", "access_type": "UNKNOWN", "attack_methods": "Unknown"}

def print_ascii_art():
    """Print ASCII art banner for the tool"""
    ascii_art = """
    ███████╗ █████╗  ██████╗████████╗ ██████╗ ██████╗ ███████╗
    ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
    █████╗  ███████║██║        ██║   ██║   ██║██████╔╝███████╗
    ██╔══╝  ██╔══██║██║        ██║   ██║   ██║██╔══██╗╚════██║
    ██║     ██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║███████║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
    """
    print(f"{MAGENTA}{ascii_art}{RESET}")
    print(f"{BOLD}{BLUE}===== Advanced Network Access Scanner ====={RESET}")
    print(f"{CYAN}[*] Identifying attack paths and lateral movement options{RESET}\n")

def print_results(results, show_banners=False, verbosity=1):
    """Print scan results in a readable format with enhanced access information"""
    count_by_risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    hosts_with_open_ports = 0
    total_open_ports = 0
    access_types_found = {}
    
    # Count hosts with open ports and total open ports
    for ip, open_ports in results:
        if open_ports:
            hosts_with_open_ports += 1
            total_open_ports += len(open_ports)
            
            # Analyze access types
            for port in open_ports:
                service_name, service_info = get_service_info(port)
                
                # Track risk level counts
                count_by_risk[service_info["risk"]] = count_by_risk.get(service_info["risk"], 0) + 1
                
                # Track access types found
                if "access_type" in service_info:
                    access_types = service_info["access_type"].split("|")
                    for access_type in access_types:
                        if access_type in access_types_found:
                            access_types_found[access_type].add(ip)
                        else:
                            access_types_found[access_type] = {ip}
    
    print(f"\n{BLUE}=== Network Access Scan Results ==={RESET}")
    print(f"{BLUE}Discovered {hosts_with_open_ports} hosts with {total_open_ports} open services{RESET}")
    
    if verbosity >= 1:
        print(f"\n{BLUE}{'IP Address':<16} {'Service':<15} {'Port':<6} {'Risk':<10} {'Access Types':<30} {'Description'}{RESET}")
        print("-" * 120)
        
        for ip, open_ports in sorted(results):
            if not open_ports:
                continue  # Skip hosts with no open ports
            
            first_line = True
            for port, banner in sorted(open_ports.items()):
                service_name, service_info = get_service_info(port)
                risk_level = service_info["risk"]
                description = service_info["description"]
                
                # Color-code based on risk level
                if risk_level == "CRITICAL":
                    risk_color = f"{BOLD}{RED}"
                elif risk_level == "HIGH":
                    risk_color = RED
                elif risk_level == "MEDIUM":
                    risk_color = YELLOW
                elif risk_level == "LOW":
                    risk_color = GREEN
                else:
                    risk_color = RESET
                
                ip_display = ip if first_line else ""
                first_line = False
                
                # Format access types
                access_types = service_info.get("access_type", "UNKNOWN").split("|")
                access_display = ", ".join(access_types)
                
                print(f"{ip_display:<16} {service_name:<15} {port:<6} {risk_color}{risk_level:<10}{RESET} {access_display:<30} {description}")
                
                # Show banner if requested and available
                if show_banners and banner and verbosity >= 2:
                    # Truncate and format banner if it's too long
                    banner_display = banner[:100] + "..." if len(banner) > 100 else banner
                    print(f"{' '*16} {CYAN}└─ Banner: {banner_display}{RESET}")
    
    # Print access paths summary
    print(f"\n{BLUE}=== Network Access Paths ==={RESET}")
    for access_type, hosts in sorted(access_types_found.items(), key=lambda x: len(x[1]), reverse=True):
        if access_type in ACCESS_TYPES:
            access_desc = ACCESS_TYPES[access_type]
            host_count = len(hosts)
            
            if access_type in ["EXEC", "ADMIN", "ROOT", "FILE_SHARING"]:
                color = RED
            elif access_type in ["DATA", "CONFIG", "AUTH", "CONTAINER"]:
                color = YELLOW
            else:
                color = GREEN
                
            print(f"{color}{access_desc}: {host_count} hosts{RESET}")
            
            if verbosity >= 2 and host_count <= 5:  # Only show hosts if 5 or fewer
                hosts_str = ", ".join(sorted(list(hosts)))
                print(f"  └─ Hosts: {hosts_str}")
    
    # Print risk summary
    print(f"\n{BLUE}=== Risk Summary ==={RESET}")
    if count_by_risk["CRITICAL"] > 0:
        print(f"{BOLD}{RED}CRITICAL: {count_by_risk['CRITICAL']} services{RESET}")
    if count_by_risk["HIGH"] > 0:
        print(f"{RED}HIGH: {count_by_risk['HIGH']} services{RESET}")
    if count_by_risk["MEDIUM"] > 0:
        print(f"{YELLOW}MEDIUM: {count_by_risk['MEDIUM']} services{RESET}")
    if count_by_risk["LOW"] > 0:
        print(f"{GREEN}LOW: {count_by_risk['LOW']} services{RESET}")
    if count_by_risk["UNKNOWN"] > 0:
        print(f"UNKNOWN: {count_by_risk['UNKNOWN']} services")

def scan_network(subnet, max_workers=100, get_banners=False, verbosity=1, timeout=0.5):
    """Scan an entire subnet for open ports"""
    try:
        # Parse the subnet
        network = ipaddress.IPv4Network(subnet, strict=False)
        total_hosts = network.num_addresses
        
        # Exclude network and broadcast addresses for regular subnets
        scan_addresses = list(network.hosts()) if total_hosts > 2 else list(network)
        
        if verbosity >= 1:
            print(f"{BLUE}[+] Starting scan of {subnet} ({len(scan_addresses)} hosts){RESET}")
        start_time = time.time()
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(
                    scan_target, 
                    str(ip), 
                    None,  # scan all ports
                    get_banners,
                    timeout
                ): ip for ip in scan_addresses
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                if verbosity >= 1 and (completed % 10 == 0 or completed == len(scan_addresses)):
                    progress = (completed/len(scan_addresses))*100
                    print(f"{BLUE}[+] Progress: {completed}/{len(scan_addresses)} hosts scanned ({progress:.1f}%){RESET}", end="\r")
                
                result = future.result()
                if result[1]:  # If there are open ports
                    results.append(result)
        
        end_time = time.time()
        if verbosity >= 1:
            print(f"\n{BLUE}[+] Scan completed in {end_time - start_time:.2f} seconds{RESET}")
        
        return results
    
    except ValueError as e:
        print(f"{RED}[!] Invalid subnet format: {e}{RESET}")
        sys.exit(1)

def analyze_findings(results, verbosity=1):
    """Analyze scan results for attack paths and lateral movement opportunities"""
    if not results:
        print(f"{YELLOW}[!] No open ports found in the scanned network.{RESET}")
        return
    
    # Categorize hosts by access type
    access_categories = {
        "file_sharing_hosts": set(),
        "exec_hosts": set(),
        "admin_hosts": set(),
        "data_hosts": set(),
        "critical_services": {}
    }
    
    # Count services and track attack methods
    service_counts = {}
    attack_methods = {}
    
    for ip, open_ports in results:
        for port in open_ports:
            service_name, service_info = get_service_info(port)
            service_counts[service_name] = service_counts.get(service_name, 0) + 1
            
            # Track attack methods
            if "attack_methods" in service_info:
                for method in service_info["attack_methods"].split(", "):
                    if method in attack_methods:
                        attack_methods[method].append((ip, service_name))
                    else:
                        attack_methods[method] = [(ip, service_name)]
            
            # Track critical services
            if service_info["risk"] == "CRITICAL":
                if service_name in access_categories["critical_services"]:
                    access_categories["critical_services"][service_name].append(ip)
                else:
                    access_categories["critical_services"][service_name] = [ip]
            
            # Categorize by access type
            if "access_type" in service_info:
                access_types = service_info["access_type"].split("|")
                
                if "FILE_SHARING" in access_types:
                    access_categories["file_sharing_hosts"].add(ip)
                
                if "EXEC" in access_types:
                    access_categories["exec_hosts"].add(ip)
                
                if "ADMIN" in access_types or "ROOT" in access_types:
                    access_categories["admin_hosts"].add(ip)
                
                if "DATA" in access_types:
                    access_categories["data_hosts"].add(ip)
    
    # Print analysis
    print(f"\n{BLUE}=== Attack Path Analysis ==={RESET}")
    
    # Print lateral movement paths
    print(f"\n{BOLD}{RED}Lateral Movement Paths:{RESET}")
    if access_categories["file_sharing_hosts"]:
        print(f"{RED}- File Transfer/Sharing: {len(access_categories['file_sharing_hosts'])} hosts{RESET}")
    if access_categories["exec_hosts"]:
        print(f"{RED}- Command Execution: {len(access_categories['exec_hosts'])} hosts{RESET}")
    if access_categories["admin_hosts"]:
        print(f"{RED}- Administrative Access: {len(access_categories['admin_hosts'])} hosts{RESET}")
    
    # Print critical services
    if access_categories["critical_services"]:
        print(f"\n{BOLD}{RED}Critical Services:{RESET}")
        for service, ips in access_categories["critical_services"].items():
            ip_list = ", ".join(ips[:5])
            if len(ips) > 5:
                ip_list += f", ... and {len(ips)-5} more"
            print(f"{RED}- {service}: {len(ips)} hosts ({ip_list}){RESET}")
    
    # Print common attack methods
    print(f"\n{BLUE}Common Attack Methods Available:{RESET}")
    for method, targets in sorted(attack_methods.items(), key=lambda x: len(x[1]), reverse=True)[:8]:
        print(f"{YELLOW}- {method}: {len(targets)} targets{RESET}")
    
    # Print recommendations
    print(f"\n{BLUE}Recommendations:{RESET}")
    
    if access_categories["file_sharing_hosts"]:
        print(f"{YELLOW}- Restrict file sharing services (SMB, NFS, FTP) with firewall rules")
        print(f"- Monitor file transfers between hosts{RESET}")
    
    if access_categories["exec_hosts"]:
        print(f"{YELLOW}- Implement application allow listing on hosts with remote execution")
        print(f"- Monitor for unusual command execution patterns{RESET}")
    
    if access_categories["admin_hosts"]:
        print(f"{YELLOW}- Implement network segmentation for administrative interfaces")
        print(f"- Use jump servers/bastion hosts for administrative access{RESET}")
    
    if "Docker API" in service_counts or "Kubernetes" in service_counts:
        print(f"{YELLOW}- URGENT: Secure container orchestration services with authentication and TLS{RESET}")
    
    if "SMB" in service_counts or "NetBIOS" in service_counts:
        print(f"{YELLOW}- Disable SMBv1, enable SMB signing, and use host isolation{RESET}")
    
    print(f"{YELLOW}- Implement least privilege across the network{RESET}")

def save_to_file(results, filename):
    """Save scan results to a CSV file with enhanced details"""
    try:
        with open(filename, 'w') as f:
            # Write header
            f.write("Network Access Scan Results\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Write summary
            hosts_with_ports = sum(1 for ip, ports in results if ports)
            total_ports = sum(len(ports) for ip, ports in results)
            f.write(f"Found {hosts_with_ports} hosts with {total_ports} open ports\n\n")
            
            # Write detailed results
            f.write("IP Address,Port,Service,Risk Level,Access Types,Attack Methods,Description\n")
            
            for ip, open_ports in sorted(results):
                if not open_ports:
                    continue
                
                for port, banner in sorted(open_ports.items()):
                    service_name, service_info = get_service_info(port)
                    risk_level = service_info["risk"]
                    description = service_info["description"]
                    access_types = service_info.get("access_type", "UNKNOWN")
                    attack_methods = service_info.get("attack_methods", "Unknown")
                    
                    f.write(f"{ip},{port},{service_name},{risk_level},{access_types},\"{attack_methods}\",\"{description}\"\n")
            
            print(f"{GREEN}[+] Results saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving results to file: {e}{RESET}")

def advanced_scan_options(results, target_ip=None):
    """Perform an advanced scan on specific targets or services"""
    if not results:
        print(f"{YELLOW}[!] No scan results available to analyze.{RESET}")
        return
    
    if target_ip:
        # Focus on a specific IP
        target_results = [(ip, ports) for ip, ports in results if ip == target_ip]
        if not target_results:
            print(f"{RED}[!] Target IP {target_ip} not found in scan results.{RESET}")
            return
        
        ip, open_ports = target_results[0]
        print(f"\n{BLUE}=== Advanced Analysis for {ip} ==={RESET}")
        
        for port, banner in sorted(open_ports.items()):
            service_name, service_info = get_service_info(port)
            risk_level = service_info["risk"]
            
            # Determine risk color
            if risk_level == "CRITICAL":
                risk_color = f"{BOLD}{RED}"
            elif risk_level == "HIGH":
                risk_color = RED
            elif risk_level == "MEDIUM":
                risk_color = YELLOW
            else:
                risk_color = GREEN
                
            print(f"\n{risk_color}[+] {service_name} (Port {port}){RESET}")
            print(f"{CYAN}    Risk: {risk_level}{RESET}")
            print(f"{CYAN}    Description: {service_info['description']}{RESET}")
            
            if "access_type" in service_info:
                access_types = service_info["access_type"].split("|")
                print(f"{CYAN}    Access Types: {', '.join(access_types)}{RESET}")
            
            if "attack_methods" in service_info:
                attack_methods = service_info["attack_methods"].split(", ")
                print(f"{CYAN}    Attack Methods:{RESET}")
                for method in attack_methods:
                    print(f"{CYAN}      - {method}{RESET}")
            
            if banner:
                print(f"{CYAN}    Banner: {banner[:200]}{RESET}")
                
        print(f"\n{YELLOW}[!] Recommendations:{RESET}")
        print(f"{YELLOW}    - Consider implementing host-based firewall rules{RESET}")
        print(f"{YELLOW}    - Ensure services are running with minimal privileges{RESET}")
        print(f"{YELLOW}    - Verify if all services need to be accessible on the network{RESET}")
    else:
        # Analyze overall network for lateral movement paths
        file_sharing_hosts = []
        exec_hosts = []
        critical_hosts = []
        
        for ip, open_ports in results:
            max_risk = "LOW"
            has_file_sharing = False
            has_exec = False
            
            for port in open_ports:
                service_name, service_info = get_service_info(port)
                risk_level = service_info["risk"]
                
                # Update max risk
                if risk_level == "CRITICAL":
                    max_risk = "CRITICAL"
                elif risk_level == "HIGH" and max_risk != "CRITICAL":
                    max_risk = "HIGH"
                
                # Check for access types
                if "access_type" in service_info:
                    access_types = service_info["access_type"].split("|")
                    if "FILE_SHARING" in access_types:
                        has_file_sharing = True
                    if "EXEC" in access_types or "ADMIN" in access_types:
                        has_exec = True
            
            # Categorize host
            if max_risk in ["CRITICAL", "HIGH"]:
                critical_hosts.append(ip)
            if has_file_sharing:
                file_sharing_hosts.append(ip)
            if has_exec:
                exec_hosts.append(ip)
        
        # Print lateral movement analysis
        print(f"\n{BLUE}=== Network Lateral Movement Analysis ==={RESET}")
        print(f"\n{RED}[!] Critical/High Risk Hosts: {len(critical_hosts)}{RESET}")
        if critical_hosts:
            for ip in critical_hosts[:5]:  # Show top 5
                print(f"{RED}    - {ip}{RESET}")
            if len(critical_hosts) > 5:
                print(f"{RED}    - ... and {len(critical_hosts) - 5} more{RESET}")
        
        print(f"\n{YELLOW}[!] File Sharing Hosts: {len(file_sharing_hosts)}{RESET}")
        if file_sharing_hosts:
            for ip in file_sharing_hosts[:5]:  # Show top 5
                print(f"{YELLOW}    - {ip}{RESET}")
            if len(file_sharing_hosts) > 5:
                print(f"{YELLOW}    - ... and {len(file_sharing_hosts) - 5} more{RESET}")
        
        print(f"\n{YELLOW}[!] Command Execution Hosts: {len(exec_hosts)}{RESET}")
        if exec_hosts:
            for ip in exec_hosts[:5]:  # Show top 5
                print(f"{YELLOW}    - {ip}{RESET}")
            if len(exec_hosts) > 5:
                print(f"{YELLOW}    - ... and {len(exec_hosts) - 5} more{RESET}")
        
        # Check for potential pivot paths
        pivot_paths = []
        for source in file_sharing_hosts:
            for target in exec_hosts:
                if source != target:
                    pivot_paths.append((source, target))
        
        if pivot_paths:
            print(f"\n{RED}[!] Potential Pivot Paths: {len(pivot_paths)}{RESET}")
            for source, target in pivot_paths[:3]:  # Show top 3
                print(f"{RED}    - {source} → {target}{RESET}")
            if len(pivot_paths) > 3:
                print(f"{RED}    - ... and {len(pivot_paths) - 3} more potential paths{RESET}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Advanced Network Access Scanner")
    parser.add_argument("subnet", help="Subnet/IP to scan (e.g., 192.168.1.0/24 or 192.168.1.75)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-b", "--banners", action="store_true", help="Attempt to grab service banners")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout for port connection in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of worker threads (default: 100)")
    parser.add_argument("-a", "--advanced", action="store_true", help="Perform advanced analysis")
    parser.add_argument("-i", "--target-ip", help="Focus advanced analysis on specific IP")
    args = parser.parse_args()
    
    # Set verbosity level
    verbosity = 0 if args.quiet else (2 if args.verbose else 1)
    
    # Clear screen and print header
    if verbosity >= 1:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_ascii_art()
    
    # Run the scan
    results = scan_network(
        args.subnet,
        max_workers=args.workers,
        get_banners=args.banners,
        verbosity=verbosity,
        timeout=args.timeout
    )
    
    if not results:
        print(f"{RED}[!] No open ports found in scan.{RESET}")
        sys.exit(0)
    
    # Print the results
    print_results(results, show_banners=args.banners, verbosity=verbosity)
    
    # Analyze the findings
    analyze_findings(results, verbosity=verbosity)
    
    # Perform advanced analysis if requested
    if args.advanced:
        advanced_scan_options(results, args.target_ip)
    
    # Save results to file if requested
    if args.output:
        save_to_file(results, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(0)