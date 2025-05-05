# 🛠️ Advanced Network Access Scanner - Usage Guide

This guide explains how to use the **Advanced Network Access Scanner**, a powerful Python-based CLI tool designed to:

* Enumerate common services
* Identify risky services and access paths
* Highlight lateral movement opportunities
* Analyze remote execution potential

---

## 📦 Requirements

* Python 3.6+
* Works on Windows/Linux/Mac
* No third-party dependencies required

---

## 🚀 Basic Usage

```bash
python3 scanner.py 192.168.1.0/24
```

Scans a full `/24` subnet for open ports defined in the tool (50+ common services).

---

## 🎛️ Arguments

| Argument                | Description                                                       |
| ----------------------- | ----------------------------------------------------------------- |
| `subnet`                | IP or CIDR to scan (e.g. `192.168.1.0/24` or `192.168.1.75`)      |
| `-o` `--output <file>`  | Save results to a file in CSV format                              |
| `-b` `--banners`        | Try to grab service banners (e.g., HTTP headers, SSH versions)    |
| `-v` `--verbose`        | Show extended output and analysis                                 |
| `-q` `--quiet`          | Suppress output except final results                              |
| `-t` `--timeout`        | Set custom socket timeout (default `0.5` seconds)                 |
| `-w` `--workers`        | Set the number of concurrent threads (default: `100`)             |
| `-a` `--advanced`       | Run post-scan advanced analysis (pivot path, attack method, etc.) |
| `-i` `--target-ip <ip>` | Run advanced analysis only on one IP                              |

---

## 🔍 Example Scans

### 1. **Scan your local subnet with banners**

```bash
python3 scanner.py 192.168.1.0/24 -b
```

### 2. **Save results to file and get verbose output**

```bash
python3 scanner.py 10.0.0.0/24 -v -o results.csv
```

### 3. **Scan a single IP and run advanced analysis on it**

```bash
python3 scanner.py 192.168.1.10 -a -i 192.168.1.10
```

---

## 📊 Output

* Color-coded services by risk level
* Grouped by service category and access type (FILE\_SHARING, EXEC, ADMIN)
* Summary of exploitable services and recommendations
* Optional: banners and pivot path analysis

---

## 🧠 Pro Tips

* Use `--banners` to fingerprint services and detect versions.
* Use `--advanced` for threat emulation and lateral movement mapping.
* Pipe output to tools or SIEM via `--output`.

---

## 🧩 Ideal For:

* Red Team Ops
* Penetration Testing
* Network Recon
* SOC Analysts
* Security Engineers

---

## 🧨 Default Port Coverage Includes:

* SMB, NetBIOS, FTP, SSH, RDP, VNC, Telnet
* Docker API, Kubernetes, Jenkins, Elasticsearch
* PostgreSQL, MySQL, MSSQL, MongoDB, Redis
* HTTP, HTTPS, SNMP, LDAP, Kerberos, DNS

Use responsibly. Pair with custom payloads or access exploits to map reachable services.
