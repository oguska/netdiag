# NetDiag

NetDiag is an advanced PowerShell automation framework designed for network diagnostics, hop-by-hop Jitter analysis, native C#-powered concurrent load testing, and comprehensive system hardware inventory collection. It correlates network metrics with application response times to pinpoint bottlenecks instantly.

## Features

* **Multi-Resolver DNS & WAF Detection:** Local vs. public DNS (8.8.8.8) consistency checks, Reverse DNS (PTR) resolution, and CDN/Reverse Proxy signature detection.
* **ICMP Ping & Path MTU Discovery:** Baseline RTT latency metrics and safe maximum MTU determination with the Don't Fragment flag.
* **Service Port Matrix:** TCP socket checks for critical ports (HTTP, HTTPS, SSH, RDP, DNS, SMB) with optional layer-7 banner verification.
* **Hop-by-Hop MTR & Jitter Analysis:** Traceroute tracking combined with multi-packet standard deviation (Jitter) and packet loss calculation per hop.
* **Native C# JMeter-Style Load Testing:** High-performance concurrent virtual user (threads) execution inside PowerShell, tracking Throughput (RPS), percentiles (p50/p90/p95), error rates, and response text assertions.
* **System Hardware Inventory:** Automatic retrieval of logged-on user identity, hostname, OS version, real-time CPU load, RAM utilization, and logical disk capacities.
* **Cross-Correlation Root-Cause Engine:** Automatically compares network Jitter against application load test latency to determine whether performance issues originate from the network infrastructure or the server/application tier.
* **HTML Dashboard Reporting:** Generates a structured, enterprise-ready HTML report complete with summary metrics, status badges, and advisory blocks.
* **Commit Hash-Based Auto-Update:** Built-in self-update mechanism that checks the GitHub main branch commit hash and safely updates the script on the fly.

## Prerequisites & Requirements

* **OS:** Windows 10 / 11 or Windows Server.
* **PowerShell:** PowerShell 5.1 or PowerShell 7+.
* **Privileges:** Running PowerShell as **Administrator** is recommended to ensure proper CIM/WMI hardware queries and network socket operations.

## Usage

Run the script interactively by launching it without arguments:

```powershell
.\netdiag.ps1
