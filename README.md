# NetDiag

NetDiag is an advanced PowerShell-based diagnostic framework for Windows. It combines DNS validation, ICMP and Path MTU testing, TCP port checks, hop-by-hop route analysis, endpoint jitter measurements, concurrent HTTP load testing, SSL inspection, system inventory, automated correlation, multilingual interactive output, and enterprise-ready HTML reporting in a single script.

NetDiag is designed to help distinguish among:

- DNS and name-resolution problems
- ICMP filtering and endpoint reachability issues
- TCP port and firewall behavior
- Route instability and intermediate-hop ICMP variation
- End-to-end latency, packet response loss, and jitter
- HTTP response-time and throughput problems
- Possible server or application bottlenecks

> **Important:** The built-in load test is a native C# HTTP load engine inspired by JMeter-style metrics. It does not launch Apache JMeter and should not be treated as a replacement for a full JMeter test plan.

---

## Features

### Multilingual interface and reports

- Automatically detects the Windows UI culture.
- Uses **Turkish** for `tr-TR` and other `tr-*` cultures.
- Uses **English** for `en-US` and other cultures by default.
- Supports manual language selection with `-Language tr`, `-Language en`, or `-Language Auto`.
- Localizes interactive questions, Yes/No input conventions, console messages, analysis results, table headings, metric names, and HTML reports.
- Uses `E/H` and `Evet/Hayır` in Turkish.
- Uses `Y/N` and `Yes/No` in English.

### Multi-resolver DNS analysis

- Local DNS resolution and IPv4 record discovery.
- Local DNS query-time measurement.
- Google Public DNS (`8.8.8.8`) comparison.
- Cloudflare DNS (`1.1.1.1`) comparison.
- Split-DNS and resolver mismatch warnings.
- Authoritative name-server discovery.
- Reverse DNS (`PTR`) lookup.
- CNAME and IP signature checks for common CDN or reverse-proxy patterns.

### ICMP and endpoint jitter analysis

- Configurable endpoint ICMP sample count.
- Minimum, average, median, p95, and maximum RTT.
- Sent, received, and response-loss metrics.
- Population standard deviation.
- Mean absolute RTT delta as endpoint mean jitter.
- Peak consecutive RTT variation.
- Smoothed RTT variation.
- Configurable timeout and interval between probes.
- ICMP failure does not automatically classify the target as offline.

### Path MTU estimation

- Tests multiple IP MTU candidates with the Don't Fragment flag.
- Reports the largest successful DF packet size as an IP MTU estimate.
- Clearly reports when ICMP or DF behavior prevents verification.

### TCP service-port matrix

- Tests the selected target port in every applicable scan mode.
- Tests common service ports in Medium, Deep, and JMeter modes.
- Distinguishes among:
  - `Open`
  - `Closed`
  - `Filtered`
  - `Unreachable`
  - `Error`
- Measures TCP connection time.
- Does not treat the absence of a protocol banner as proof that a TCP port is closed.
- Correlates ICMP reachability with the selected TCP port result.

Default extended port matrix:

- `80` HTTP
- `443` HTTPS
- `22` SSH
- `3389` RDP
- `53` DNS
- `445` SMB
- The user-selected target port

> A successful TCP handshake confirms that a connection was established. It does not by itself prove that the expected application protocol is running on that port.

### Hop-by-hop route and jitter analysis

- Discovers the route with `Test-NetConnection -TraceRoute`.
- Sends configurable ICMP samples to each responsive hop.
- Reports, per hop:
  - Minimum RTT
  - Maximum RTT
  - Average RTT
  - Median RTT
  - p95 RTT
  - Mean jitter
  - Peak jitter
  - Standard deviation
  - ICMP response loss
  - Diagnostic status
- Separates intermediate-hop ICMP variation from destination jitter.
- Does not automatically classify an unresponsive intermediate hop as end-to-end packet loss.
- Gives greater diagnostic weight to destination measurements than to router ICMP behavior.

### Native C# HTTP Load Engine v2

- Runs inside PowerShell using an embedded C# engine.
- Supports configurable concurrent users, total requests, warm-up requests, ramp-up time, think time, timeout, HTTP method, assertion text, and maximum response size.
- Supports `GET` and `HEAD` requests.
- Reuses HTTP connections through `HttpClient`.
- Supports HTTP decompression.
- Separates response-header time from full-response elapsed time.
- Applies a response-size limit to reduce uncontrolled memory usage.
- Treats HTTP `200-399` as successful when any configured assertion also passes.

Collected load-test metrics include:

- Requested and measured peak concurrency
- Warm-up request count
- Successful and failed requests
- Total test duration
- Throughput in requests per second
- Average header / TTFB-like time
- p95 header / TTFB-like time
- Average response-download time
- Average total elapsed time
- Elapsed-time standard deviation
- p50, p75, p90, p95, and p99 elapsed time
- HTTP error rate
- HTTP status-code distribution
- Error-type distribution
- Total response data
- Average response size
- Response-data throughput

> The reported header time is a client-observed time until response headers become available. It is useful as a TTFB-like metric but is not a packet-capture-level server timing measurement.

### External JMeter result analysis

- Imports an existing JMeter `.jtl` or `.csv` result file.
- Reads the `elapsed` field when available.
- Calculates and reports the external result-file p95 elapsed time.

### SSL and HTTP inspection

For supported web ports in Deep mode:

- Performs a TLS connection.
- Reads the remote certificate.
- Reports certificate subject, issuer, and remaining validity.
- Sends an HTTP request.
- Reports HTTP status and total response time.

### System hardware inventory

- Signed-in user
- Computer name
- Operating-system version
- CPU model and current load when available
- Total, used, and free memory
- Logical-disk capacity and utilization
- Active network adapter
- Local IPv4 address

### Cross-correlation analysis

The analysis engine correlates destination network quality with application-load metrics. Possible outcomes include:

- Insufficient measurement
- Possible network-quality issue
- Network and application latency correlation
- Possible server or application bottleneck
- Network variation detected, application unaffected
- Measured values are normal
- Network quality measured without application load data
- Application measured with limited network data
- Intermediate-hop ICMP variation without confirmed end-to-end degradation

The analysis is advisory. It does not claim that a client-side test definitively proves a specific IIS, database, operating-system, or infrastructure root cause.

### HTML dashboard reporting

- Generates a localized HTML report.
- Includes system, DNS, ICMP, MTU, TCP, route, jitter, HTTP, SSL, and load-test metrics.
- Includes advisory messages and correlation results.
- Includes a detailed hop table with status coloring.
- Safely HTML-encodes externally sourced values.
- Preserves trusted port-status badge markup generated by the script.
- Writes to a temporary file first.
- Overwrites an existing report with the same path.
- Removes read-only protection from an existing report when possible.
- Verifies the final UTF-8 byte length before reporting success.
- Reports whether a file was newly created or overwritten.
- Displays the final path, file size, and last-write time.
- Emits a visible error if the file cannot be written or is locked by another process.

### Commit hash-based auto-update

- Checks the latest commit on the GitHub `main` branch.
- Compares the seven-character remote commit hash with the local script version.
- Prompts with localized Yes/No options.
- Downloads the new script to a temporary file.
- Validates that the downloaded content resembles a PowerShell script.
- Runs PowerShell parser validation before replacement.
- Replaces the current script only after validation succeeds.
- Restarts the updated script in the **current Windows Terminal tab and current PowerShell host**.
- Does not open a separate `pwsh.exe` or `powershell.exe` window.
- Preserves the selected language during restart.
- Displays a manual restart command if in-session restart fails.

---

## Scan levels

### Low

Fast reachability test:

- System inventory
- DNS checks
- Endpoint ICMP metrics
- Path MTU estimation
- User-selected TCP port

### Medium

Standard network analysis:

- All Low checks
- Basic TCP port matrix
- Trace route
- Per-hop RTT and jitter analysis

### Deep

Detailed web and network diagnostics:

- All Medium checks
- Extended TCP port matrix
- Detailed route and jitter metrics
- SSL certificate inspection for supported HTTPS ports
- HTTP status and response-time check for supported web ports

### JMeter

Application-load and network-correlation mode:

- Endpoint ICMP and jitter analysis
- Extended TCP port matrix
- Hop-by-hop route analysis
- Native C# HTTP Load Engine v2
- Percentiles, throughput, response sizes, status distribution, errors, and assertions
- Network/application cross-correlation

---

## Prerequisites and requirements

- **Operating system:** Windows 10, Windows 11, or Windows Server
- **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+
- **Recommended privileges:** Administrator
- **Network access:** Required for target tests, public DNS checks, and GitHub update checks
- **PowerShell modules/cmdlets used:**
  - `Resolve-DnsName`
  - `Test-NetConnection`
  - `Get-CimInstance`
  - `Get-NetAdapter`
  - `Get-NetIPAddress`
  - `Get-NetIPConfiguration`
  - `Invoke-RestMethod`
  - `Invoke-WebRequest`
  - `Add-Type`

Administrator privileges are recommended for consistent CIM/WMI inventory retrieval and network diagnostics, but some tests may work without elevation.

---

## Installation

Download or clone the repository, then place `netdiag.ps1` in the preferred working directory.

Example:

```powershell
Set-Location C:\scripts
Unblock-File .\netdiag.ps1
```

If local execution policy prevents the script from running, start it with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\netdiag.ps1
```

PowerShell 7 example:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\netdiag.ps1
```

---

## Interactive usage

Start the interactive wizard without parameters:

```powershell
.\netdiag.ps1
```

The wizard explains:

- Target hostname or IP address
- Target TCP port
- Scan-level differences
- Per-hop ping count
- Concurrent HTTP users
- Total HTTP requests
- Optional response assertion
- Destination jitter sample count
- Warm-up requests
- Ramp-up duration
- HTML report generation

---

## Command-line usage

### Quick HTTPS reachability test

```powershell
.\netdiag.ps1 `
    -Target "example.com" `
    -Port 443 `
    -ScanLevel Low
```

### Detailed network and HTTPS analysis

```powershell
.\netdiag.ps1 `
    -Target "example.com" `
    -Port 443 `
    -ScanLevel Deep `
    -HopPingCount 10 `
    -DestinationPingCount 30 `
    -ExportHtmlPath ".\NetworkReport_example_com.html"
```

### Concurrent HTTP load test

```powershell
.\netdiag.ps1 `
    -Target "example.com" `
    -Port 443 `
    -ScanLevel JMeter `
    -DestinationPingCount 30 `
    -HopPingCount 10 `
    -JMeterThreads 10 `
    -JMeterTotalRequests 100 `
    -JMeterWarmupRequests 5 `
    -JMeterRampUpSeconds 5 `
    -HttpTimeoutSec 10 `
    -ExportHtmlPath ".\NetworkReport_example_com.html"
```

### Load test with response assertion

```powershell
.\netdiag.ps1 `
    -Target "example.com" `
    -Port 443 `
    -ScanLevel JMeter `
    -JMeterThreads 20 `
    -JMeterTotalRequests 200 `
    -JMeterAssertText "Expected text" `
    -JMeterWarmupRequests 10 `
    -JMeterRampUpSeconds 10
```

### Analyze an existing JMeter file

```powershell
.\netdiag.ps1 `
    -Target "example.com" `
    -Port 443 `
    -ScanLevel Deep `
    -JMeterCsvPath ".\results.jtl"
```

### Force English

```powershell
.\netdiag.ps1 -Language en
```

### Force Turkish

```powershell
.\netdiag.ps1 -Language tr
```

### Automatic language selection

```powershell
.\netdiag.ps1 -Language Auto
```

---

## Main parameters

```text
-Target                     Target DNS name or IP address
-Port                       Target TCP port, default 443
-ScanLevel                  Low, Medium, Deep, or JMeter
-HopPingCount               ICMP samples per responsive route hop
-EnableLoadTest             Enables the built-in HTTP load test outside JMeter mode
-JMeterThreads              Maximum concurrent HTTP requests
-JMeterTotalRequests        Total measured HTTP requests
-JMeterAssertText           Optional response-body assertion text
-JMeterCsvPath              Optional external JMeter JTL/CSV file
-ExportHtmlPath             HTML report output path
-CheckUpdate                Runs update checking in parameter-based execution
-TcpTimeoutMs               TCP connection timeout in milliseconds
-HttpTimeoutSec             HTTP request timeout in seconds
-PingTimeoutMs              Per-ICMP-probe timeout in milliseconds
-PingIntervalMs             Delay between ICMP probes
-DestinationPingCount       Endpoint ICMP sample count
-JMeterWarmupRequests       Unmeasured HTTP warm-up requests
-JMeterRampUpSeconds        Load ramp-up duration
-JMeterThinkTimeMs          Delay after measured requests
-JMeterMaxResponseBytes     Maximum accepted response-body size
-JMeterHttpMethod           GET or HEAD
-Language                   Auto, tr, or en
```

---

## HTML report overwrite behavior

When the selected HTML path already exists, NetDiag overwrites the existing report without an additional confirmation prompt.

Successful overwrite example:

```text
[REPORT] Existing report overwritten: C:\scripts\NetworkReport_example_com.html | 15324 Byte | 2026-08-13 15:20:31
```

If the report cannot be replaced, NetDiag prints the actual error and does not display a false success message.

---

## Update behavior

When a newer commit is detected:

1. NetDiag displays the local and remote short commit hashes.
2. The user chooses whether to update.
3. The new script is downloaded to a temporary path.
4. The downloaded script is parsed and validated.
5. The current script is replaced.
6. The updated script is invoked in the same terminal session.
7. The selected language is preserved.

If automatic in-session restart fails, NetDiag displays a manual restart command.

---

## Interpreting jitter results

NetDiag distinguishes among several related measurements:

- **RTT standard deviation:** Overall RTT dispersion around the average.
- **Mean jitter:** Average absolute difference between consecutive successful RTT samples.
- **Peak jitter:** Largest absolute difference between two consecutive successful RTT samples.
- **Smoothed RTT variation:** Exponentially smoothed consecutive RTT variation.

Intermediate routers may deprioritize or rate-limit ICMP replies. Therefore:

- High jitter on one intermediate hop does not automatically prove end-to-end degradation.
- Missing ICMP replies from an intermediate hop do not automatically represent real packet loss.
- Destination jitter and destination response loss receive greater weight in the final analysis.

---

## Interpreting HTTP metrics

- **Header / TTFB-like time:** Client-observed time until response headers are available.
- **Download time:** Time spent reading the response after headers arrive.
- **Elapsed time:** Total client-observed request duration.
- **Throughput:** Completed measured requests divided by total load-test duration.
- **Peak concurrency:** Highest number of requests simultaneously active during the measurement.
- **Error rate:** Failed measured requests divided by total measured requests.

Warm-up requests are excluded from the main result set.

---

## Accuracy and limitations

- ICMP may be blocked even when the target service is available.
- A successful TCP handshake does not validate the expected protocol.
- CDN, WAF, reverse proxy, transparent proxy, or TCP interception can affect observed results.
- Intermediate-hop ICMP behavior may not represent forwarded application traffic.
- Path MTU is an estimate and depends on ICMP and Don't Fragment behavior.
- The HTTP load engine is client-side and does not prove a specific server-side root cause.
- SSL certificate validation is intentionally relaxed during diagnostic retrieval and load testing. Do not interpret this as a certificate trust validation result.
- Large load tests can affect the target service. Only test systems for which authorization has been granted.

---

## Safety recommendations

- Begin with Low or Deep mode before running a load test.
- Use conservative thread and request counts in production.
- Confirm authorization before testing third-party or production systems.
- Review target rate limits, WAF rules, and monitoring alerts.
- Treat correlation output as diagnostic guidance, not definitive proof.

---

## Contributing

Issues and pull requests are welcome. When reporting a problem, include:

- PowerShell version from `$PSVersionTable`
- Windows version
- Selected scan level
- Sanitized console output
- Parser errors with line and column numbers
- Sanitized HTML report when relevant
