# NetDiag

NetDiag is an advanced PowerShell-based diagnostic framework for Windows. It combines DNS validation, ICMP and Path MTU testing, protocol-aware TCP and UDP service validation, hop-by-hop route analysis, endpoint jitter measurements, concurrent HTTP load testing, TLS certificate inspection, HTTP fallback handling, system inventory, automated cross-correlation, multilingual output, and enterprise-ready HTML reporting in a single script.

NetDiag is designed to help distinguish among:

- DNS and name-resolution problems
- ICMP filtering and endpoint reachability issues
- TCP connectivity versus actual application-service availability
- UDP service availability and indeterminate UDP responses
- Route instability and intermediate-hop ICMP variation
- End-to-end latency, response loss, and jitter
- TLS handshake, certificate validity, and HTTPS availability problems
- HTTP response-time, throughput, and error-rate problems
- Possible server, application, database, or network bottlenecks
- Transparent proxy, firewall interception, CDN, WAF, and reverse-proxy behavior

> **Important:** The built-in load test is a native C# HTTP load engine inspired by JMeter-style metrics. It does not launch Apache JMeter and is not a replacement for a full Apache JMeter test plan.

---

## Features

### Multilingual interface and reports

- Automatically detects the Windows UI culture.
- Uses Turkish for `tr-TR` and other `tr-*` cultures.
- Uses English for `en-US` and other cultures by default.
- Supports manual selection with `-Language tr`, `-Language en`, or `-Language Auto`.
- Localizes interactive prompts, Yes/No conventions, console messages, correlation results, warnings, table headings, status labels, infographics, privacy notices, and HTML reports.
- Uses `E/H` and `Evet/Hayır` in Turkish.
- Uses `Y/N` and `Yes/No` in English.

### Multi-resolver DNS analysis

- Local DNS resolution and IPv4 record discovery.
- Local DNS query-time measurement.
- Google Public DNS (`8.8.8.8`) comparison.
- Cloudflare DNS (`1.1.1.1`) comparison.
- Split-DNS and resolver-mismatch warnings.
- Authoritative name-server discovery.
- Reverse DNS (`PTR`) lookup.
- CNAME and IP-signature checks for common CDN and reverse-proxy patterns.
- Separate DNS-over-UDP and DNS-over-TCP protocol validation in extended scan modes.

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

### Protocol-aware TCP service matrix

NetDiag separates a successful TCP handshake from successful application-protocol validation.

Possible TCP results include:

- `SERVICE VERIFIED`
- `TCP CONNECTED, SERVICE NOT VERIFIED`
- `CLOSED`
- `FILTERED / TIMEOUT`
- `UNREACHABLE`
- `ERROR`

A completed TCP handshake proves that a connection was established to an endpoint. It does not prove that the expected protocol is running on that endpoint.

Protocol-aware checks include:

- HTTP status-line validation
- TLS handshake and certificate inspection
- SSH banner validation
- RDP X.224 / negotiation-response validation
- DNS-over-TCP transaction validation
- SMTP greeting validation
- POP3 greeting validation
- IMAP greeting validation
- Implicit-TLS validation for SMTPS, IMAPS, and POP3S
- Safe identification of database ports without claiming protocol verification from a handshake alone

### Extended TCP port matrix

By default, Deep and JMeter modes test the essential web, mail, DNS, and administration ports, plus the user-selected target port:

#### Web and administration

- `80` HTTP
- `443` HTTPS / TLS
- `8080` HTTP-alt
- `8443` HTTPS-alt
- `22` SSH
- `3389` RDP
- `445` SMB
- `53` DNS over TCP
- `23` Telnet
- `21` FTP

#### Mail services

- `25` SMTP relay
- `587` SMTP submission / STARTTLS
- `465` SMTPS / implicit TLS
- `110` POP3 / STARTTLS
- `995` POP3S / implicit TLS
- `143` IMAP / STARTTLS
- `993` IMAPS / implicit TLS

STARTTLS-capable plaintext ports validate the initial service greeting without submitting credentials or authenticating. Implicit-TLS ports perform a TLS handshake and certificate-date evaluation.

#### Custom port list

The default port set can be overridden with `-Ports "80,443,22,3389"` (comma-, space-, or semicolon-separated; values must be between 1 and 65535). The user-selected target port is always appended. In interactive (wizard) mode NetDiag prompts for an optional custom port list. When a custom list is supplied, the report records the scanned ports and notes that the scan used the custom list.

Database ports (such as `1433`, `3306`, `5432`, `1521`, `6379`, `27017`, `9200`) are not scanned by default. When they are present in a custom `-Ports` list and respond to a TCP handshake, NetDiag warns that internet-exposed database services were detected. Database ports are never reported as verified database services based only on a TCP handshake; without full protocol negotiation NetDiag reports `TCP CONNECTED, SERVICE NOT VERIFIED`.

### UDP service validation

Deep and JMeter modes include a dedicated UDP validation matrix:

- `53/UDP` DNS query validation
- `123/UDP` NTP response validation
- `1434/UDP` SQL Server Browser response validation

Possible UDP results include:

- `SERVICE VERIFIED`
- `RESPONSE RECEIVED, SERVICE NOT VERIFIED`
- `NO RESPONSE / INDETERMINATE`
- `CLOSED OR REJECTED`
- `ERROR`

> UDP does not establish a connection. No response does not conclusively mean that a UDP port is closed; the service may be open, filtered, restricted, or silently dropping probes.

### Transparent proxy and interception awareness

- Detects suspicious patterns where several unrelated ports accept TCP connections but do not return valid application-protocol responses.
- Adds an advisory warning for possible transparent proxy, firewall interception, security gateway, or TCP interception behavior.
- Does not report such ports as verified services.

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
- Localizes hidden-hop labels such as `Hidden/Unresponsive (*)`.
- Gives greater diagnostic weight to destination measurements than to router ICMP behavior.

### GeoIP and ASN enrichment

- Enriches the target and route hop IP addresses with ASN, provider, ISP, and geolocation data via the ip-api.com batch API.
- Reports target ASN/provider, geolocation, ISP/organization, and per-hop ASN for the discovered route.
- Enabled by default on every scan; disable with `-SkipGeoIp`.
- In interactive (wizard) mode, NetDiag asks whether GeoIP/ASN enrichment should run, defaulting to Yes, and discloses that IP addresses are sent to the third-party ip-api.com service.

### Native C# HTTP Load Engine v2

- Runs inside PowerShell using an embedded C# engine.
- Supports configurable concurrent users, total requests, warm-up requests, ramp-up time, think time, timeout, HTTP method, assertion text, and maximum response size.
- Supports `GET` and `HEAD` requests.
- Reuses HTTP connections through `HttpClient`.
- Supports HTTP decompression.
- Separates response-header time from full-response elapsed time.
- Applies a response-size limit to reduce uncontrolled memory usage.
- Treats HTTP `200-399` as successful when any configured assertion also passes.
- Reports `N/A` instead of blank percentile values when no successful samples exist.

Collected load-test metrics include:

- Requested concurrency
- Measured peak concurrency
- Warm-up request count
- Successful and failed request counts
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

> Header time is a client-observed measurement until response headers become available. It is a TTFB-like metric, not a packet-capture-level server timing measurement.

### HTTPS certificate inspection and HTTP fallback

For supported HTTPS targets, NetDiag attempts to capture and report:

- TLS handshake result
- TLS protocol
- Certificate subject
- Certificate issuer
- Certificate valid-from date
- Certificate valid-until date
- Remaining validity
- Certificate status

Certificate states include:

- `Valid`
- `Expired`
- `NotYetValid`
- `Missing`
- `HandshakeFailed`
- `MissingOrHandshakeFailed`
- `NotApplicable`

When HTTPS cannot be verified but HTTP on port 80 is protocol-verified, JMeter mode can fall back to:

```text
http://target:80/
```

The effective load-test URL is written to the HTML report. If neither HTTPS nor HTTP/80 can be verified, the load test is skipped instead of generating predictable request failures.

### External JMeter result analysis

- Imports an existing JMeter `.jtl` or `.csv` result file.
- Reads the `elapsed` field when available.
- Calculates and reports the external result-file p95 elapsed time.

### System hardware inventory

- Signed-in user
- Computer name
- Operating-system version
- CPU model
- Current CPU usage
- CPU usage data source
- Total, used, and free memory
- Logical-disk capacity and utilization
- Active network adapter
- Local IPv4 address

CPU utilization uses a fallback chain:

1. `Win32_PerfFormattedData_PerfOS_Processor`
2. `Get-Counter '\Processor(_Total)\% Processor Time'`
3. `Win32_Processor.LoadPercentage`

If no source is available, the report displays `N/A` and records the reason.

### Cross-correlation analysis

The correlation engine evaluates destination network quality together with application-load metrics. Possible outcomes include:

- Insufficient measurement
- Application test completely failed
- High application error rate
- Possible network-quality issue
- Network and application latency correlation
- Possible server or application bottleneck
- Network variation detected, application unaffected
- Measured values are normal
- Network quality measured without application-load data
- Application measured with limited network data
- Intermediate-hop ICMP variation without confirmed end-to-end degradation

A 100% HTTP failure rate takes priority and cannot be reported as normal. If no successful HTTP sample exists, HTTP percentiles remain `N/A`.

The analysis is advisory. A client-side test cannot conclusively identify a specific IIS, database, operating-system, network-device, or application root cause by itself.

### Power BI-inspired HTML infographics

The HTML report includes responsive, dependency-free visual summaries built with embedded HTML and CSS:

- Network-quality KPI cards
  - Average RTT
  - Destination p95 RTT
  - Mean jitter
  - Response loss
- HTTP load-test KPI cards
  - Throughput
  - HTTP p95
  - Error rate
  - Peak concurrency
- Successful-versus-failed request donut visualization
- HTTP p50, p75, p90, p95, and p99 horizontal bars
- Hop-by-hop jitter distribution bars
- Responsive card layout for desktop and narrow browser windows

No external JavaScript, chart library, CDN asset, or image file is required. Charts are generated only when the required measurements exist; NetDiag does not fabricate missing values.

### Enterprise-ready HTML reporting

- Generates a localized HTML report.
- Includes system, DNS, ICMP, MTU, TCP, UDP, route, jitter, HTTP, TLS, certificate, and load-test metrics.
- Includes protocol-verification evidence and advisory messages.
- Includes a detailed hop table with status coloring.
- Presents all metrics in a responsive, auto-extending grid of cards (roughly 2-3 columns on desktop) instead of a single tall table; wide rows such as the port matrix and security-header audit span the full width, and new metrics flow in automatically.
- Includes Power BI-inspired KPI cards and charts.
- Safely HTML-encodes externally sourced values.
- Preserves only trusted badge markup generated by NetDiag.
- Writes to a temporary file first.
- Overwrites an existing report with the same path without an extra prompt.
- Removes read-only protection from an existing report when possible.
- Verifies the final UTF-8 byte length before reporting success.
- Reports whether the file was newly created or overwritten.
- Displays final path, size, and last-write time.
- Emits a visible error if the report cannot be written or is locked.

### Report footer and project promotion

The report footer includes:

- NetDiag short version / commit identifier
- A statement that the report was generated by NetDiag
- A short open-source project description
- A link to the [NetDiag GitHub project](https://github.com/oguska/netdiag)

### Privacy and data-processing notice

The HTML footer contains a collapsed-by-default privacy disclosure. It explains that:

- Diagnostic results are not sent to a NetDiag-owned server, central database, or the NetDiag developer.
- Diagnostic values are processed locally during execution.
- The HTML report is created locally only when the user chooses to save it.
- The report may contain user name, computer name, local IP address, target address, system inventory, and network measurements.
- The user or organization running NetDiag is responsible for storing, sharing, and protecting the generated report.
- Update checks may communicate with GitHub.
- DNS comparisons may communicate with configured public DNS resolvers.
- Diagnostic probes communicate with the selected target systems.
- NetDiag does not use cookies, advertising identifiers, usage analytics, or persistent user profiles.

The disclosure includes informational links to official EU GDPR and Turkish KVKK resources. It is informational and is not legal advice.

### Commit hash-based auto-update

- When the script runs inside a git clone, it reads the current commit hash from the repository HEAD (`git rev-parse --short HEAD`), so the reported version is always accurate after every local or remote commit.
- When git is unavailable, it queries the GitHub API for the latest commit on `main` and reports that hash; if the machine is offline it falls back to the last-known commit hash stamped into the script.
- Checks the latest commit on the GitHub `main` branch.
- Compares the seven-character remote commit hash with the local script version (the git HEAD when inside a clone, otherwise the stamped hash).
- The stamped hash is rewritten to the latest commit whenever an update is downloaded, so end users without git always carry an accurate version marker.
- Prompts with localized Yes/No options.
- Downloads the new script to a temporary file.
- Validates that the downloaded content resembles a PowerShell script.
- Runs PowerShell parser validation before replacement.
- Replaces the current script only after validation succeeds.
- Restarts the updated script in the current Windows Terminal tab and PowerShell host.
- Does not intentionally open a separate `pwsh.exe` or `powershell.exe` window.
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

Detailed service, web, and network diagnostics:

- All Medium checks
- Extended protocol-aware TCP matrix
- Mail-service ports
- Database-service ports
- UDP DNS, NTP, and SQL Server Browser validation
- Detailed route and jitter metrics
- TLS certificate inspection
- HTTP status and response-time analysis
- HTML metrics and infographics

### JMeter

Application-load and network-correlation mode:

- Endpoint ICMP and jitter analysis
- Extended TCP and UDP service matrices
- Mail and database port checks
- Hop-by-hop route analysis
- Native C# HTTP Load Engine v2
- HTTPS certificate evaluation
- Verified HTTP/80 fallback when HTTPS is unavailable
- Percentiles, throughput, response-size, status, error, and assertion metrics
- Network/application cross-correlation
- Power BI-inspired report infographics

### WebSec

Web security scan mode (level 5). Includes all Deep checks (inventory, DNS, ICMP, MTU, extended TCP matrix, UDP validation, route/jitter, TLS/SSL inspection, HTTP analysis, GeoIP/ASN, advisor notes) and additionally performs a passive web attack-surface analysis:

- Detects which open TCP ports actually serve HTTP or HTTPS.
- HTTP method probes (OPTIONS `Allow`), including TRACE, PUT, DELETE, and PATCH detection (TRACE is a cross-site tracing/XST risk).
- Server banner and `X-Powered-By` disclosure checks.
- Directory-listing detection.
- Cookie `Secure`, `HttpOnly`, and `SameSite` flag checks.
- Missing/weak security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) per web port.
- HTTP/80 to HTTPS redirect validation.
- Advisor notes with concrete remediation advice for each finding, plus a `Web Attack-Surface Summary` and `Web Attack-Surface Findings` section in the HTML report.

The probes are read-only (GET/HEAD/OPTIONS/TRACE) and never modify server state. The concurrent load test remains exclusive to JMeter mode.

---

## Prerequisites and requirements

- **Operating system:** Windows 10, Windows 11, or Windows Server
- **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+
- **Recommended privileges:** Administrator
- **Network access:** Required for target tests, public DNS checks, and GitHub update checks
- **PowerShell modules and cmdlets used:**
  - `Resolve-DnsName`
  - `Test-NetConnection`
  - `Get-CimInstance`
  - `Get-Counter`
  - `Get-NetAdapter`
  - `Get-NetIPAddress`
  - `Get-NetIPConfiguration`
  - `Invoke-RestMethod`
  - `Invoke-WebRequest`
  - `Add-Type`

Administrator privileges are recommended for consistent CIM/WMI inventory retrieval, performance counters, and network diagnostics. Some checks may work without elevation.

---

## Installation

Download or clone the repository, then place `netdiag.ps1` in the preferred working directory.

```powershell
Set-Location C:\scripts
Unblock-File .\netdiag.ps1
```

If the local execution policy prevents the script from running:

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
-ScanLevel                  Low, Medium, Deep, JMeter, or WebSec
-HopPingCount               ICMP samples per responsive route hop
-EnableLoadTest             Enables the built-in HTTP load test outside JMeter mode
-JMeterThreads              Maximum concurrent HTTP requests
-JMeterTotalRequests        Total measured HTTP requests
-JMeterAssertText           Optional response-body assertion text
-JMeterCsvPath              Optional external JMeter JTL/CSV file
-ExportHtmlPath             HTML report output path
-CheckUpdate                Runs update checking in parameter-based execution
-TcpTimeoutMs               TCP and UDP probe timeout in milliseconds
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
-Ports                      Optional comma/space/semicolon-separated TCP port list
-SkipGeoIp                  Disables GeoIP/ASN enrichment (enabled by default)
```

---

## HTML report overwrite behavior

When the selected HTML path already exists, NetDiag overwrites the existing report without an additional confirmation prompt.

```text
[REPORT] Existing report overwritten: C:\scripts\NetworkReport_example_com.html | 15324 Byte | 2026-08-13 15:20:31
```

If the report cannot be replaced, NetDiag reports the actual error and does not display a false success message.

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

## Interpreting service results

### Service verified

The expected protocol returned a recognizable response, banner, handshake, or transaction result.

### TCP connected, service not verified

A TCP handshake completed, but the expected application protocol was not validated. Possible explanations include:

- A different service is running on the port
- A transparent proxy or security device accepted the connection
- The protocol did not send the expected greeting
- TLS negotiation failed
- The service requires additional negotiation not performed by NetDiag

### No UDP response / indeterminate

No valid UDP response was received. This does not prove that the port is closed because UDP may be silently filtered or dropped.

---

## Interpreting jitter results

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
- **Peak concurrency:** Highest number of requests simultaneously active during measurement.
- **Error rate:** Failed measured requests divided by total measured requests.

Warm-up requests are excluded from the main result set.

---

## Accuracy and limitations

- ICMP may be blocked even when the target service is available.
- A successful TCP handshake does not validate the expected protocol.
- No UDP response does not conclusively prove a closed port.
- CDN, WAF, reverse proxy, transparent proxy, or TCP interception can affect observed results.
- Intermediate-hop ICMP behavior may not represent forwarded application traffic.
- Path MTU is an estimate and depends on ICMP and Don't Fragment behavior.
- The HTTP load engine is client-side and does not prove a specific server-side root cause.
- Certificate dates and TLS handshake results do not replace a complete public-key infrastructure, revocation, hostname, or trust-policy assessment.
- Some diagnostic TLS retrieval uses a permissive callback so that certificate metadata can be inspected. The reported certificate status should not be interpreted as a complete operating-system trust decision.
- STARTTLS ports currently validate the initial service greeting but do not authenticate or submit credentials.
- Database ports may be identified by conventional port number without completing full database authentication or protocol negotiation.
- Large load tests can affect the target service. Only test systems for which authorization has been granted.

---

## Privacy and data handling

NetDiag processes diagnostic information locally and does not send diagnostic results to a NetDiag-owned server, central database, or the NetDiag developer.

The generated HTML report may contain:

- Signed-in user name
- Computer name
- Local IP address
- Target address
- System inventory
- Network and application measurements

The user or organization running NetDiag is responsible for storing, sharing, and protecting generated reports.

NetDiag may communicate with:

- GitHub for update checks
- Configured public DNS resolvers for DNS comparison
- The selected target systems for diagnostic probes and load testing
- The ip-api.com service for GeoIP/ASN enrichment (enabled by default; disable with `-SkipGeoIp`)

NetDiag does not use cookies, advertising identifiers, usage analytics, or persistent user profiles. The report includes a collapsed privacy and data-processing notice with informational links to official EU GDPR and Turkish KVKK resources.

This information is not legal advice. Organizations should separately evaluate obligations under applicable laws, regulations, contracts, and internal policies.

---

## Safety recommendations

- Begin with Low or Deep mode before running a load test.
- Use conservative thread and request counts in production.
- Confirm authorization before testing third-party or production systems.
- Review target rate limits, WAF rules, firewall rules, and monitoring alerts.
- Avoid exposing database, mail, SMB, RDP, or SQL Browser services to untrusted networks.
- Treat correlation output as diagnostic guidance, not definitive proof.
- Review and sanitize HTML reports before sharing them externally.

---

# Changelog

## Unreleased

### Added

- Git-less commit reporting: when `git` is unavailable, the version banner and report fall back to the latest commit from the GitHub API, and to the stamped hash when offline.
- Update comparison now uses the true local version (git HEAD inside a clone, otherwise the stamped hash), so end users without git are still offered updates on stale copies.

- Protocol-aware TCP service validation with separate handshake and service-verification states.
- RDP X.224 / negotiation-response validation on TCP/3389.
- SSH banner validation on TCP/22.
- HTTP status-line validation on TCP/80.
- TLS handshake and certificate-date inspection on TCP/443.
- DNS-over-TCP transaction validation.
- Mail-service checks for SMTP, SMTP submission, SMTPS, POP3, POP3S, IMAP, and IMAPS.
- Database-port coverage for Microsoft SQL Server, MySQL/MariaDB, PostgreSQL, and Oracle Database Listener.
- UDP validation for DNS/53, NTP/123, and SQL Server Browser/1434.
- Transparent-proxy and TCP-interception advisory logic.
- TLS certificate states for valid, expired, not-yet-valid, missing, and failed handshakes.
- Verified HTTP/80 fallback when HTTPS cannot be validated.
- Effective load-test URL reporting.
- CPU usage fallback chain and CPU data-source reporting.
- Power BI-inspired HTML KPI cards.
- HTTP success/failure donut visualization.
- HTTP percentile bar visualization.
- Hop-by-hop jitter bar visualization.
- Report footer with NetDiag version and GitHub project link.
- Collapsed privacy and data-processing disclosure.
- Official GDPR and KVKK informational links in the HTML disclosure.
- New `WebSec` scan level (level 5) that runs all Deep checks plus a passive HTTP/HTTPS attack-surface analysis (methods/TRACE, banners, directory listing, cookie flags, per-port security headers, HTTP-to-HTTPS redirect) with per-finding remediation advice in the advisor notes and dedicated report rows.

### Changed

- Extended Deep and JMeter scan matrices with common mail and database ports.
- Reworked the TCP port scan to use an essential default set (web, mail, DNS, and administration ports) with an optional `-Ports` custom list and a wizard prompt for a custom list.
- Added report rows and advisor entries for the scanned port list, internet-exposed database/RDP/SMB/Telnet/FTP warnings, SSH and HTTP/80 information, and SSL certificate expiry warnings.
- Enabled GeoIP/ASN enrichment on every scan by default (previously opt-in with `-GeoIp`), with `-SkipGeoIp` to disable and a wizard confirmation prompt.
- Made the reported commit hash auto-derived from the git repository HEAD when running inside a clone, so it stays accurate after every local or remote commit without manual edits.
- Rendered the metrics section as a responsive, auto-extending card grid (about 2-3 columns on desktop) instead of a single tall table, with full-width cards for the port matrices and security-header audit.
- Renamed the extended matrix to clarify TCP and UDP service validation.
- Reworked correlation priority so 100% HTTP failure cannot be reported as normal.
- Reworked network-variation logic so elevated jitter with healthy application results is reported separately.
- Replaced blank HTTP latency and percentile values with `N/A` when no successful request sample exists.
- Localized correlation output directly instead of relying only on post-processing translations.
- Expanded localization for dynamic inventory, route, service, certificate, chart, and footer values.
- Improved report overwrite behavior with temporary-file creation, byte-length verification, and explicit create/overwrite status.
- Updated auto-restart behavior to continue in the current terminal host.

### Fixed

- False-positive `Open` classifications caused by TCP handshake-only checks.
- RDP/3389 false positives when no RDP X.224 response is present.
- Duplicate case-insensitive translation keys in PowerShell hash literals.
- Mixed Turkish and English text in English HTML reports.
- Turkish hidden-hop labels in English route tables.
- Missing CPU usage on systems where `Win32_Processor.LoadPercentage` is unavailable.
- Invalid inline PowerShell `if` expressions in route and CPU report values.
- Empty TTFB and percentile values after complete HTTP load-test failure.
- Incorrect `MEASURED VALUES ARE NORMAL` output during 100% HTTP failure.
- Incorrect full-HTML translation passes that could alter markup or values.
- Report path overwrite behavior and false-positive report-success messages.
- Auto-update restart opening a separate PowerShell window.
- Partially translated phrases such as `Error yok`.
- Missing translations for service counts, privacy text, infographic headings, and report footer labels.

---

## Contributing

Issues and pull requests are welcome. When reporting a problem, include:

- PowerShell version from `$PSVersionTable`
- Windows version
- Selected scan level
- Target service type, with sensitive hostnames sanitized when necessary
- Sanitized console output
- Parser errors with line and column numbers
- Sanitized HTML report when relevant

Project home: [NetDiag on GitHub](https://github.com/oguska/netdiag)
