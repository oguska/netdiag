<#
.SYNOPSIS
    An advanced enterprise network diagnostic, JMeter load testing, hardware inventory
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Target,

    [Parameter(Mandatory = $false, Position = 1)]
    [int]$Port,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Low', 'Medium', 'Deep', 'JMeter')]
    [string]$ScanLevel,

    [Parameter(Mandatory = $false)]
    [int]$HopPingCount,

    [Parameter(Mandatory = $false)]
    [bool]$EnableLoadTest,

    [Parameter(Mandatory = $false)]
    [int]$JMeterThreads = 10,

    [Parameter(Mandatory = $false)]
    [int]$JMeterTotalRequests = 50,

    [Parameter(Mandatory = $false)]
    [string]$JMeterAssertText,

    [Parameter(Mandatory = $false)]
    [string]$JMeterCsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ExportHtmlPath,

    [Parameter(Mandatory = $false)]
    [switch]$CheckUpdate
)

$GithubRawUrl = "https://raw.githubusercontent.com/oguska/netdiag/main/netdiag.ps1"

# --- OTOMATİK SÜRÜM KONTROLÜ (COMMIT HASH TABANLI) ---
function Test-ScriptUpdate {
    # Scriptin içindeki sabit değişken
    $CurrentCommit = "d33d9f4" # <-- Burası scriptin içine hardcoded yazılacak ve her güncellemede güncellenecek
    
    Write-Host "[*] GitHub üzerinden güncel sürüm kontrol ediliyor..." -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $apiUrl = "https://api.github.com/repos/oguska/netdiag/commits/main"
        $headers = @{ "Accept" = "application/vnd.github.v3+json" }
        
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -TimeoutSec 3
        $latestCommitHash = $response.sha.Substring(0, 7)
        
        if ($CurrentCommit -ne $latestCommitHash) {
            Write-Host "`n=========================================================================" -ForegroundColor Yellow
            Write-Host " [!] DİKKAT: Yeni sürüm bulundu! (Local: $CurrentCommit -> Remote: $latestCommitHash)" -ForegroundColor Yellow
            Write-Host "=========================================================================" -ForegroundColor Yellow
            
            $updateAns = Read-Host " -> Otomatik güncelleyip yeniden başlatılsın mı? (E/H)"
            if ($updateAns -match '^[EeYy]') {
                $rawContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/oguska/netdiag/main/netdiag.ps1" -UseBasicParsing).Content
                
                # ÖNEMLİ: Scripti güncellerken hash değerini de yeni hash ile değiştiren küçük bir regex operasyonu
                $newContent = $rawContent -replace '(?<=CurrentCommit = ")([a-f0-9]{7})', $latestCommitHash
                
                $currentScriptPath = $PSCommandPath
                $newContent | Out-File -FilePath $currentScriptPath -Encoding utf8
                
                Write-Host "[+] Script güncellendi ($latestCommitHash). Yeniden başlatılıyor..." -ForegroundColor Green
                & $currentScriptPath
                Exit
            }
        } else {
            Write-Host "[+] Script güncel (Hash: $CurrentCommit)." -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Sürüm kontrolü yapılamadı." -ForegroundColor DarkGray
    }
}

# --- İNTERAKTİF GİRDİ YÖNETİMİ ---
if ([string]::IsNullOrWhiteSpace($Target)) {
    Clear-Host
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host "NetDiag - An network diagnostic, JMeter load testing, hardware inventory script ($CurrentCommit)          " -ForegroundColor Cyan
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Test-ScriptUpdate
    Write-Host ""

    do {
        $Target = Read-Host " -> Test edilecek hedef adresi girin (Domain veya IP) [Örn: google.com]"
    } while ([string]::IsNullOrWhiteSpace($Target))

    $inputPort = Read-Host " -> Test edilecek TCP Port Numarası [Varsayılan: 443]"
    if ([string]::IsNullOrWhiteSpace($inputPort)) { $Port = 443 } else { $Port = [int]$inputPort }

    Write-Host "`n-------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " TARAMA VE TEST SEVİYESİNİ SEÇİN:" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host " [1] LOW (Basic)    : Hızlı Test. Donanım/PC Bilgisi + DNS, ICMP Ping, Port." -ForegroundColor White
    Write-Host " [2] MEDIUM (Detail): Standart Test. Donanım Bilgisi + Rota Jitter Analizi." -ForegroundColor White
    Write-Host " [3] DEEP (Complete): Derinlemesine. Donanım Bilgisi + Soket, TTFB, SSL & WAF." -ForegroundColor White
    Write-Host " [4] JMETER (Load)  : Uygulama Katmanı. Donanım Bilgisi + Jitter + Yük Testi." -ForegroundColor White
    Write-Host "-------------------------------------------------------------------------" -ForegroundColor Yellow

    do {
        $levelChoice = Read-Host " Seçiminiz (1-4) [Varsayılan: 3 - Deep]"
        if ([string]::IsNullOrWhiteSpace($levelChoice)) { $levelChoice = "3" }
    } while ($levelChoice -notin @('1','2','3','4'))

    switch ($levelChoice) {
        '1' { $ScanLevel = 'Low' }
        '2' { $ScanLevel = 'Medium' }
        '3' { $ScanLevel = 'Deep' }
        '4' { $ScanLevel = 'JMeter' }
    }

    if ($ScanLevel -eq 'JMeter') {
        Write-Host "`n-------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " JMETER TEST PARAMETRELERİ:" -ForegroundColor Yellow
        Write-Host "-------------------------------------------------------------------------" -ForegroundColor Yellow
        
        $inThreads = Read-Host " -> Eşzamanlı Sanal Kullanıcı (Thread) Sayısı [Varsayılan: 10]"
        if ([string]::IsNullOrWhiteSpace($inThreads)) { $JMeterThreads = 10 } else { $JMeterThreads = [int]$inThreads }

        $inReqs = Read-Host " -> Toplam Gönderilecek HTTP İstek Sayısı [Varsayılan: 50]"
        if ([string]::IsNullOrWhiteSpace($inReqs)) { $JMeterTotalRequests = 50 } else { $JMeterTotalRequests = [int]$inReqs }

        $JMeterAssertText = Read-Host " -> Response Assertion (Sayfada Doğrulanacak Kelime/JSON) [Opsiyonel]"
        
        $inputPing = Read-Host " -> Ağ Rota/Jitter analizi için Hop başına Ping paket sayısı [Varsayılan: 5]"
        if ([string]::IsNullOrWhiteSpace($inputPing)) { $HopPingCount = 5 } else { $HopPingCount = [int]$inputPing }
    } else {
        if ($ScanLevel -in @('Medium', 'Deep')) {
            $inputPing = Read-Host "`n -> Rota analizi için Hop başına Ping paket sayısı [Varsayılan: 5]"
            if ([string]::IsNullOrWhiteSpace($inputPing)) { $HopPingCount = 5 } else { $HopPingCount = [int]$inputPing }
        } else {
            $HopPingCount = 1
        }

        Write-Host "`n-------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host " HARİCİ JMETER TEST DOSYASI (OPSİYONEL):" -ForegroundColor Yellow
        Write-Host " Elimde daha önce alınmış bir JMeter .jtl/.csv sonuç dosyası var diyorsanız girin." -ForegroundColor Gray
        Write-Host "-------------------------------------------------------------------------" -ForegroundColor Yellow
        $csvAns = Read-Host " -> Analize dahil edilecek CSV/JTL Dosya Yolu [Boş geçilebilir]"
        if (-not [string]::IsNullOrWhiteSpace($csvAns) -and (Test-Path $csvAns)) {
            $JMeterCsvPath = $csvAns
        }
    }

    $htmlAns = Read-Host "`n -> HTML Raporu kaydedilsin mi? (E/H) [Varsayılan: E]"
    if ([string]::IsNullOrWhiteSpace($htmlAns) -or $htmlAns -match '^[EeYy]') {
        $defaultPath = "C:\scripts\NetworkReport_$($Target -replace '[^a-zA-Z0-9]','_').html"
        $inputPath = Read-Host " -> Kayıt Yolu [Varsayılan: $defaultPath]"
        if ([string]::IsNullOrWhiteSpace($inputPath)) { $ExportHtmlPath = $defaultPath } else { $ExportHtmlPath = $inputPath }
    }
}

if (-not $Port) { $Port = 443 }
if (-not $ScanLevel) { $ScanLevel = 'Deep' }
if (-not $HopPingCount) { $HopPingCount = 5 }

# --- YARDIMCI FONKSİYONLAR ---
function Write-LogHeader ($text) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Write-Status ($step, $status, $color) {
    Write-Host "[$step] " -NoNewline -ForegroundColor Gray
    Write-Host "$status" -ForegroundColor $color
}

function Get-StandardDeviation ($values) {
    if (-not $values -or $values.Count -lt 2) { return 0 }
    $avg = ($values | Measure-Object -Average).Average
    $sumOfSquares = 0
    foreach ($v in $values) { $sumOfSquares += [Math]::Pow(($v - $avg), 2) }
    return [Math]::Round([Math]::Sqrt($sumOfSquares / ($values.Count - 1)), 2)
}

function Get-Percentile ($sortedArray, $percentile) {
    if (-not $sortedArray) { return 0 }
    $index = [math]::Ceiling(($percentile / 100) * $sortedArray.Count) - 1
    if ($index -lt 0) { $index = 0 }
    return $sortedArray[$index]
}

$ReportData = [ordered]@{}
$AdvisorNotes = [System.Collections.Generic.List[string]]::new()
$AnalysisSummaryText = [System.Text.StringBuilder]::new()

$ReportData["Script_Version"] = "v$ScriptVersion"
$ReportData["Target"] = $Target
$ReportData["Port"] = $Port
$ReportData["ScanLevel"] = $ScanLevel
$ReportData["Timestamp"] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

# ---------------------------------------------------------------------------
# ADIM 0: SİSTEM, DONANIM VE KULLANICI ENVANTERİ TOPLAMA
# ---------------------------------------------------------------------------
Write-LogHeader "0. KULLANICI, DONANIM VE SİSTEM ENVANTERİ"

try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
    
    $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    if (-not $netAdapters) {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    $computerName = $env:COMPUTERNAME
    $osName = if ($osInfo) { $osInfo.Caption.Trim() } else { "Bilinmiyor" }
    
    $totalRamGB = if ($osInfo) { [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 1) } else { 0 }
    $freeRamGB = if ($osInfo) { [math]::Round($osInfo.FreePhysicalMemory / 1MB, 1) } else { 0 }
    $usedRamGB = [math]::Round($totalRamGB - $freeRamGB, 1)
    $ramUsagePercent = if ($totalRamGB -gt 0) { [math]::Round(($usedRamGB / $totalRamGB) * 100) } else { 0 }

    $cpuLoad = if ($cpuInfo.LoadPercentage) { $cpuInfo.LoadPercentage } else { (Get-CimInstance Win32_Processor).LoadPercentage }
    if (-not $cpuLoad) { $cpuLoad = "N/A" }

    $diskSummary = @()
    foreach ($d in $diskInfo) {
        $dSize = [math]::Round($d.Size / 1GB, 1)
        $dFree = [math]::Round($d.FreeSpace / 1GB, 1)
        $dUsedPct = [math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100)
        $diskSummary += "$($d.DeviceID) (Toplam: ${dSize}GB, Boş: ${dFree}GB, Doluluk: %${dUsedPct})"
    }
    $diskText = $diskSummary -join " | "

    $localIp = "Bilinmiyor"
    if ($netAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceAlias $netAdapters.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ipConfig) { $localIp = $ipConfig.IPAddress }
    }

    $ReportData["Env_User"] = $currentUser
    $ReportData["Env_ComputerName"] = $computerName
    $ReportData["Env_OS"] = $osName
    $ReportData["Env_CPU"] = "$($cpuInfo.Name) (Anlık Kullanım: %$cpuLoad)"
    $ReportData["Env_Memory"] = "Toplam: ${totalRamGB}GB | Kullanılan: ${usedRamGB}GB (%$ramUsagePercent)"
    $ReportData["Env_Disk"] = $diskText
    $ReportData["Env_LocalIP"] = "$localIp ($($netAdapters.Name))"

    Write-Status "ENV" "Kullanıcı: $currentUser | PC: $computerName" Green
    Write-Status "ENV" "CPU: %$cpuLoad | RAM: %$ramUsagePercent Kullanımda (${usedRamGB}/${totalRamGB} GB)" Green
    Write-Status "ENV" "Yerel IP: $localIp | Adaptör: $($netAdapters.Name)" Green
} catch {
    Write-Status "ENV" "Donanım envanteri alınırken hata oluştu: $_" Yellow
}

Write-LogHeader "AĞ DIAGNOSTIC FRAMEWORK BAŞLATILDI: [$Target]"
Write-Host "Seçilen Tarama Modu: $ScanLevel | Port: $Port" -ForegroundColor Green

# ---------------------------------------------------------------------------
# ADIM 1: MULTI-DNS, PTR VE CDN / PROXY TESPİTİ
# ---------------------------------------------------------------------------
Write-LogHeader "1. MULTI-RESOLVER DNS, PTR VE CDN/WAF TESPİTİ"

$targetIP = $Target
$isCDN = $false
$cdnName = "Yok / Doğrudan Sunucu"

try {
    $dnsRecords = Resolve-DnsName -Name $Target -ErrorAction Stop
    [string[]]$localIpv4 = $dnsRecords | Where-Object { $_.IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -ExpandProperty IPAddress
    
    if ($localIpv4.Count -gt 0) { $targetIP = $localIpv4[0] }
    Write-Status "DNS-LOCAL" "Yerel DNS IPv4 Yanıtı: $targetIP" Green
    $ReportData["Local_DNS_IP"] = $targetIP

    if ($targetIP -match '^(172\.(6[4-7]|7[0-1])|104\.(1[6-9]|2[0-7])|162\.158)\.') {
        $isCDN = $true
        $cdnName = "Cloudflare CDN / Reverse Proxy"
    } elseif ($targetIP -match '^(13|52|54)\.') {
        $cname = ($dnsRecords | Where-Object { $_.Type -eq 'CNAME' }).NameHost
        if ($cname -match 'cloudfront|akamai|fastly|cloudflare') {
            $isCDN = $true
            $cdnName = "CDN Provider ($cname)"
        }
    }

    if ($isCDN) {
        Write-Status "CDN-DETECT" "HEDEF REVERSE PROXY / CDN ARKASINDA: $cdnName" Yellow
        $AdvisorNotes.Add("[i] CDN TESPİT EDİLDİ: Target $cdnName arkasında duruyor. Port taramalarında standart TCP yanıtları Proxy tarafından yakalanabilir.")
    } else {
        Write-Status "CDN-DETECT" "Doğrudan Sunucu Bağlantısı (CDN İmzası Yok)" Green
    }
    $ReportData["CDN_Status"] = $cdnName

    if ($ScanLevel -in @('Medium', 'Deep', 'JMeter')) {
        try {
            $publicDns = Resolve-DnsName -Name $Target -Server "8.8.8.8" -ErrorAction SilentlyContinue
            [string[]]$publicIpv4 = $publicDns | Where-Object { $_.IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | Select-Object -ExpandProperty IPAddress
            
            if ($publicIpv4.Count -gt 0) {
                Write-Status "DNS-PUBLIC" "Public DNS (8.8.8.8) Yanıtı: $($publicIpv4[0])" Green
                $ReportData["Public_DNS_IP"] = $publicIpv4[0]

                if ($targetIP -ne $publicIpv4[0]) {
                    Write-Status "DNS-WARN" "Yerel DNS ile Public DNS yanıtı EŞLEŞMİYOR!" Yellow
                    $AdvisorNotes.Add("[!] DNS MISMATCH: Yerel DNS ($targetIP) ile Public DNS ($($publicIpv4[0])) farklı IP veriyor. Split-DNS durumunu inceleyin.")
                }
            }
        } catch {}
    }

    try {
        $ptrRecord = (Resolve-DnsName -Name $targetIP -Type PTR -ErrorAction SilentlyContinue).NameHost
        if ($ptrRecord) {
            Write-Status "PTR" "Reverse DNS: $ptrRecord" Green
            $ReportData["Reverse_DNS"] = $ptrRecord
        }
    } catch {}

} catch {
    Write-Status "DNS" "DNS Çözümlenemedi veya Doğrudan IP Girildi." Yellow
    $ReportData["Local_DNS_IP"] = $Target
}

# ---------------------------------------------------------------------------
# ADIM 2: ICMP PING VE PATH MTU DISCOVERY
# ---------------------------------------------------------------------------
Write-LogHeader "2. ICMP PING VE PATH MTU ANALİZİ"

$unloadedPing = Test-Connection -ComputerName $targetIP -Count 4 -ErrorAction SilentlyContinue
$unloadedAvgRtt = 0

if ($unloadedPing) {
    $unloadedRttArray = $unloadedPing | ForEach-Object {
        if ($_.PSObject.Properties['Latency']) { $_.Latency }
        elseif ($_.PSObject.Properties['ResponseTime']) { $_.ResponseTime }
        else { 0 }
    }
    $unloadedAvgRtt = [math]::Round(($unloadedRttArray | Measure-Object -Average).Average, 1)
    Write-Status "PING" "Boştaki Ortalama Latency: ${unloadedAvgRtt} ms" Green
    $ReportData["Unloaded_Avg_RTT"] = "${unloadedAvgRtt} ms"
} else {
    Write-Status "PING" "ICMP Ping Yanıt Vermiyor." Red
}

$mtuSizes = @(1500, 1492, 1472, 1420, 1280)
$maxWorkingMtu = 0

foreach ($size in $mtuSizes) {
    $payloadSize = $size - 28
    if ($payloadSize -lt 32) { continue }
    $pingMtu = Test-Connection -ComputerName $targetIP -Count 1 -BufferSize $payloadSize -DontFragment -ErrorAction SilentlyContinue
    if ($pingMtu) { $maxWorkingMtu = $size; break }
}

if ($maxWorkingMtu -gt 0) {
    Write-Status "MTU" "Maksimum Güvenli MTU: $maxWorkingMtu Byte" Green
    $ReportData["Path_MTU"] = "$maxWorkingMtu Byte"
}

# ---------------------------------------------------------------------------
# ADIM 3: SOKET VE PORT ANALİZİ
# ---------------------------------------------------------------------------
if ($ScanLevel -in @('Medium', 'Deep', 'JMeter')) {
    Write-LogHeader "3. HIZLI SERVİS PORT MATRİSİ TARAMASI"
    $commonPorts = if ($ScanLevel -in @('Deep', 'JMeter')) { @(80, 443, 22, 3389, 53, 445) } else { @(80, 443, $Port) }
    $badgeList = [System.Collections.Generic.List[string]]::new()

    foreach ($cp in ($commonPorts | Select-Object -Unique)) {
        $tClient = New-Object System.Net.Sockets.TcpClient
        try {
            $ar = $tClient.BeginConnect($Target, $cp, $null, $null)
            $w = $ar.AsyncWaitHandle.WaitOne(1200, $false)
            
            if ($w -and $tClient.Connected) {
                if ($isCDN -and $cp -notin @(80, 443)) {
                    $stream = $tClient.GetStream()
                    $stream.ReadTimeout = 1000
                    $buffer = New-Object byte[] 256
                    try {
                        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                        if ($bytesRead -gt 0) {
                            Write-Host "  Port $cp : " -NoNewline
                            Write-Host "AÇIK (L7 Banner Doğrulandı)" -ForegroundColor Green
                            $badgeList.Add("<span class='badge badge-open'>Port ${cp}: OPEN</span>")
                        } else {
                            Write-Host "  Port $cp : " -NoNewline
                            Write-Host "KAPALI (Proxy Intercept)" -ForegroundColor Red
                            $badgeList.Add("<span class='badge badge-closed'>Port ${cp}: CLOSED</span>")
                        }
                    } catch {
                        Write-Host "  Port $cp : " -NoNewline
                        Write-Host "KAPALI (Proxy Intercept)" -ForegroundColor Red
                        $badgeList.Add("<span class='badge badge-closed'>Port ${cp}: CLOSED</span>")
                    }
                } else {
                    Write-Host "  Port $cp : " -NoNewline
                    Write-Host "AÇIK" -ForegroundColor Green
                    $badgeList.Add("<span class='badge badge-open'>Port ${cp}: OPEN</span>")
                }
            } else {
                Write-Host "  Port $cp : " -NoNewline
                Write-Host "ZAMAN AŞIMI (DROP/FIREWALL)" -ForegroundColor DarkGray
                $badgeList.Add("<span class='badge badge-drop'>Port ${cp}: DROP</span>")
            }
        } catch {
            Write-Host "  Port $cp : " -NoNewline
            Write-Host "KAPALI (REJECT)" -ForegroundColor Red
            $badgeList.Add("<span class='badge badge-closed'>Port ${cp}: REJECT</span>")
        } finally {
            $tClient.Close()
            $tClient.Dispose()
        }
    }
    $ReportData["Port_Matrix"] = ($badgeList -join " ")
}

# ---------------------------------------------------------------------------
# ADIM 4: ROTA VE JİTTER ANALİZİ
# ---------------------------------------------------------------------------
$RouteReportRows = [System.Collections.Generic.List[PSObject]]::new()
$maxJitterVal = 0

if ($ScanLevel -in @('Medium', 'Deep', 'JMeter')) {
    Write-LogHeader "4. HOP KATMANLI MTR, JITTER VE ROTA ANALİZİ"
    $tracert = Test-NetConnection -ComputerName $targetIP -TraceRoute

    if ($tracert.TraceRoute) {
        $hops = $tracert.TraceRoute
        Write-Host "Toplam $($hops.Count) Hop Tespit Edildi. $HopPingCount paket ile Jitter analizi yapılıyor...`n" -ForegroundColor Yellow

        Write-Host ("{0,-4} {1,-18} {2,-8} {3,-8} {4,-8} {5,-8} {6,-10} {7,-14}" -f "Hop", "IP Adresi", "Min", "Max", "Ort", "Jitter", "Kayıp", "Durum") -ForegroundColor Cyan
        Write-Host ("{0,-4} {1,-18} {2,-8} {3,-8} {4,-8} {5,-8} {6,-10} {7,-14}" -f "----", "------------------", "--------", "--------", "--------", "--------", "----------", "--------------") -ForegroundColor Cyan

        $previousRtt = 0
        $hopIndex = 1

        foreach ($hopIp in $hops) {
            if ([string]::IsNullOrWhiteSpace($hopIp) -or $hopIp -eq "..." -or $hopIp -eq "0.0.0.0" -or $hopIp -eq "::") {
                Write-Host ("{0,-4} {1,-18} {2,-8} {3,-8} {4,-8} {5,-8} {6,-10} {7,-14}" -f $hopIndex, "Gizli/Yanıtsız (*)", "N/A", "N/A", "N/A", "N/A", "100%", "Cevap Yok") -ForegroundColor DarkGray
                $RouteReportRows.Add([PSCustomObject]@{ Hop = $hopIndex; IP = "Gizli/Yanıtsız (*)"; Min = "N/A"; Max = "N/A"; Avg = "N/A"; Jitter = "N/A"; Loss = "100%"; Status = "Cevap Yok"; CssClass = "failed" })
                $hopIndex++
                continue
            }

            $pings = Test-Connection -ComputerName $hopIp -Count $HopPingCount -ErrorAction SilentlyContinue
            
            if ($pings) {
                $successfulPings = ($pings | Measure-Object).Count
                $lossPercent = [math]::Round((( $HopPingCount - $successfulPings ) / $HopPingCount) * 100)
                
                $rttArray = $pings | ForEach-Object {
                    if ($_.PSObject.Properties['Latency']) { $_.Latency }
                    elseif ($_.PSObject.Properties['ResponseTime']) { $_.ResponseTime }
                    else { 0 }
                }

                $stats = $rttArray | Measure-Object -Minimum -Maximum -Average
                $minRtt = [math]::Round($stats.Minimum)
                $maxRtt = [math]::Round($stats.Maximum)
                $avgHopRtt = [math]::Round($stats.Average, 1)
                $jitter = Get-StandardDeviation -values $rttArray

                if ($jitter -gt $maxJitterVal) { $maxJitterVal = $jitter }

                $statusStr = "Stabil (OK)"
                $statusColor = "Green"
                $cssClass = "success"

                if ($hopIndex -le 3 -and $jitter -gt 10) {
                    $AdvisorNotes.Add("[!] YEREL AĞ JITTER: Hop $hopIndex ($hopIp) üzerinde yerel ağ dalgalanması var (±${jitter}ms). Switch/Firewall bufferbloat kontrolü yapın.")
                }

                if ($jitter -gt 15) { $statusStr = "YÜKSEK JİTTER"; $statusColor = "Yellow"; $cssClass = "warning" }
                if ($previousRtt -gt 0 -and ($avgHopRtt - $previousRtt) -gt 35) { $statusStr = "LATENCY SIÇRAMASI"; $statusColor = "Yellow"; $cssClass = "warning" }
                if ($lossPercent -gt 0) { $statusStr = "PAKET KAYBI (%$lossPercent)"; $statusColor = "Red"; $cssClass = "danger" }

                Write-Host ("{0,-4} {1,-18} {2,-8} {3,-8} {4,-8} {5,-8} {6,-10} " -f $hopIndex, $hopIp, "${minRtt}ms", "${maxRtt}ms", "${avgHopRtt}ms", "±${jitter}ms", "%$lossPercent") -NoNewline
                Write-Host ("{0,-14}" -f $statusStr) -ForegroundColor $statusColor

                $RouteReportRows.Add([PSCustomObject]@{ Hop = $hopIndex; IP = $hopIp; Min = "${minRtt} ms"; Max = "${maxRtt} ms"; Avg = "${avgHopRtt} ms"; Jitter = "±${jitter} ms"; Loss = "%$lossPercent"; Status = $statusStr; CssClass = $cssClass })
                $previousRtt = $avgHopRtt
            } else {
                Write-Host ("{0,-4} {1,-18} {2,-8} {3,-8} {4,-8} {5,-8} {6,-10} {7,-14}" -f $hopIndex, $hopIp, "N/A", "N/A", "N/A", "N/A", "100%", "ICMP Engeli") -ForegroundColor DarkGray
                $RouteReportRows.Add([PSCustomObject]@{ Hop = $hopIndex; IP = $hopIp; Min = "N/A"; Max = "N/A"; Avg = "N/A"; Jitter = "N/A"; Loss = "100%"; Status = "ICMP Engeli"; CssClass = "failed" })
            }
            $hopIndex++
        }
    }
}

# ---------------------------------------------------------------------------
# ADIM 5: SEVİYE 4 - APACHE JMETER MODE (NATIVE C# ENGINE)
# ---------------------------------------------------------------------------
$jmeterP95Val = 0
$jmeterErrRateVal = 0

if ($ScanLevel -eq 'JMeter') {
    Write-LogHeader "5. APACHE JMETER MODU: EŞZAMANLI YÜK, RPS & ASSERTION TESTİ"
    
    $protocol = if ($Port -in @(443, 8443)) { "https" } else { "http" }
    $url = "${protocol}://${Target}:${Port}"

    Write-Host "JMeter Test Senaryosu Başlatılıyor:" -ForegroundColor Yellow
    Write-Host "  -> Hedef URL            : $url" -ForegroundColor White
    Write-Host "  -> Eşzamanlı Threads   : $JMeterThreads Sanal Kullanıcı" -ForegroundColor White
    Write-Host "  -> Toplam İstek Sayısı : $JMeterTotalRequests Request" -ForegroundColor White
    if ($JMeterAssertText) { Write-Host "  -> Assertion Metni      : '$JMeterAssertText'" -ForegroundColor White }
    Write-Host ""

    $cCode = @"
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Net.Http;
    using System.Threading.Tasks;

    public class JRunner {
        public class Result {
            public double Latency { get; set; }
            public bool Success { get; set; }
            public bool AssertErr { get; set; }
            public string Error { get; set; }
        }

        public static ConcurrentBag<Result> RunTest(string url, int totalRequests, int threads, string assertStr) {
            var bag = new ConcurrentBag<Result>();
            
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            using (var client = new HttpClient(handler)) {
                client.Timeout = TimeSpan.FromSeconds(5);
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36");

                Parallel.For(0, totalRequests, new ParallelOptions { MaxDegreeOfParallelism = threads }, i => {
                    var sw = Stopwatch.StartNew();
                    var resObj = new Result { Success = false, AssertErr = false, Error = "" };

                    try {
                        var responseTask = client.GetAsync(url);
                        responseTask.Wait();
                        var response = responseTask.Result;
                        sw.Stop();

                        resObj.Latency = sw.ElapsedMilliseconds;

                        if (response != null) {
                            resObj.Success = true;
                            if (!string.IsNullOrEmpty(assertStr)) {
                                var bodyTask = response.Content.ReadAsStringAsync();
                                bodyTask.Wait();
                                if (!bodyTask.Result.Contains(assertStr)) {
                                    resObj.Success = false;
                                    resObj.AssertErr = true;
                                    resObj.Error = "AssertionFailed";
                                }
                            }
                        }
                    } catch (Exception ex) {
                        sw.Stop();
                        resObj.Latency = sw.ElapsedMilliseconds;
                        resObj.Success = false;
                        resObj.Error = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                    }

                    bag.Add(resObj);
                });
            }

            return bag;
        }
    }
"@

    if (-not ("JRunner" -as [type])) {
        Add-Type -TypeDefinition $cCode -Language CSharp
    }

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    $rawResults = [JRunner]::RunTest($url, $JMeterTotalRequests, $JMeterThreads, $JMeterAssertText)
    $swTotal.Stop()

    $totalTimeSec = [math]::Round($swTotal.Elapsed.TotalSeconds, 2)
    $results = $rawResults.ToArray()

    $successCount = ($results | Where-Object { $_.Success -eq $true }).Count
    $failCount = ($results | Where-Object { $_.Success -eq $false }).Count
    $assertionFailCount = ($results | Where-Object { $_.AssertErr -eq $true }).Count

    $latencyList = $results | Select-Object -ExpandProperty Latency | Sort-Object
    
    $avgLatency = if ($latencyList) { [math]::Round(($latencyList | Measure-Object -Average).Average, 1) } else { 0 }
    $minLatency = if ($latencyList) { $latencyList[0] } else { 0 }
    $maxLatency = if ($latencyList) { $latencyList[-1] } else { 0 }

    $p50 = Get-Percentile -sortedArray $latencyList -percentile 50
    $p90 = Get-Percentile -sortedArray $latencyList -percentile 90
    $p95 = Get-Percentile -sortedArray $latencyList -percentile 95

    $jmeterP95Val = $p95
    $rps = if ($totalTimeSec -gt 0) { [math]::Round(($JMeterTotalRequests / $totalTimeSec), 2) } else { 0 }
    $errorRate = if ($JMeterTotalRequests -gt 0) { [math]::Round(($failCount / $JMeterTotalRequests) * 100, 1) } else { 0 }
    $jmeterErrRateVal = $errorRate

    Write-Status "JMETEER-SUMMARY" "Toplam Sürat: ${totalTimeSec} saniye | RPS (Throughput): $rps req/sec" Green
    Write-Status "JMETEER-STATS" "Başarılı (Sunucu Yanıt Verdi): $successCount | Bağlantı/Zaman Aşımı Hatası: $failCount | Hata Oranı: %$errorRate" $(if($errorRate -gt 5){'Red'}else{'Green'})
    if ($JMeterAssertText) { Write-Status "ASSERTION" "Assertion Başarısızlığı: $assertionFailCount" $(if($assertionFailCount -gt 0){'Red'}else{'Green'}) }

    Write-Host "`n Latency Dağılımı (Percentiles):" -ForegroundColor Cyan
    Write-Host "   -> Min / Max / Ort : ${minLatency}ms / ${maxLatency}ms / ${avgLatency}ms" -ForegroundColor White
    Write-Host "   -> p50 (Median)   : ${p50} ms" -ForegroundColor White
    Write-Host "   -> p90            : ${p90} ms" -ForegroundColor White
    Write-Host "   -> p95            : ${p95} ms" -ForegroundColor White

    $ReportData["JMeter_Threads"] = "$JMeterThreads Concurrent Users"
    $ReportData["JMeter_Total_Requests"] = "$JMeterTotalRequests"
    $ReportData["JMeter_Throughput_RPS"] = "$rps req/sec"
    $ReportData["JMeter_Avg_Latency"] = "${avgLatency} ms"
    $ReportData["JMeter_p90_Latency"] = "${p90} ms"
    $ReportData["JMeter_p95_Latency"] = "${p95} ms"
    $ReportData["JMeter_Error_Rate"] = "%$errorRate ($failCount / $JMeterTotalRequests)"
}

# HARİCİ CSV / JTL AYRIŞTIRMA (VARSA)
if ($JMeterCsvPath -and (Test-Path $JMeterCsvPath)) {
    Write-LogHeader "HARİCİ JMETER CSV/JTL ANALİZİ"
    try {
        $csvResults = Import-Csv -Path $JMeterCsvPath
        if ($csvResults) {
            $csvTotal = $csvResults.Count
            $csvElapseds = $csvResults.elapsed | ForEach-Object { [double]$_ } | Sort-Object
            $csvAvg = [math]::Round(($csvElapseds | Measure-Object -Average).Average, 1)
            $csvP95 = Get-Percentile -sortedArray $csvElapseds -percentile 95
            
            $jmeterP95Val = $csvP95
            Write-Status "CSV-JMETER" "Harici Dosya Okundu ($csvTotal Kayıt) | Ort: ${csvAvg}ms | p95: ${csvP95}ms" Green
            $ReportData["Ext_JMeter_File"] = (Split-Path $JMeterCsvPath -Leaf)
            $ReportData["Ext_JMeter_p95"] = "${csvP95} ms"
        }
    } catch {
        Write-Status "CSV-JMETER" "CSV/JTL Dosyası Okunamadı." Red
    }
}

# ---------------------------------------------------------------------------
# ADIM 6: WEB, SSL & WAF ANALİZİ
# ---------------------------------------------------------------------------
if ($ScanLevel -eq 'Deep' -and $Port -in @(80, 443, 8080, 8443)) {
    Write-LogHeader "6. WEB UYGULAMA, SSL & WAF/HEADER ANALİZİ"
    $protocol = if ($Port -in @(443, 8443)) { "https" } else { "http" }
    $url = "${protocol}://${Target}:${Port}"

    if ($protocol -eq "https") {
        try {
            $tcpClientCert = New-Object System.Net.Sockets.TcpClient($targetIP, $Port)
            $sslStream = New-Object System.Net.Security.SslStream($tcpClientCert.GetStream(), $false, ({ $true }))
            $sslStream.AuthenticateAsClient($Target)
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate

            if ($cert2) {
                $daysLeft = [math]::Round(($cert2.NotAfter - (Get-Date)).TotalDays)
                Write-Status "SSL" "Sertifika Yayıncısı: $($cert2.Issuer)" Green
                Write-Status "SSL" "Kalan Süre: $daysLeft Gün (Bitiş: $($cert2.NotAfter.ToString('yyyy-MM-dd')))" Green
                $ReportData["SSL_Issuer"] = $cert2.Issuer
                $ReportData["SSL_Days_Left"] = "$daysLeft Gün"
            }
            $sslStream.Close()
            $tcpClientCert.Close()
        } catch { Write-Status "SSL" "SSL Sertifikası Çekilemedi." Red }
    }

    try {
        $swHttp = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $webParams = @{ Uri = $url; Method = 'Get'; TimeoutSec = 5; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -ge 7) { $webParams["SkipHttpErrorCheck"] = $true }

        $webRequest = Invoke-WebRequest @webParams
        $swHttp.Stop()
        $ttfb = $swHttp.ElapsedMilliseconds

        Write-Status "HTTP" "Status Code: $($webRequest.StatusCode)" Green
        Write-Status "TTFB" "Time To First Byte (TTFB): ${ttfb} ms" Green
        $ReportData["HTTP_Code"] = "$($webRequest.StatusCode)"
        $ReportData["HTTP_TTFB"] = "${ttfb} ms"
    } catch { Write-Status "HTTP" "Web Yanıtı Alınamadı." Red }
}

# ---------------------------------------------------------------------------
# ADIM 7: KÖK NEDEN VE ÇAPRAZ KORELASYON ANALİZ MOTORU
# ---------------------------------------------------------------------------
Write-LogHeader "7. KÖK NEDEN VE ÇAPRAZ KORELASYON ANALİZİ"

[void]$AnalysisSummaryText.AppendLine("<b>[Sistem Mimarisi Ve Performans Değerlendirmesi]</b><br>")

if ($maxJitterVal -lt 10) {
    if ($jmeterP95Val -gt 1000 -or $jmeterErrRateVal -gt 5) {
        [void]$AnalysisSummaryText.AppendLine("<b>DARBOĞAZ TESPİTİ: [Sunucu / Uygulama Katmanı]</b><br>")
        [void]$AnalysisSummaryText.AppendLine("Ağ katmanında Jitter (±${maxJitterVal}ms) ve Paket Kaybı son derece düşük ve stabil kalmasına rağmen; yük testinde p95 yanıt sürelerinde (${jmeterP95Val}ms) ve/veya Hata Oranında (%${jmeterErrRateVal}) belirgin bir yükseliş gözlemlendi.<br>")
        [void]$AnalysisSummaryText.AppendLine("<b>Kök Neden:</b> Sorun network altyapısında değil; IIS Worker Process kilitlenmeleri, SQL Server veritabanı lock'ları, Connection Pool tükenmesi veya sunucu CPU/RAM kaynaklarının yetersizliğinden kaynaklanmaktadır.")
        $AdvisorNotes.Add("[!] UYGULAMA DARBOĞAZI: Ağ stabil ancak uygulama p95 süresi ${jmeterP95Val}ms. Sunucu CPU/RAM ve DB pool ayarlarını inceleyin.")
    } else {
        [void]$AnalysisSummaryText.AppendLine("<b>SİSTEM PERFORMANSI: [MÜKEMMEL / STABİL]</b><br>")
        [void]$AnalysisSummaryText.AppendLine("Hem Ağ Katmanı gecikme sapmaları (Jitter: ±${maxJitterVal}ms) sınırların altında son derece stabil seyretmekte, hem de uygulama yük testi (p95: ${jmeterP95Val}ms) SLA limitleri içerisinde başarıyla yanıt vermektedir.<br>")
        [void]$AnalysisSummaryText.AppendLine("Sistemde herhangi bir network veya sunucu taraflı darboğaz tespit edilmemiştir.")
    }
} else {
    if ($jmeterP95Val -gt 1000) {
        [void]$AnalysisSummaryText.AppendLine("<b>DARBOĞAZ TESPİTİ: [Ağ / Altyapı Katmanı]</b><br>")
        [void]$AnalysisSummaryText.AppendLine("Ağ katmanındaki yüksek Jitter (±${maxJitterVal}ms) ve hat üzerindeki paket dalgalanmaları, yük testindeki uygulama yanıt sürelerini (p95: ${jmeterP95Val}ms) doğrudan olumsuz etkilemektedir.<br>")
        [void]$AnalysisSummaryText.AppendLine("<b>Kök Neden:</b> Router/Switch üzerindeki paket kuyruklama sorunları (Bufferbloat), ISS kaynaklı hat dalgalanmaları veya QoS yapılandırması eksikliği.")
        $AdvisorNotes.Add("[!] AĞ DARBOĞAZI: Yüksek Network Jitter (±${maxJitterVal}ms) uygulama gecikmesini tetikliyor. Switch/QoS kontrolü yapın.")
    } else {
        [void]$AnalysisSummaryText.AppendLine("<b>AĞ UYARISI: [Lokal Dalgalanma]</b><br>")
        [void]$AnalysisSummaryText.AppendLine("Ağ üzerinde ±${maxJitterVal}ms seviyesinde Jitter (dalgalanma) görülmesine rağmen uygulama katmanı yanıt sürelerini tolere edebilmiştir.")
    }
}

Write-Host ($AnalysisSummaryText.ToString() -replace '<br>','`n' -replace '<b>','' -replace '</b>','') -ForegroundColor Yellow

if ($ExportHtmlPath) {
    Write-LogHeader "HTML DASHBOARD OLUŞTURULUYOR"
    
    $displayNames = @{
        "Script_Version"        = "NetDiag Script Sürümü"
        "Env_User"              = "Oturum Açan Kullanıcı"
        "Env_ComputerName"      = "İstemci Bilgisayar Adı"
        "Env_OS"                = "İşletim Sistemi Sürümü"
        "Env_CPU"               = "Donanım CPU Bilgisi"
        "Env_Memory"            = "Sistem Bellek (RAM) Durumu"
        "Env_Disk"              = "Sabit Disk (Storage) Durumu"
        "Env_LocalIP"           = "Ağ Adaptörü & Yerel IP"
        "Target"                = "Hedef Sunucu / Domain"
        "Port"                  = "Hedef Port"
        "ScanLevel"             = "Tarama Seviyesi"
        "Timestamp"             = "Rapor Tarihi"
        "Local_DNS_IP"          = "Yerel DNS IPv4 Adresi"
        "CDN_Status"            = "CDN / Reverse Proxy Durumu"
        "Public_DNS_IP"         = "Public DNS (8.8.8.8) IPv4"
        "Reverse_DNS"           = "Reverse DNS (PTR) Kaydı"
        "Unloaded_Avg_RTT"      = "Boştaki Ortalama Latency (RTT)"
        "Path_MTU"              = "Maksimum Güvenli MTU"
        "Port_Matrix"           = "Port Erişilebilirlik Matrisi"
        "SSL_Issuer"            = "SSL Sertifika Yayıncısı"
        "SSL_Days_Left"         = "SSL Kalan Geçerlilik Süresi"
        "HTTP_Code"             = "HTTP Yanıt Kodu (Status Code)"
        "HTTP_TTFB"             = "Time To First Byte (TTFB)"
        "JMeter_Threads"        = "Eşzamanlı Sanal Kullanıcı (Threads)"
        "JMeter_Total_Requests" = "Toplam Gönderilen İstek"
        "JMeter_Throughput_RPS" = "Saniyedeki İşlem Hızı (RPS / Throughput)"
        "JMeter_Avg_Latency"    = "JMeter Ortalama Latency"
        "JMeter_p90_Latency"    = "Percentile p90 Latency"
        "JMeter_p95_Latency"    = "Percentile p95 Latency"
        "JMeter_Error_Rate"     = "Bağlantı / İstek Hata Oranı"
        "Ext_JMeter_File"       = "Harici JMeter Sonuç Dosyası"
        "Ext_JMeter_p95"        = "Harici JMeter p95 Yanıt Süresi"
    }

    $routeTableRowsHtml = ""
    foreach ($row in $RouteReportRows) {
        $routeTableRowsHtml += @"
        <tr class="$($row.CssClass)">
            <td><b>$($row.Hop)</b></td>
            <td>$($row.IP)</td>
            <td>$($row.Min)</td>
            <td>$($row.Max)</td>
            <td><b>$($row.Avg)</b></td>
            <td>$($row.Jitter)</td>
            <td>$($row.Loss)</td>
            <td>$($row.Status)</td>
        </tr>
"@
    }

    $summaryRowsHtml = ""
    foreach ($item in $ReportData.GetEnumerator()) {
        $keyName = $item.Key
        $friendlyTitle = if ($displayNames.ContainsKey($keyName)) { $displayNames[$keyName] } else { $keyName }
        $val = $item.Value

        $summaryRowsHtml += "<tr><td><b>$friendlyTitle</b></td><td>$val</td></tr>`n"
    }

    $advisorRowsHtml = ""
    foreach ($adv in $AdvisorNotes) {
        $advisorRowsHtml += "<div class='advisor-item'>$adv</div>`n"
    }

    $htmlContent = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Network & Infrastructure Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 25px; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        h2 { color: #005a9e; border-bottom: 2px solid #005a9e; padding-bottom: 10px; margin-top: 0; }
        h3 { color: #333; margin-top: 25px; font-size: 18px; }
        table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }
        th, td { padding: 10px 14px; border: 1px solid #e1e4e8; text-align: left; }
        th { background-color: #0078d4; color: white; font-weight: 600; }
        tr:nth-child(even) { background-color: #f9fafb; }
        .advisor-box { background-color: #fff8e1; border-left: 5px solid #ffc107; padding: 15px; border-radius: 4px; margin-top: 15px; }
        .analysis-box { background-color: #ebf8ff; border-left: 5px solid #0078d4; padding: 18px; border-radius: 4px; margin-top: 15px; font-size: 14px; line-height: 1.6; }
        .advisor-item { font-weight: 600; color: #795548; margin-bottom: 6px; }
        .badge { padding: 4px 9px; border-radius: 4px; font-size: 12px; font-weight: bold; display: inline-block; margin: 2px; }
        .badge-open { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .badge-closed { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .badge-drop { background-color: #e2e3e5; color: #383d41; border: 1px solid #d6d8db; }
        .success { background-color: #e6f4ea !important; color: #137333; }
        .warning { background-color: #fef7e0 !important; color: #b06000; font-weight: bold; }
        .danger { background-color: #fce8e6 !important; color: #c5221f; font-weight: bold; }
        .failed { background-color: #f1f3f4 !important; color: #5f6368; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Kurumsal Teşhis & Performance Raporu ($ScanLevel Scan)</h2>
        
        <div class="analysis-box">
            $($AnalysisSummaryText.ToString())
        </div>

        <div class="advisor-box">
            <h3 style="margin-top:0; color:#b78103;">Aksiyon & Sistem Uyarıları</h3>
            $advisorRowsHtml
        </div>

        <h3>Genel Sistem Metrikleri & Donanım Envanteri</h3>
        <table>
            <thead>
                <tr><th>Parametre</th><th>Değer</th></tr>
            </thead>
            <tbody>
                $summaryRowsHtml
            </tbody>
        </table>

        $([string]::IsNullOrWhiteSpace($routeTableRowsHtml) ? "" : @"
        <h3>Hop Katmanlı MTR, Jitter & Rota Analizi</h3>
        <table>
            <thead>
                <tr>
                    <th>Hop</th>
                    <th>IP Adresi</th>
                    <th>Min</th>
                    <th>Max</th>
                    <th>Ort (RTT)</th>
                    <th>Jitter (Sapma)</th>
                    <th>Paket Kaybı</th>
                    <th>Durum</th>
                </tr>
            </thead>
            <tbody>
                $routeTableRowsHtml
            </tbody>
        </table>
"@)
    </div>
</body>
</html>
"@
    $htmlContent | Out-File -FilePath $ExportHtmlPath -Encoding utf8
    Write-Host "Rapor Başarıyla Oluşturuldu: $ExportHtmlPath" -ForegroundColor Green
}

Write-LogHeader "DIAGNOSTIC TAMAMLANDI"
