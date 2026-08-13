<#
.SYNOPSIS
    Advanced network diagnostic, TCP port scanning, route/jitter analysis,
    HTTP load testing, SSL inspection, hardware inventory and HTML reporting.
.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7+ on Windows.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)][string]$Target,
    [Parameter(Position=1)][ValidateRange(1,65535)][int]$Port = 443,
    [ValidateSet('Low','Medium','Deep','JMeter')][string]$ScanLevel = 'Deep',
    [ValidateRange(1,100)][int]$HopPingCount = 5,
    [switch]$EnableLoadTest,
    [ValidateRange(1,1000)][int]$JMeterThreads = 10,
    [ValidateRange(1,1000000)][int]$JMeterTotalRequests = 50,
    [string]$JMeterAssertText,
    [string]$JMeterCsvPath,
    [string]$ExportHtmlPath,
    [switch]$CheckUpdate,
    [ValidateRange(100,30000)][int]$TcpTimeoutMs = 1500,
    [ValidateRange(1,60)][int]$HttpTimeoutSec = 5,
    [ValidateRange(100,5000)][int]$PingTimeoutMs = 1200,
    [ValidateRange(0,5000)][int]$PingIntervalMs = 150,
    [ValidateRange(5,500)][int]$DestinationPingCount = 20,
    [ValidateRange(0,10000)][int]$JMeterWarmupRequests = 5,
    [ValidateRange(0,300)][int]$JMeterRampUpSeconds = 2,
    [ValidateRange(0,60000)][int]$JMeterThinkTimeMs = 0,
    [ValidateRange(1024,104857600)][int]$JMeterMaxResponseBytes = 10485760,
    [ValidateSet('GET','HEAD')][string]$JMeterHttpMethod = 'GET',
    [ValidateSet('Auto','tr','en')][string]$Language = 'Auto'
)

# --- LANGUAGE DETECTION AND LOCALIZATION ---
$SystemUICulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
if ($Language -eq 'Auto') {
    switch -Regex ($SystemUICulture) {
        '^tr-TR$' { $Script:LanguageCode = 'tr'; break }
        '^en-US$' { $Script:LanguageCode = 'en'; break }
        '^tr'     { $Script:LanguageCode = 'tr'; break }
        default   { $Script:LanguageCode = 'en' }
    }
} else {
    $Script:LanguageCode = $Language
}

$Script:EnglishTranslations = [ordered]@{
    'KULLANICI, DONANIM VE SİSTEM ENVANTERİ'='USER, HARDWARE AND SYSTEM INVENTORY'
    'DNS, PTR VE CDN TESPİTİ'='DNS, PTR AND CDN DETECTION'
    'ICMP PING, HEDEF JITTER VE PATH MTU ANALİZİ'='ICMP PING, DESTINATION JITTER AND PATH MTU ANALYSIS'
    'TCP SERVİS PORT MATRİSİ'='TCP SERVICE PORT MATRIX'
    'HOP KATMANLI ROTA VE JITTER ANALİZİ'='HOP-BY-HOP ROUTE AND JITTER ANALYSIS'
    'GELİŞMİŞ HTTP EŞZAMANLI YÜK TESTİ'='ADVANCED CONCURRENT HTTP LOAD TEST'
    'WEB, SSL VE HTTP ANALİZİ'='WEB, SSL AND HTTP ANALYSIS'
    'KÖK NEDEN VE ÇAPRAZ KORELASYON'='ROOT CAUSE AND CROSS-CORRELATION'
    'HTML RAPOR OLUŞTURULUYOR'='GENERATING HTML REPORT'
    'DIAGNOSTIC TAMAMLANDI'='DIAGNOSTIC COMPLETED'
    'Güncellemeler kontrol ediliyor'='Checking for updates'
    'Script güncel'='Script is up to date'
    'Yeni sürüm bulundu'='New version found'
    'Güncellensin mi?'='Update now?'
    'Güncellendi; aynı parametrelerle yeniden başlatılıyor.'='Updated; restarting with the same parameters.'
    'Kontrol başarısız'='Update check failed'
    'Geçersiz commit yanıtı.'='Invalid commit response.'
    'İndirilen içerik PowerShell scripti görünmüyor.'='Downloaded content does not appear to be a PowerShell script.'
    'Yeni sürüm parse doğrulamasından geçemedi'='The new version failed PowerShell parser validation'
    'Test edilecek hedef (domain veya IP)'='Target to test (domain or IP)'
    'TCP port'='TCP port'
    'Seviye'='Level'
    'Hop başına ping'='Pings per hop'
    'Eşzamanlı kullanıcı'='Concurrent users'
    'Toplam istek'='Total requests'
    'Assertion metni'='Assertion text'
    'Hedef jitter paket sayısı'='Destination jitter packet count'
    'Warm-up istek sayısı'='Warm-up request count'
    'Ramp-up süresi saniye'='Ramp-up duration in seconds'
    'Harici JTL/CSV yolu'='External JTL/CSV path'
    'HTML rapor kaydedilsin mi?'='Save HTML report?'
    'Yol'='Path'
    'opsiyonel'='optional'
    'Geçersiz port.'='Invalid port.'
    'Envanter kısmen alınamadı'='Inventory could only be collected partially'
    'Bilinmiyor'='Unknown'
    'Aktif adaptör belirlenemedi'='Active adapter could not be detected'
    'IPv4 A kaydı bulunamadı.'='No IPv4 A record was found.'
    'Ölçülemedi'='Could not be measured'
    'Yanıt alınamadı'='No response received'
    'Yok / Doğrudan Sunucu'='None / Direct server'
    'CDN/reverse proxy tespit edildi; görülen port ve gecikme değerleri origin sunucuyu temsil etmeyebilir.'='CDN/reverse proxy detected; observed port and latency values may not represent the origin server.'
    'DNS çözümlenemedi; hedefe bağlı ağ testleri atlandı.'='DNS resolution failed; target-dependent network tests were skipped.'
    'Yanıt alındı'='Response received'
    'Yanıt yok / filtrelenmiş olabilir'='No response / possibly filtered'
    'ICMP yanıtı yok; hedef kapalı kabul edilmeyecek.'='No ICMP response; the target will not be considered offline.'
    'En büyük başarılı DF IP MTU tahmini'='Largest successful DF IP MTU estimate'
    'Ölçülemedi; ICMP veya DF paketleri filtreleniyor olabilir.'='Could not be measured; ICMP or DF packets may be filtered.'
    'ICMP/DF doğrulanamadı'='ICMP/DF could not be verified'
    'Test edilmedi'='Not tested'
    'Erişilebilir - ICMP filtreli'='Reachable - ICMP filtered'
    'Erişilebilir - ICMP ve TCP'='Reachable - ICMP and TCP'
    'başarılı'='successful'
    'Host erişilebilir'='Host reachable'
    'kapalı veya filtreli'='closed or filtered'
    'Doğrulanamadı'='Could not be verified'
    'yanıtı yok'='no response'
    'Ping kapalı ancak'='Ping unavailable but'
    'handshake başarılı; hedef servis erişilebilir.'='handshake succeeded; target service is reachable.'
    'Hedef ICMP yanıtlıyor ancak'='The target responds to ICMP but'
    'erişimi başarısız; listener/firewall kontrol edin.'='access failed; check the listener/firewall.'
    'Hedef kapalı sonucu kesin değildir; firewall DROP, routing ve servis durumunu kontrol edin.'='The target cannot conclusively be considered offline; check firewall DROP, routing, and service status.'
    'Gizli/Yanıtsız (*)'='Hidden/Unresponsive (*)'
    'ICMP yanıtlamıyor'='No ICMP response'
    'Stabil'='Stable'
    'Hedef yanıt kaybı'='Destination response loss'
    'Ara hop ICMP yanıt kaybı'='Intermediate-hop ICMP response loss'
    'Hedefte yüksek jitter'='High jitter at destination'
    'Ara hop ICMP varyasyonu'='Intermediate-hop ICMP variation'
    'Hedefte orta jitter'='Moderate jitter at destination'
    'Ara hopta orta varyasyon'='Moderate intermediate-hop variation'
    'Ortalama değişim'='Mean variation'
    'Kayıp'='Loss'
    'Hatalı'='Failed'
    'Hata'='Error'
    'Toplam'='Total'
    'Ort'='Avg'
    'saniye'='seconds'
    'Hata yok'='No errors'
    '[Sistem Mimarisi ve Performans Değerlendirmesi]'='[System Architecture and Performance Assessment]'
    'SONUÇ: YETERSİZ ÖLÇÜM'='RESULT: INSUFFICIENT MEASUREMENT'
    'Hedef ICMP kalite metrikleri ve HTTP yük metrikleri alınamadığından kesin korelasyon yapılamadı.'='No definitive correlation could be made because destination ICMP quality and HTTP load metrics were unavailable.'
    'OLASI AĞ KALİTESİ SORUNU'='POSSIBLE NETWORK QUALITY ISSUE'
    'AĞ VE UYGULAMA GECİKMESİ KORELASYONU'='NETWORK AND APPLICATION LATENCY CORRELATION'
    'OLASI SUNUCU VEYA UYGULAMA DARBOĞAZI'='POSSIBLE SERVER OR APPLICATION BOTTLENECK'
    'AĞ DEĞİŞKENLİĞİ VAR, UYGULAMA ETKİLENMEMİŞ'='NETWORK VARIATION DETECTED, APPLICATION UNAFFECTED'
    'ÖLÇÜLEN DEĞERLER NORMAL'='MEASURED VALUES ARE NORMAL'
    'AĞ KALİTESİ ÖLÇÜLDÜ'='NETWORK QUALITY MEASURED'
    'UYGULAMA ÖLÇÜLDÜ, AĞ METRİĞİ SINIRLI'='APPLICATION MEASURED, NETWORK METRICS LIMITED'
    'Bazı ara hoplarda yüksek ICMP yanıt değişkenliği görülmesine rağmen son hedef jitter değeri düşüktür. Ara hop değişkenliği uçtan uca trafik bozulması olarak doğrulanmamıştır.'='Some intermediate hops show high ICMP response variation, but destination jitter is low. The intermediate-hop variation was not confirmed as end-to-end traffic degradation.'
    'NetDiag Ağ, Sistem ve Uygulama Teşhis Raporu'='NetDiag Network, System and Application Diagnostic Report'
    'Hedef'='Target'
    'Tarama'='Scan'
    'Önerilen Aksiyonlar ve Sistem Uyarıları'='Recommended Actions and System Warnings'
    'Ek uyarı yok.'='No additional warnings.'
    'Genel Sistem, Ağ ve Uygulama Metrikleri'='General System, Network and Application Metrics'
    'Hop Katmanlı Rota, Gecikme ve Jitter Analizi'='Hop-by-Hop Route, Latency and Jitter Analysis'
    'Medyan'='Median'
    'Durum'='Status'
    'NetDiag Script Sürümü'='NetDiag Script Version'
    'Hedef Sunucu / Domain'='Target Server / Domain'
    'Hedef TCP Portu'='Target TCP Port'
    'Tarama Seviyesi'='Scan Level'
    'Rapor Tarihi'='Report Date'
    'Oturum Açan Kullanıcı'='Signed-in User'
    'İstemci Bilgisayar Adı'='Client Computer Name'
    'İşletim Sistemi'='Operating System'
    'CPU Bilgisi ve Kullanımı'='CPU Information and Usage'
    'Sistem Belleği (RAM)'='System Memory (RAM)'
    'Disk Kullanımı'='Disk Usage'
    'Aktif Ağ Adaptörü ve Yerel IP'='Active Network Adapter and Local IP'
    'Yerel DNS IPv4 Sonucu'='Local DNS IPv4 Result'
    'Google Public DNS IPv4 Sonucu'='Google Public DNS IPv4 Result'
    'Cloudflare DNS IPv4 Sonucu'='Cloudflare DNS IPv4 Result'
    'Yerel DNS Sorgu Süresi'='Local DNS Query Time'
    'Yetkili DNS Sunucuları'='Authoritative DNS Servers'
    'Reverse DNS (PTR) Kaydı'='Reverse DNS (PTR) Record'
    'CDN / Reverse Proxy Durumu'='CDN / Reverse Proxy Status'
    'ICMP Ping Durumu'='ICMP Ping Status'
    'Gönderilen ICMP Paketi'='ICMP Packets Sent'
    'Yanıtlanan ICMP Paketi'='ICMP Packets Received'
    'Hedef ICMP Yanıt Kaybı'='Destination ICMP Response Loss'
    'Hedef Minimum RTT'='Destination Minimum RTT'
    'Boştaki Ortalama Gecikme (RTT)'='Idle Average Latency (RTT)'
    'Hedef Medyan RTT'='Destination Median RTT'
    'Hedef p95 RTT'='Destination p95 RTT'
    'Hedef Maksimum RTT'='Destination Maximum RTT'
    'Hedef RTT Standart Sapması'='Destination RTT Standard Deviation'
    'Hedef Ortalama Jitter'='Destination Mean Jitter'
    'Hedef Peak Jitter'='Destination Peak Jitter'
    'Hedef Yumuşatılmış RTT Değişimi'='Destination Smoothed RTT Variation'
    'Path MTU Tahmini'='Path MTU Estimate'
    'TCP Port Erişilebilirlik Matrisi'='TCP Port Reachability Matrix'
    'Seçilen Portun Durumu'='Selected Port Status'
    'Açık Port Sayısı'='Open Port Count'
    'Test Edilen Port Sayısı'='Tested Port Count'
    'Genel Erişilebilirlik Durumu'='Overall Reachability Status'
    'HTTP Yük Test Motoru'='HTTP Load Test Engine'
    'HTTP Metodu'='HTTP Method'
    'Eşzamanlı Sanal Kullanıcı'='Concurrent Virtual Users'
    'Ölçülen En Yüksek Eşzamanlı İstek'='Measured Peak Concurrent Requests'
    'Ramp-up Süresi'='Ramp-up Duration'
    'Warm-up İstek Sayısı'='Warm-up Request Count'
    'Toplam HTTP İsteği'='Total HTTP Requests'
    'Başarılı HTTP İsteği'='Successful HTTP Requests'
    'Başarısız HTTP İsteği'='Failed HTTP Requests'
    'Toplam Yük Testi Süresi'='Total Load Test Duration'
    'HTTP İşlem Hızı (RPS)'='HTTP Throughput (RPS)'
    'Ortalama Header / TTFB Süresi'='Average Header / TTFB Time'
    'p95 Header / TTFB Süresi'='p95 Header / TTFB Time'
    'Ortalama Response İndirme Süresi'='Average Response Download Time'
    'Ortalama Toplam HTTP Süresi'='Average Total HTTP Time'
    'HTTP Süre Standart Sapması'='HTTP Time Standard Deviation'
    'p50 Toplam HTTP Süresi'='p50 Total HTTP Time'
    'p75 Toplam HTTP Süresi'='p75 Total HTTP Time'
    'p90 Toplam HTTP Süresi'='p90 Total HTTP Time'
    'p95 Toplam HTTP Süresi'='p95 Total HTTP Time'
    'p99 Toplam HTTP Süresi'='p99 Total HTTP Time'
    'HTTP Hata Oranı'='HTTP Error Rate'
    'HTTP Durum Kodu Dağılımı'='HTTP Status Code Distribution'
    'HTTP Hata Tipi Dağılımı'='HTTP Error Type Distribution'
    'Toplam Alınan Response Verisi'='Total Response Data Received'
    'Ortalama Response Boyutu'='Average Response Size'
    'Response Veri Aktarım Hızı'='Response Data Throughput'
    'SSL Sertifika Konusu'='SSL Certificate Subject'
    'SSL Sertifika Yayıncısı'='SSL Certificate Issuer'
    'SSL Kalan Geçerlilik Süresi'='SSL Remaining Validity'
    'Rapor Dili'='Report Language'
    'Sistem Arayüz Kültürü'='System UI Culture'
    'Türkçe'='Turkish'
    'Bu araç DNS, ICMP, MTU, TCP portları, rota/jitter ve isteğe bağlı HTTP yük testlerini çalıştırır.'='This tool runs DNS, ICMP, MTU, TCP port, route/jitter, and optional HTTP load tests.'
    'Güncelleme mevcut. Yerel sürüm'='An update is available. Local version'
    'uzak sürüm'='remote version'
    'Güncelleme mevcut script dosyasını doğruladıktan sonra değiştirecektir.'='The update will replace the current script only after validation.'
    'Test edilecek DNS adı veya IPv4 adresi. Örnek: example.com veya 10.0.0.10'='DNS name or IPv4 address to test. Example: example.com or 10.0.0.10'
    'Hedef servisin TCP portu. HTTPS için 443, HTTP için 80.'='TCP port of the target service. Use 443 for HTTPS or 80 for HTTP.'
    'Test seviyesini seçin:'='Select a test level:'
    'Hızlı erişilebilirlik: envanter, DNS, ICMP, MTU ve seçilen TCP portu.'='Quick reachability: inventory, DNS, ICMP, MTU, and the selected TCP port.'
    'Standart ağ analizi: Low testlerine ek olarak temel port matrisi ve rota/jitter.'='Standard network analysis: Low tests plus a basic port matrix and route/jitter.'
    'Ayrıntılı teşhis: geniş port matrisi, rota/jitter, SSL ve HTTP analizi.'='Detailed diagnostics: extended port matrix, route/jitter, SSL, and HTTP analysis.'
    'Yük testi: Deep ağ ölçümlerine ek olarak gelişmiş eşzamanlı HTTP testi.'='Load test: Deep network measurements plus an advanced concurrent HTTP test.'
    'Her rota adımına gönderilecek ICMP paketi sayısı. Daha yüksek değer daha güvenilir fakat daha yavaştır.'='Number of ICMP packets sent to each route hop. Higher values are more reliable but slower.'
    'Aynı anda gönderilebilecek en yüksek HTTP isteği sayısı.'='Maximum number of HTTP requests that may be sent concurrently.'
    'Ana yük testi boyunca gönderilecek toplam HTTP isteği.'='Total HTTP requests sent during the main load test.'
    'Yanıt gövdesinde aranacak metin. Boş bırakılırsa içerik doğrulaması yapılmaz.'='Text to search for in the response body. Leave blank to skip content validation.'
    'Uçtan uca RTT ve jitter için hedefe gönderilecek ICMP paketi sayısı.'='Number of ICMP packets sent to the destination for end-to-end RTT and jitter.'
    'Ölçüme dahil edilmeyen, bağlantı ve önbellekleri hazırlayan istek sayısı.'='Requests excluded from measurements and used to warm connections and caches.'
    'Eşzamanlı yükün kademeli olarak artırılacağı süre.'='Time over which concurrent load is gradually increased.'
    'Rapor; ölçümleri, korelasyon sonucunu, uyarıları ve hop tablosunu içerir.'='The report includes measurements, correlation results, warnings, and the hop table.'
    'Oluşturulan geçici rapor dosyası boş.'='The generated temporary report file is empty.'
    'Rapor doğrulaması başarısız.'='Report verification failed.'
    'Beklenen boyut'='Expected size'
    'yazılan'='written'
    'Mevcut raporun üzerine yazıldı'='Existing report overwritten'
    'Yeni rapor oluşturuldu'='New report created'
    'Rapor yazılamadı'='Report could not be written'
    'HTTP Yanıt Kodu'='HTTP Status Code'
    'Toplam HTTP Yanıt Süresi'='Total HTTP Response Time'
}

function ConvertTo-LocalizedText([object]$Text) {
    if ($null -eq $Text) { return '' }

    $result = [string]$Text
    if ($Script:LanguageCode -eq 'tr') { return $result }

    # PowerShell hash keys and UI text comparisons are case-insensitive.
    # Sort longer phrases first so a short translation cannot corrupt a longer one.
    $entries = @(
        $Script:EnglishTranslations.GetEnumerator() |
            Sort-Object { ([string]$_.Key).Length } -Descending
    )

    foreach ($entry in $entries) {
        $escapedKey = [System.Text.RegularExpressions.Regex]::Escape(
            [string]$entry.Key
        )

        # Do not translate a key when it occurs inside another word.
        # Example: 'Ort' must not alter 'Port' or 'Report'.
        $pattern = '(?<![\p{L}\p{N}_])' + $escapedKey + '(?![\p{L}\p{N}_])'
        $replacement = [string]$entry.Value

        $result = [System.Text.RegularExpressions.Regex]::Replace(
            $result,
            $pattern,
            [System.Text.RegularExpressions.MatchEvaluator]{
                param($match)
                return $replacement
            },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    return $result
}

function Test-NetDiagSyntax([string]$Path) {
    $syntaxTokens = $null
    $syntaxErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$syntaxTokens,
        [ref]$syntaxErrors
    ) | Out-Null
    return @($syntaxErrors)
}
function Get-LocalizedYesNoLabel {
    if ($Script:LanguageCode -eq 'tr') { return 'E/H' }
    return 'Y/N'
}
function Get-LocalizedDefaultYesLabel {
    if ($Script:LanguageCode -eq 'tr') { return 'E' }
    return 'Y'
}
function Test-LocalizedYesResponse([string]$Answer,[bool]$DefaultYes=$false) {
    if ([string]::IsNullOrWhiteSpace($Answer)) { return $DefaultYes }
    $value = $Answer.Trim()
    if ($Script:LanguageCode -eq 'tr') { return ($value -match '^(?i:e|evet)$') }
    return ($value -match '^(?i:y|yes)$')
}
function Test-LocalizedNoResponse([string]$Answer) {
    if ([string]::IsNullOrWhiteSpace($Answer)) { return $false }
    $value = $Answer.Trim()
    if ($Script:LanguageCode -eq 'tr') { return ($value -match '^(?i:h|hayır|hayir)$') }
    return ($value -match '^(?i:n|no)$')
}

function Read-LocalizedHost([string]$Prompt) {
    return Read-Host (ConvertTo-LocalizedText $Prompt)
}

$CurrentCommit = 'ad71321'
$GitHubApiUrl = 'https://api.github.com/repos/oguska/netdiag/commits/main'
$GitHubRawUrl = 'https://raw.githubusercontent.com/oguska/netdiag/refs/heads/main/netdiag.ps1'

function Write-LogHeader([string]$Text) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "  $(ConvertTo-LocalizedText $Text)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}
function Write-Status([string]$Step,[string]$Status,[ConsoleColor]$Color='Gray') {
    Write-Host "[$Step] " -NoNewline -ForegroundColor Gray
    Write-Host (ConvertTo-LocalizedText $Status) -ForegroundColor $Color
}
function ConvertTo-HtmlSafe([object]$Value) {
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
function Get-StandardDeviation([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $avg = ($Values | Measure-Object -Average).Average
    $sum = 0.0
    foreach ($v in $Values) { $sum += [Math]::Pow(($v-$avg),2) }
    return [Math]::Round([Math]::Sqrt($sum/($Values.Count-1)),2)
}
function Get-Percentile([double[]]$SortedArray,[double]$Percentile) {
    if (-not $SortedArray -or $SortedArray.Count -eq 0) { return $null }
    $i = [Math]::Ceiling(($Percentile/100)*$SortedArray.Count)-1
    if ($i -lt 0) { $i=0 }
    return $SortedArray[$i]
}
function Get-PingLatency([object]$PingObject) {
    if ($null -ne $PingObject.PSObject.Properties['Latency']) { return [double]$PingObject.Latency }
    if ($null -ne $PingObject.PSObject.Properties['ResponseTime']) { return [double]$PingObject.ResponseTime }
    return $null
}
function Get-PopulationStandardDeviation([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $average = ($Values | Measure-Object -Average).Average
    $sum = 0.0
    foreach ($value in $Values) { $sum += [Math]::Pow(($value - $average),2) }
    return [Math]::Round([Math]::Sqrt($sum / $Values.Count),2)
}
function Get-MeanAbsoluteDelta([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $deltas = @()
    for ($i=1; $i -lt $Values.Count; $i++) { $deltas += [Math]::Abs($Values[$i]-$Values[$i-1]) }
    return [Math]::Round(($deltas | Measure-Object -Average).Average,2)
}
function Get-PeakAbsoluteDelta([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $peak=0.0
    for ($i=1; $i -lt $Values.Count; $i++) { $d=[Math]::Abs($Values[$i]-$Values[$i-1]);if($d -gt $peak){$peak=$d} }
    return [Math]::Round($peak,2)
}
function Get-SmoothedRttVariation([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $variation=0.0
    for ($i=1; $i -lt $Values.Count; $i++) { $d=[Math]::Abs($Values[$i]-$Values[$i-1]);$variation+=($d-$variation)/16.0 }
    return [Math]::Round($variation,2)
}
function Invoke-PingProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName,[int]$Count=10,[int]$TimeoutMs=1200,[int]$IntervalMs=150,[int]$PayloadSize=32,[switch]$DontFragment)
    $samples=New-Object 'System.Collections.Generic.List[object]'
    $latencies=New-Object 'System.Collections.Generic.List[double]'
    $pinger=New-Object System.Net.NetworkInformation.Ping
    try {
        for($sequence=1;$sequence -le $Count;$sequence++){
            $buffer=New-Object byte[] $PayloadSize
            $options=New-Object System.Net.NetworkInformation.PingOptions
            $options.DontFragment=$DontFragment.IsPresent;$options.Ttl=128
            try {
                $reply=$pinger.Send($ComputerName,$TimeoutMs,$buffer,$options)
                $success=$reply.Status-eq[System.Net.NetworkInformation.IPStatus]::Success
                $rtt=if($success){[double]$reply.RoundtripTime}else{$null}
                if($null -ne $rtt){$latencies.Add($rtt)}
                $samples.Add([pscustomobject]@{Sequence=$sequence;Timestamp=Get-Date;Success=$success;RTT=$rtt;Status=$reply.Status.ToString()})
            } catch {$samples.Add([pscustomobject]@{Sequence=$sequence;Timestamp=Get-Date;Success=$false;RTT=$null;Status=$_.Exception.Message})}
            if($IntervalMs-gt0 -and $sequence -lt $Count){Start-Sleep -Milliseconds $IntervalMs}
        }
    } finally {$pinger.Dispose()}
    $ok=$latencies.Count;$failed=$Count-$ok;$loss=[Math]::Round(($failed/[double]$Count)*100,1)
    if($ok-eq0){return [pscustomobject]@{ComputerName=$ComputerName;Attempted=$Count;Successful=0;Failed=$failed;LossPercent=$loss;Min=$null;Average=$null;Median=$null;P95=$null;Max=$null;StandardDeviation=$null;MeanJitter=$null;PeakJitter=$null;SmoothedVariation=$null;Samples=$samples.ToArray();RTTValues=@()}}
    [double[]]$ordered=@($latencies.ToArray()|Sort-Object)
    [double[]]$sequenceValues=$latencies.ToArray()
    return [pscustomobject]@{ComputerName=$ComputerName;Attempted=$Count;Successful=$ok;Failed=$failed;LossPercent=$loss;Min=[Math]::Round($ordered[0],2);Average=[Math]::Round(($ordered|Measure-Object -Average).Average,2);Median=[Math]::Round((Get-Percentile $ordered 50),2);P95=[Math]::Round((Get-Percentile $ordered 95),2);Max=[Math]::Round($ordered[-1],2);StandardDeviation=(Get-PopulationStandardDeviation $sequenceValues);MeanJitter=(Get-MeanAbsoluteDelta $sequenceValues);PeakJitter=(Get-PeakAbsoluteDelta $sequenceValues);SmoothedVariation=(Get-SmoothedRttVariation $sequenceValues);Samples=$samples.ToArray();RTTValues=$sequenceValues}
}
function Test-TcpPort {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName,[Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,[int]$TimeoutMs=1500)
    $client = New-Object System.Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ar = $client.BeginConnect($ComputerName,$Port,$null,$null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) {
            return [pscustomobject]@{Port=$Port;State='Filtered';TcpSucceeded=$false;LatencyMs=$null;Error='Timeout'}
        }
        try { $client.EndConnect($ar) }
        catch [Net.Sockets.SocketException] {
            $code=$_.Exception.SocketErrorCode
            $state=switch($code){'ConnectionRefused'{'Closed'}'HostUnreachable'{'Unreachable'}'NetworkUnreachable'{'Unreachable'}'TimedOut'{'Filtered'}default{'Error'}}
            return [pscustomobject]@{Port=$Port;State=$state;TcpSucceeded=$false;LatencyMs=$null;Error=$code.ToString()}
        }
        $sw.Stop()
        return [pscustomobject]@{Port=$Port;State='Open';TcpSucceeded=$true;LatencyMs=[Math]::Round($sw.Elapsed.TotalMilliseconds,1);Error=$null}
    } catch {
        return [pscustomobject]@{Port=$Port;State='Error';TcpSucceeded=$false;LatencyMs=$null;Error=$_.Exception.Message}
    } finally { $sw.Stop();$client.Close();$client.Dispose() }
}
function Test-ScriptUpdate {
    Write-Host '[*] Güncellemeler kontrol ediliyor...' -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $headers=@{'User-Agent'='NetDiag-PowerShell'}
        $response=Invoke-RestMethod -Uri $GitHubApiUrl -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $latest=[string]$response.sha
        if ($latest.Length -lt 7) { throw 'Geçersiz commit yanıtı.' }
        $latest=$latest.Substring(0,7)
        if ($CurrentCommit -eq $latest) { Write-Status UPDATE "Script güncel ($CurrentCommit)." Green;return }
        Write-Status UPDATE (ConvertTo-LocalizedText "Güncelleme mevcut. Yerel sürüm: $CurrentCommit | uzak sürüm: $latest") Yellow
        Write-Host (ConvertTo-LocalizedText '    Güncelleme mevcut script dosyasını doğruladıktan sonra değiştirecektir.') -ForegroundColor DarkGray
        $yesNoLabel = Get-LocalizedYesNoLabel
        $updateAnswer = Read-LocalizedHost " -> Güncellensin mi? ($yesNoLabel)"
        if (-not $Host.UI.RawUI -or -not (Test-LocalizedYesResponse -Answer $updateAnswer -DefaultYes $false)) { return }
        $tempFile=Join-Path ([IO.Path]::GetTempPath()) ("netdiag_{0}.ps1" -f [guid]::NewGuid().ToString('N'))
        try {
            $raw=(Invoke-WebRequest -Uri $GitHubRawUrl -Headers $headers -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop).Content
            if ([string]::IsNullOrWhiteSpace($raw) -or $raw -notmatch '(?i)CmdletBinding|param\s*\(') { throw 'İndirilen içerik PowerShell scripti görünmüyor.' }
            $raw=($raw -replace '(?<=CurrentCommit\s*=\s*["''])([a-f0-9]{7})(?=["''])',$latest)
            [IO.File]::WriteAllText($tempFile,$raw,(New-Object Text.UTF8Encoding($false)))
            $tokens=$null;$parseErrors=$null
            [Management.Automation.Language.Parser]::ParseFile($tempFile,[ref]$tokens,[ref]$parseErrors)|Out-Null
            if ($parseErrors.Count -gt 0) { throw "Yeni sürüm parse doğrulamasından geçemedi: $($parseErrors[0].Message)" }
            Copy-Item $tempFile $PSCommandPath -Force
            Write-Status UPDATE 'Güncellendi; aynı parametrelerle yeniden başlatılıyor.' Green
            $restart=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Target',$Target,'-Port',[string]$Port,'-ScanLevel',$ScanLevel,'-HopPingCount',[string]$HopPingCount,'-JMeterThreads',[string]$JMeterThreads,'-JMeterTotalRequests',[string]$JMeterTotalRequests,'-TcpTimeoutMs',[string]$TcpTimeoutMs,'-HttpTimeoutSec',[string]$HttpTimeoutSec,'-Language',$Script:LanguageCode)
            if ($JMeterAssertText) {$restart+=@('-JMeterAssertText',$JMeterAssertText)}
            if ($JMeterCsvPath) {$restart+=@('-JMeterCsvPath',$JMeterCsvPath)}
            if ($ExportHtmlPath) {$restart+=@('-ExportHtmlPath',$ExportHtmlPath)}
            Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $restart
            exit
        } finally { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
    } catch { Write-Status UPDATE "Kontrol başarısız: $($_.Exception.Message)" Yellow }
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    Clear-Host
    Write-Host '=================================================================================================' -ForegroundColor Cyan
    Write-Host "NetDiag - Network diagnostic, load test and inventory ($CurrentCommit)" -ForegroundColor Cyan
    Write-Host (ConvertTo-LocalizedText 'Bu araç DNS, ICMP, MTU, TCP portları, rota/jitter ve isteğe bağlı HTTP yük testlerini çalıştırır.') -ForegroundColor DarkGray
    Write-Host '=================================================================================================' -ForegroundColor Cyan
    Test-ScriptUpdate
    Write-Host (ConvertTo-LocalizedText '    Test edilecek DNS adı veya IPv4 adresi. Örnek: example.com veya 10.0.0.10') -ForegroundColor DarkGray
    do { $Target = Read-LocalizedHost ' -> Test edilecek hedef (domain veya IP)' } while ([string]::IsNullOrWhiteSpace($Target))
    Write-Host (ConvertTo-LocalizedText '    Hedef servisin TCP portu. HTTPS için 443, HTTP için 80.') -ForegroundColor DarkGray
    $v = Read-LocalizedHost ' -> TCP port [443]'
    if ($v) { if (-not [int]::TryParse($v,[ref]$Port) -or $Port -lt 1 -or $Port -gt 65535) { throw (ConvertTo-LocalizedText 'Geçersiz port.') } }
    Write-Host "`n$(ConvertTo-LocalizedText 'Test seviyesini seçin:')" -ForegroundColor Yellow
    Write-Host " [1] Low     - $(ConvertTo-LocalizedText 'Hızlı erişilebilirlik: envanter, DNS, ICMP, MTU ve seçilen TCP portu.')" -ForegroundColor White
    Write-Host " [2] Medium  - $(ConvertTo-LocalizedText 'Standart ağ analizi: Low testlerine ek olarak temel port matrisi ve rota/jitter.')" -ForegroundColor White
    Write-Host " [3] Deep    - $(ConvertTo-LocalizedText 'Ayrıntılı teşhis: geniş port matrisi, rota/jitter, SSL ve HTTP analizi.')" -ForegroundColor White
    Write-Host " [4] JMeter  - $(ConvertTo-LocalizedText 'Yük testi: Deep ağ ölçümlerine ek olarak gelişmiş eşzamanlı HTTP testi.')" -ForegroundColor White
    do {$v=Read-LocalizedHost ' -> Seviye [3]';if(-not $v){$v='3'}}while($v -notin @('1','2','3','4'))
    $ScanLevel=@{'1'='Low';'2'='Medium';'3'='Deep';'4'='JMeter'}[$v]
    if ($ScanLevel -ne 'Low') {
        Write-Host (ConvertTo-LocalizedText '    Her rota adımına gönderilecek ICMP paketi sayısı. Daha yüksek değer daha güvenilir fakat daha yavaştır.') -ForegroundColor DarkGray
        $v = Read-LocalizedHost ' -> Hop başına ping [5]'; if ($v) { $HopPingCount = [int]$v }
    }
    if($ScanLevel-eq'JMeter'){
        Write-Host (ConvertTo-LocalizedText '    Aynı anda gönderilebilecek en yüksek HTTP isteği sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Eşzamanlı kullanıcı [10]';if($v){$JMeterThreads=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Ana yük testi boyunca gönderilecek toplam HTTP isteği.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Toplam istek [50]';if($v){$JMeterTotalRequests=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Yanıt gövdesinde aranacak metin. Boş bırakılırsa içerik doğrulaması yapılmaz.') -ForegroundColor DarkGray
        $JMeterAssertText=Read-LocalizedHost ' -> Assertion metni [opsiyonel]'
        Write-Host (ConvertTo-LocalizedText '    Uçtan uca RTT ve jitter için hedefe gönderilecek ICMP paketi sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Hedef jitter paket sayısı [20]';if($v){$DestinationPingCount=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Ölçüme dahil edilmeyen, bağlantı ve önbellekleri hazırlayan istek sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Warm-up istek sayısı [5]';if($v){$JMeterWarmupRequests=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Eşzamanlı yükün kademeli olarak artırılacağı süre.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Ramp-up süresi saniye [2]';if($v){$JMeterRampUpSeconds=[int]$v}
    } else {
        $v=Read-LocalizedHost ' -> Harici JTL/CSV yolu [opsiyonel]';if($v-and(Test-Path $v)){$JMeterCsvPath=$v}
    }
    $yesNoLabel = Get-LocalizedYesNoLabel
    Write-Host (ConvertTo-LocalizedText '    Rapor; ölçümleri, korelasyon sonucunu, uyarıları ve hop tablosunu içerir.') -ForegroundColor DarkGray
    $defaultYesLabel = Get-LocalizedDefaultYesLabel
    $v = Read-LocalizedHost " -> HTML rapor kaydedilsin mi? ($yesNoLabel) [$defaultYesLabel]"
    if (Test-LocalizedYesResponse -Answer $v -DefaultYes $true) {
        $dir=if($PSScriptRoot){$PSScriptRoot}else{(Get-Location).Path}
        $default=Join-Path $dir ("NetworkReport_{0}.html" -f ($Target-replace'[^a-zA-Z0-9]','_'))
        $v=Read-LocalizedHost " -> Yol [$default]";$ExportHtmlPath=if($v){$v}else{$default}
    }
} elseif($CheckUpdate){Test-ScriptUpdate}

$ReportData=[ordered]@{Script_Version="Commit: $CurrentCommit";Language=if($Script:LanguageCode-eq'tr'){'Türkçe'}else{'English'};System_UICulture=$SystemUICulture;Yes_No_Format=(Get-LocalizedYesNoLabel);Target=$Target;Port=$Port;ScanLevel=$ScanLevel;Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')}
$AdvisorNotes=New-Object 'System.Collections.Generic.List[string]'
$RouteReportRows=New-Object 'System.Collections.Generic.List[object]'

Write-LogHeader '0. KULLANICI, DONANIM VE SİSTEM ENVANTERİ'
try {
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cpu=Get-CimInstance Win32_Processor -ErrorAction Stop|Select-Object -First 1
    $disks=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } |
        Sort-Object ifIndex |
        Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } |
            Sort-Object ifIndex |
            Select-Object -First 1
    }
    $ipObject = $null
    if ($adapter) {
        $ipObject = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
            Sort-Object PrefixOrigin |
            Select-Object -First 1
    }
    if (-not $ipObject) {
        $ipObject = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } |
            Select-Object -ExpandProperty IPv4Address |
            Where-Object { $_.IPAddress -notlike '169.254*' } |
            Select-Object -First 1
    }
    $ip = if ($ipObject) { $ipObject.IPAddress } else { 'Bilinmiyor' }
    $adapterName = if ($adapter) { $adapter.Name } else { 'Aktif adaptör belirlenemedi' }
    $cpuLoad = $cpu.LoadPercentage
    if ($null -eq $cpuLoad) {
        $cpuLoadSamples = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
            Where-Object { $null -ne $_.LoadPercentage } |
            Select-Object -ExpandProperty LoadPercentage)
        if ($cpuLoadSamples.Count -gt 0) {
            $cpuLoad = [Math]::Round(($cpuLoadSamples | Measure-Object -Average).Average)
        } else {
            $cpuLoad = 'N/A'
        }
    }
    $total=[Math]::Round($os.TotalVisibleMemorySize/1MB,1);$free=[Math]::Round($os.FreePhysicalMemory/1MB,1);$used=[Math]::Round($total-$free,1);$pct=if($total){[Math]::Round($used/$total*100)}else{0}
    $diskText=($disks|ForEach-Object{$size=[Math]::Round($_.Size/1GB,1);$df=[Math]::Round($_.FreeSpace/1GB,1);$dp=if($_.Size){[Math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100)}else{0};"$($_.DeviceID) (Toplam ${size}GB, Boş ${df}GB, Doluluk %$dp)"})-join' | '
    $ReportData.Env_User="$env:USERDOMAIN\$env:USERNAME";$ReportData.Env_ComputerName=$env:COMPUTERNAME;$ReportData.Env_OS=$os.Caption.Trim();$ReportData.Env_CPU="$($cpu.Name) (Anlık %$cpuLoad)";$ReportData.Env_Memory="Toplam ${total}GB | Kullanılan ${used}GB (%$pct)";$ReportData.Env_Disk=$diskText;$ReportData.Env_LocalIP="$ip ($adapterName)"
    Write-Status ENV "CPU %$cpuLoad | RAM %$pct | IP $ip" Green
} catch {Write-Status ENV "Envanter kısmen alınamadı: $($_.Exception.Message)" Yellow}

Write-LogHeader "1. DNS, PTR VE CDN TESPİTİ: [$Target]"
$targetIP=$null;$dnsOk=$false;$isCDN=$false;$cdnName='Yok / Doğrudan Sunucu';$dnsRecords=@()
try {
    $parsed=$null
    if([Net.IPAddress]::TryParse($Target,[ref]$parsed)){$targetIP=$parsed.IPAddressToString;$dnsOk=$true}
    else{$dnsRecords=@(Resolve-DnsName $Target -ErrorAction Stop);$ips=@($dnsRecords|Where-Object{$_.IPAddress -and $_.IPAddress-match'^\d{1,3}(\.\d{1,3}){3}$'}|Select-Object -ExpandProperty IPAddress -Unique);if($ips.Count-eq 0){throw 'IPv4 A kaydı bulunamadı.'};$targetIP=$ips[0];$dnsOk=$true;$ReportData.Local_DNS_IP=($ips-join', ')}
    Write-Status DNS "IPv4: $targetIP" Green
    $ReportData.Local_DNS_IP = if ($ReportData.Local_DNS_IP) { $ReportData.Local_DNS_IP } else { $targetIP }
    if ($Target -ne $targetIP) {
        $dnsWatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $null = Resolve-DnsName $Target -DnsOnly -ErrorAction Stop
            $dnsWatch.Stop()
            $ReportData.DNS_Query_Time = "$([Math]::Round($dnsWatch.Elapsed.TotalMilliseconds,1)) ms"
        } catch {
            $dnsWatch.Stop()
            $ReportData.DNS_Query_Time = 'Ölçülemedi'
        }
        try {
            $nsRecords = @(Resolve-DnsName $Target -Type NS -ErrorAction SilentlyContinue |
                Where-Object { $_.NameHost } | Select-Object -ExpandProperty NameHost -Unique)
            if ($nsRecords.Count -gt 0) { $ReportData.DNS_Name_Servers = $nsRecords -join ', ' }
        } catch {}
        try {
            $cloudflare = @(Resolve-DnsName $Target -Server '1.1.1.1' -Type A -ErrorAction Stop |
                Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique)
            if ($cloudflare.Count -gt 0) { $ReportData.Cloudflare_DNS_IP = $cloudflare -join ', ' }
        } catch {
            $ReportData.Cloudflare_DNS_IP = 'Yanıt alınamadı'
        }
    }
    $cname=($dnsRecords|Where-Object Type-eq'CNAME'|Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue)-join','
    if($targetIP-match'^(172\.(6[4-7]|7[0-1])|104\.(1[6-9]|2[0-7])|162\.158)\.'){$isCDN=$true;$cdnName='Cloudflare CDN / Reverse Proxy'}
    elseif($cname-match'cloudfront|akamai|fastly|cloudflare'){$isCDN=$true;$cdnName="CDN Provider ($cname)"}
    $ReportData.CDN_Status=$cdnName
    if($isCDN){Write-Status CDN $cdnName Yellow;$AdvisorNotes.Add('[i] CDN/reverse proxy tespit edildi; görülen port ve gecikme değerleri origin sunucuyu temsil etmeyebilir.')}
    if(($ScanLevel -in @('Medium','Deep','JMeter')) -and $Target -ne $targetIP){try{$pub=@(Resolve-DnsName $Target -Server 8.8.8.8 -ErrorAction Stop|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress -Unique);if($pub){$ReportData.Public_DNS_IP=$pub-join', ';if($targetIP -notin $pub){$AdvisorNotes.Add("[!] DNS MISMATCH: Yerel $targetIP, public $($pub-join', '). Split-DNS ihtimalini inceleyin.")}}}catch{}}
    try{$ptr=(Resolve-DnsName $targetIP -Type PTR -ErrorAction Stop).NameHost;if($ptr){$ReportData.Reverse_DNS=$ptr-join', '}}catch{}
} catch {$ReportData.Local_DNS_IP='Çözümlenemedi';Write-Status DNS $_.Exception.Message Red;$AdvisorNotes.Add('[!] DNS çözümlenemedi; hedefe bağlı ağ testleri atlandı.')}

$icmpAvailable=$false;$unloadedAvgRtt=$null;$maxWorkingMtu=$null
$destinationPingMetrics=$null;$destinationMeanJitter=$null;$destinationP95Rtt=$null;$destinationLossPercent=$null
if($dnsOk){
    Write-LogHeader '2. ICMP PING, HEDEF JITTER VE PATH MTU ANALİZİ'
    $destinationPingMetrics=Invoke-PingProbe -ComputerName $targetIP -Count $DestinationPingCount -TimeoutMs $PingTimeoutMs -IntervalMs $PingIntervalMs
    if($destinationPingMetrics.Successful-gt0){
        $icmpAvailable=$true;$unloadedAvgRtt=$destinationPingMetrics.Average;$destinationMeanJitter=$destinationPingMetrics.MeanJitter;$destinationP95Rtt=$destinationPingMetrics.P95;$destinationLossPercent=$destinationPingMetrics.LossPercent
        $ReportData.ICMP_Status='Yanıt alındı';$ReportData.ICMP_Sent=$destinationPingMetrics.Attempted;$ReportData.ICMP_Received=$destinationPingMetrics.Successful;$ReportData.ICMP_Loss="%$destinationLossPercent"
        $ReportData.Unloaded_Min_RTT="$($destinationPingMetrics.Min) ms";$ReportData.Unloaded_Avg_RTT="$($destinationPingMetrics.Average) ms";$ReportData.Unloaded_Median_RTT="$($destinationPingMetrics.Median) ms";$ReportData.Unloaded_p95_RTT="$($destinationPingMetrics.P95) ms";$ReportData.Unloaded_Max_RTT="$($destinationPingMetrics.Max) ms"
        $ReportData.Destination_RTT_StdDev="$($destinationPingMetrics.StandardDeviation) ms";$ReportData.Destination_Mean_Jitter="$($destinationPingMetrics.MeanJitter) ms";$ReportData.Destination_Peak_Jitter="$($destinationPingMetrics.PeakJitter) ms";$ReportData.Destination_Smoothed_Variation="$($destinationPingMetrics.SmoothedVariation) ms"
        Write-Status PING "Min $($destinationPingMetrics.Min) | Ort $($destinationPingMetrics.Average) | p95 $($destinationPingMetrics.P95) | Kayıp %$destinationLossPercent" Green
        Write-Status JITTER "Ortalama değişim ±$destinationMeanJitter ms | Peak ±$($destinationPingMetrics.PeakJitter) ms | Smoothed ±$($destinationPingMetrics.SmoothedVariation) ms" $(if($destinationMeanJitter-gt20 -or $destinationLossPercent-gt2){'Yellow'}else{'Green'})
    } else {
        $ReportData.ICMP_Status='Yanıt yok / filtrelenmiş olabilir';$ReportData.ICMP_Sent=$destinationPingMetrics.Attempted;$ReportData.ICMP_Received=0;$ReportData.ICMP_Loss='N/A';$ReportData.Unloaded_Avg_RTT='N/A';$ReportData.Destination_Mean_Jitter='N/A';Write-Status PING 'ICMP yanıtı yok; hedef kapalı kabul edilmeyecek.' Yellow
    }
    if($icmpAvailable){foreach ($size in @(1500,1492,1472,1460,1450,1420,1400,1380,1360,1280)){try{$mtuProbe=Invoke-PingProbe -ComputerName $targetIP -Count 1 -TimeoutMs $PingTimeoutMs -IntervalMs 0 -PayloadSize ($size-28) -DontFragment;if($mtuProbe.Successful-gt0){$maxWorkingMtu=$size;break}}catch{}}}
    if($maxWorkingMtu){$ReportData.Path_MTU="$maxWorkingMtu Byte (IP MTU tahmini)";Write-Status MTU "En büyük başarılı DF IP MTU tahmini: $maxWorkingMtu Byte" Green}else{$ReportData.Path_MTU='N/A - ICMP/DF doğrulanamadı';Write-Status MTU 'Ölçülemedi; ICMP veya DF paketleri filtreleniyor olabilir.' Yellow}
}

$portResults=New-Object 'System.Collections.Generic.List[object]';$targetTcpReachable=$false
if($dnsOk){
    Write-LogHeader '3. TCP SERVİS PORT MATRİSİ'
    $ports=switch($ScanLevel){'Low'{@($Port)}'Medium'{@(80,443,$Port)}default{@(80,443,22,3389,53,445,$Port)}}
    $badges=New-Object 'System.Collections.Generic.List[string]'
    foreach($cp in($ports|Select-Object -Unique)){
        $r=Test-TcpPort $Target $cp $TcpTimeoutMs;$portResults.Add($r);if($cp -eq $Port -and $r.TcpSucceeded){$targetTcpReachable=$true}
        $color=switch($r.State){'Open'{'Green'}'Closed'{'Red'}'Unreachable'{'Red'}default{'DarkGray'}}
        $detail=if($r.State-eq'Open'){"$($r.LatencyMs) ms"}else{$r.Error};Write-Status "TCP-$cp" "$($r.State) - $detail" $color
        $cls=switch($r.State){'Open'{'badge-open'}'Closed'{'badge-closed'}default{'badge-drop'}};$badges.Add("<span class='badge $cls'>Port ${cp}: $($r.State.ToUpper())</span>")
    }
    $ReportData.Port_Matrix = $badges -join ' '
    $primary = $portResults | Where-Object { $_.Port -eq $Port } | Select-Object -First 1
    $ReportData.Target_Port_Status = if ($primary) { "$($primary.State)" } else { 'Test edilmedi' }
    $ReportData.Open_Port_Count = @($portResults | Where-Object { $_.State -eq 'Open' }).Count
    $ReportData.Tested_Port_Count = $portResults.Count
    if(-not $icmpAvailable -and $targetTcpReachable){$ReportData.Reachability_Status="Erişilebilir - ICMP filtreli, TCP/$Port açık";$AdvisorNotes.Add("[i] Ping kapalı ancak TCP/$Port handshake başarılı; hedef servis erişilebilir.")}
    elseif($icmpAvailable -and $targetTcpReachable){$ReportData.Reachability_Status="Erişilebilir - ICMP ve TCP/$Port başarılı"}
    elseif($icmpAvailable){$ReportData.Reachability_Status="Host erişilebilir; TCP/$Port kapalı veya filtreli";$AdvisorNotes.Add("[!] Hedef ICMP yanıtlıyor ancak TCP/$Port erişimi başarısız; listener/firewall kontrol edin.")}
    else{$ReportData.Reachability_Status="Doğrulanamadı - ICMP ve TCP/$Port yanıtı yok";$AdvisorNotes.Add('[!] Hedef kapalı sonucu kesin değildir; firewall DROP, routing ve servis durumunu kontrol edin.')}
}

$maxJitterVal=$null;$routeMetricsAvailable=$false;$destinationHopJitter=$null
if($dnsOk-and($ScanLevel -in @('Medium','Deep','JMeter'))){
    Write-LogHeader '4. HOP KATMANLI ROTA VE JITTER ANALİZİ'
    try{$trace=Test-NetConnection $targetIP -TraceRoute -WarningAction SilentlyContinue;$hops=@($trace.TraceRoute)}catch{$hops=@()}
    $idx=1
    foreach ($hop in $hops){
        if(-not $hop -or $hop -in @('...','0.0.0.0','::')){$RouteReportRows.Add([pscustomobject]@{Hop=$idx;IP='Gizli/Yanıtsız (*)';Min='N/A';Max='N/A';Avg='N/A';Median='N/A';P95='N/A';Jitter='N/A';PeakJitter='N/A';StdDev='N/A';Loss='N/A';Status='ICMP yanıtlamıyor';CssClass='failed';Destination=$false});$idx++;continue}
        $hm=Invoke-PingProbe -ComputerName $hop -Count $HopPingCount -TimeoutMs $PingTimeoutMs -IntervalMs $PingIntervalMs
        if($hm.Successful-gt0){
            $routeMetricsAvailable=$true;$isDestinationHop=($hop -eq $targetIP -or $idx -eq $hops.Count)
            if($null -eq $maxJitterVal -or $hm.MeanJitter -gt $maxJitterVal){$maxJitterVal=$hm.MeanJitter};if($isDestinationHop){$destinationHopJitter=$hm.MeanJitter}
            $status='Stabil';$css='success'
            if($hm.LossPercent-gt0){if($isDestinationHop){$status="Hedef yanıt kaybı %$($hm.LossPercent)";$css='danger'}else{$status="Ara hop ICMP yanıt kaybı %$($hm.LossPercent)";$css='warning'}}
            elseif($hm.MeanJitter-gt20){if($isDestinationHop){$status='Hedefte yüksek jitter';$css='danger'}else{$status='Ara hop ICMP varyasyonu';$css='warning'}}
            elseif($hm.MeanJitter-gt10){$status=if($isDestinationHop){'Hedefte orta jitter'}else{'Ara hopta orta varyasyon'};$css='warning'}
            $RouteReportRows.Add([pscustomobject]@{Hop=$idx;IP=$hop;Min="$($hm.Min) ms";Max="$($hm.Max) ms";Avg="$($hm.Average) ms";Median="$($hm.Median) ms";P95="$($hm.P95) ms";Jitter="±$($hm.MeanJitter) ms";PeakJitter="±$($hm.PeakJitter) ms";StdDev="$($hm.StandardDeviation) ms";Loss="%$($hm.LossPercent)";Status=$status;CssClass=$css;Destination=$isDestinationHop})
            Write-Status "HOP-$idx" "$hop | Ort $($hm.Average) ms | p95 $($hm.P95) ms | Jitter ±$($hm.MeanJitter) ms | Kayıp %$($hm.LossPercent)" $(if($css-eq'success'){'Green'}elseif($css-eq'danger'){'Red'}else{'Yellow'})
        }else{$RouteReportRows.Add([pscustomobject]@{Hop=$idx;IP=$hop;Min='N/A';Max='N/A';Avg='N/A';Median='N/A';P95='N/A';Jitter='N/A';PeakJitter='N/A';StdDev='N/A';Loss='N/A';Status='ICMP yanıtlamıyor';CssClass='failed';Destination=$false})}
        $idx++
    }
}

$jmeterP95Val=$null;$jmeterErrRateVal=$null;$appMetricsAvailable=$false
if($ScanLevel-eq'JMeter' -or $EnableLoadTest){
    Write-LogHeader '5. GELİŞMİŞ HTTP EŞZAMANLI YÜK TESTİ'
    $protocol=if($Port -in @(443,8443)){'https'}else{'http'};$url="${protocol}://${Target}:${Port}/"
    $code=@'
using System;using System.Collections.Concurrent;using System.Diagnostics;using System.IO;using System.Net;using System.Net.Http;using System.Threading;using System.Threading.Tasks;
public class NetDiagRunnerV2{
 public class Result{public int Sequence;public DateTime StartedUtc;public double HeaderMs;public double ElapsedMs;public double DownloadMs;public long Bytes;public bool Success;public bool AssertionFailed;public int StatusCode;public string ErrorType;public string Error;}
 public class TestOutput{public ConcurrentBag<Result> Results;public int PeakConcurrency;}
 static int activeRequests=0,peakConcurrency=0;
 static void UpdatePeak(int current){int observed;do{observed=peakConcurrency;if(current<=observed)return;}while(Interlocked.CompareExchange(ref peakConcurrency,current,observed)!=observed);}
 static async Task<Result> ExecuteRequest(HttpClient client,string url,string method,string assertion,int timeoutSeconds,int maxResponseBytes,int sequence){var r=new Result{Sequence=sequence,StartedUtc=DateTime.UtcNow,Success=false,ErrorType="",Error=""};int active=Interlocked.Increment(ref activeRequests);UpdatePeak(active);var total=Stopwatch.StartNew();try{using(var cts=new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))using(var req=new HttpRequestMessage(method=="HEAD"?HttpMethod.Head:HttpMethod.Get,url)){var header=Stopwatch.StartNew();using(var response=await client.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,cts.Token).ConfigureAwait(false)){header.Stop();r.HeaderMs=header.Elapsed.TotalMilliseconds;r.StatusCode=(int)response.StatusCode;long bytes=0;string text="";if(method!="HEAD"){using(var stream=await response.Content.ReadAsStreamAsync().ConfigureAwait(false))using(var memory=new MemoryStream()){var buffer=new byte[8192];while(true){int read=await stream.ReadAsync(buffer,0,buffer.Length,cts.Token).ConfigureAwait(false);if(read<=0)break;bytes+=read;if(bytes>maxResponseBytes)throw new InvalidOperationException("ResponseSizeLimitExceeded");memory.Write(buffer,0,read);}if(!String.IsNullOrEmpty(assertion)){memory.Position=0;using(var reader=new StreamReader(memory)){text=reader.ReadToEnd();}}}}total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.DownloadMs=Math.Max(0,r.ElapsedMs-r.HeaderMs);r.Bytes=bytes;bool httpOk=r.StatusCode>=200&&r.StatusCode<400;bool assertOk=true;if(!String.IsNullOrEmpty(assertion)){assertOk=text.IndexOf(assertion,StringComparison.Ordinal)>=0;if(!assertOk){r.AssertionFailed=true;r.ErrorType="AssertionFailed";r.Error="Assertion text was not found.";}}r.Success=httpOk&&assertOk;if(!httpOk){r.ErrorType="HttpStatus";r.Error="HTTP "+r.StatusCode;}}}}catch(TaskCanceledException ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType="Timeout";r.Error=ex.Message;}catch(HttpRequestException ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType="HttpRequestException";r.Error=ex.InnerException!=null?ex.InnerException.Message:ex.Message;}catch(Exception ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType=ex.GetType().Name;r.Error=ex.InnerException!=null?ex.InnerException.Message:ex.Message;}finally{Interlocked.Decrement(ref activeRequests);}return r;}
 public static TestOutput Run(string url,int totalRequests,int threads,string assertion,int timeoutSeconds,int warmupRequests,int rampUpSeconds,int thinkTimeMs,int maxResponseBytes,string method){activeRequests=0;peakConcurrency=0;var results=new ConcurrentBag<Result>();var handler=new HttpClientHandler();handler.ServerCertificateCustomValidationCallback=(a,b,c,d)=>true;handler.AutomaticDecompression=DecompressionMethods.GZip|DecompressionMethods.Deflate;handler.MaxConnectionsPerServer=Math.Max(threads,2);using(var client=new HttpClient(handler)){client.Timeout=Timeout.InfiniteTimeSpan;client.DefaultRequestHeaders.Add("User-Agent","NetDiag/2.0");for(int w=0;w<warmupRequests;w++)ExecuteRequest(client,url,method,assertion,timeoutSeconds,maxResponseBytes,-(w+1)).GetAwaiter().GetResult();var options=new ParallelOptions{MaxDegreeOfParallelism=threads};Parallel.For(0,totalRequests,options,index=>{if(rampUpSeconds>0&&totalRequests>1){double ratio=index/(double)(totalRequests-1);int delay=(int)(ratio*rampUpSeconds*1000);if(delay>0)Thread.Sleep(delay);}var r=ExecuteRequest(client,url,method,assertion,timeoutSeconds,maxResponseBytes,index+1).GetAwaiter().GetResult();results.Add(r);if(thinkTimeMs>0)Thread.Sleep(thinkTimeMs);});}return new TestOutput{Results=results,PeakConcurrency=peakConcurrency};}
}
'@
    if(-not('NetDiagRunnerV2'-as[type])){Add-Type -TypeDefinition $code -Language CSharp}
    $testWatch=[Diagnostics.Stopwatch]::StartNew();$output=[NetDiagRunnerV2]::Run($url,$JMeterTotalRequests,$JMeterThreads,$JMeterAssertText,$HttpTimeoutSec,$JMeterWarmupRequests,$JMeterRampUpSeconds,$JMeterThinkTimeMs,$JMeterMaxResponseBytes,$JMeterHttpMethod);$testWatch.Stop();$results=@($output.Results.ToArray())
    if($results.Count){
        $appMetricsAvailable=$true;$successful=@($results|Where-Object{$_.Success});$failed=@($results|Where-Object{-not $_.Success});$elapsed=@($successful|Select-Object -ExpandProperty ElapsedMs|Sort-Object);$headers=@($successful|Select-Object -ExpandProperty HeaderMs|Sort-Object);$downloads=@($successful|Select-Object -ExpandProperty DownloadMs|Sort-Object)
        $successCount=$successful.Count;$failCount=$failed.Count;$errorRate=[Math]::Round(($failCount/[double]$results.Count)*100,2);$duration=[Math]::Round($testWatch.Elapsed.TotalSeconds,3);$rps=if($duration-gt0){[Math]::Round($results.Count/$duration,2)}else{0}
        if($elapsed.Count){$avgElapsed=[Math]::Round(($elapsed|Measure-Object -Average).Average,2);$stdElapsed=Get-PopulationStandardDeviation $elapsed;$p50=[Math]::Round((Get-Percentile $elapsed 50),2);$p75=[Math]::Round((Get-Percentile $elapsed 75),2);$p90=[Math]::Round((Get-Percentile $elapsed 90),2);$p95=[Math]::Round((Get-Percentile $elapsed 95),2);$p99=[Math]::Round((Get-Percentile $elapsed 99),2);$avgHeader=[Math]::Round(($headers|Measure-Object -Average).Average,2);$p95Header=[Math]::Round((Get-Percentile $headers 95),2);$avgDownload=[Math]::Round(($downloads|Measure-Object -Average).Average,2)}else{$avgElapsed=$stdElapsed=$p50=$p75=$p90=$p95=$p99=$avgHeader=$p95Header=$avgDownload=$null}
        $jmeterP95Val=$p95;$jmeterErrRateVal=$errorRate;$totalBytes=($successful|Measure-Object Bytes -Sum).Sum;if($null -eq $totalBytes){$totalBytes=0};$avgBytes=if($successCount){[Math]::Round($totalBytes/[double]$successCount)}else{0};$mbps=if($duration-gt0){[Math]::Round((($totalBytes*8)/$duration)/1000000,3)}else{0}
        $statusDist=(@($results|Group-Object StatusCode|Sort-Object Name|ForEach-Object{"HTTP $($_.Name): $($_.Count)"}))-join' | ';$errorDist=(@($failed|Group-Object ErrorType|Sort-Object Count -Descending|ForEach-Object{"$($_.Name): $($_.Count)"}))-join' | ';if(-not $errorDist){$errorDist='Hata yok'}
        $ReportData.JMeter_Engine='NetDiag HTTP Load Engine v2';$ReportData.JMeter_Method=$JMeterHttpMethod;$ReportData.JMeter_Threads=$JMeterThreads;$ReportData.JMeter_Peak_Concurrency=$output.PeakConcurrency;$ReportData.JMeter_RampUp="$JMeterRampUpSeconds saniye";$ReportData.JMeter_Warmup_Requests=$JMeterWarmupRequests;$ReportData.JMeter_Total_Requests=$results.Count;$ReportData.JMeter_Successful_Requests=$successCount;$ReportData.JMeter_Failed_Requests=$failCount;$ReportData.JMeter_Test_Duration="$duration saniye";$ReportData.JMeter_Throughput_RPS="$rps req/sec";$ReportData.JMeter_Avg_Header_Time="$avgHeader ms";$ReportData.JMeter_p95_Header_Time="$p95Header ms";$ReportData.JMeter_Avg_Download_Time="$avgDownload ms";$ReportData.JMeter_Avg_Elapsed="$avgElapsed ms";$ReportData.JMeter_Elapsed_StdDev="$stdElapsed ms";$ReportData.JMeter_p50_Elapsed="$p50 ms";$ReportData.JMeter_p75_Elapsed="$p75 ms";$ReportData.JMeter_p90_Elapsed="$p90 ms";$ReportData.JMeter_p95_Elapsed="$p95 ms";$ReportData.JMeter_p99_Elapsed="$p99 ms";$ReportData.JMeter_Error_Rate="%$errorRate";$ReportData.JMeter_Status_Distribution=$statusDist;$ReportData.JMeter_Error_Distribution=$errorDist;$ReportData.JMeter_Total_Data="$([Math]::Round($totalBytes/1MB,3)) MB";$ReportData.JMeter_Average_Response_Size="$avgBytes Byte";$ReportData.JMeter_Download_Throughput="$mbps Mbps"
        Write-Status LOAD "RPS $rps | Peak $($output.PeakConcurrency) | Başarılı $successCount | Hatalı $failCount | Hata %$errorRate" $(if($errorRate-gt5){'Red'}elseif($errorRate-gt0){'Yellow'}else{'Green'});Write-Status TTFB "Ort $avgHeader ms | p95 $p95Header ms" $(if($p95Header-gt1000){'Yellow'}else{'Green'});Write-Status ELAPSED "Ort $avgElapsed | p50 $p50 | p90 $p90 | p95 $p95 | p99 $p99 ms" $(if($p95-gt1000){'Yellow'}else{'Green'});Write-Status DATA "Toplam $([Math]::Round($totalBytes/1MB,3)) MB | Ort $avgBytes Byte | $mbps Mbps" Cyan
    }
}
if($JMeterCsvPath-and(Test-Path $JMeterCsvPath)){try{$csv=@(Import-Csv $JMeterCsvPath);$elapsedCsv=@($csv|ForEach-Object{if($_.elapsed -ne $null){[double]$_.elapsed}}|Sort-Object);if($elapsedCsv.Count){$ReportData.Ext_JMeter_File=Split-Path $JMeterCsvPath -Leaf;$ReportData.Ext_JMeter_p95="$(Get-Percentile $elapsedCsv 95) ms"}}catch{Write-Status CSV $_.Exception.Message Red}}


if($dnsOk -and $ScanLevel -eq 'Deep' -and ($Port -in @(80,443,8080,8443))){
    Write-LogHeader '6. WEB, SSL VE HTTP ANALİZİ'
    $protocol=if($Port -in @(443,8443)){'https'}else{'http'};$url="${protocol}://${Target}:${Port}/"
    if($protocol -eq 'https' -and $targetTcpReachable){
        $tc=$null;$ss=$null
        try{$tc=New-Object Net.Sockets.TcpClient;$ar=$tc.BeginConnect($targetIP,$Port,$null,$null);if(-not $ar.AsyncWaitHandle.WaitOne($TcpTimeoutMs,$false)){throw 'SSL TCP timeout'};$tc.EndConnect($ar);$ss=New-Object Net.Security.SslStream($tc.GetStream(),$false,({$true}));$ss.ReadTimeout=$HttpTimeoutSec*1000;$ss.WriteTimeout=$HttpTimeoutSec*1000;$ss.AuthenticateAsClient($Target);$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ss.RemoteCertificate;$days=[Math]::Floor(($cert.NotAfter-(Get-Date)).TotalDays);$ReportData.SSL_Subject=$cert.Subject;$ReportData.SSL_Issuer=$cert.Issuer;$ReportData.SSL_Days_Left="$days Gün";Write-Status SSL "$days gün kaldı" $(if($days-lt30){'Yellow'}else{'Green'})}catch{Write-Status SSL $_.Exception.Message Red}finally{if($ss){$ss.Dispose()};if($tc){$tc.Dispose()}}
    }
    try{$old=[Net.ServicePointManager]::ServerCertificateValidationCallback;[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$sw=[Diagnostics.Stopwatch]::StartNew();$wp=@{Uri=$url;Method='Get';TimeoutSec=$HttpTimeoutSec;ErrorAction='Stop';UseBasicParsing=$true};$wr=Invoke-WebRequest @wp;$sw.Stop();$ReportData.HTTP_Code=$wr.StatusCode;$ReportData.HTTP_Total_Time="$($sw.ElapsedMilliseconds) ms";Write-Status HTTP "Status $($wr.StatusCode), toplam $($sw.ElapsedMilliseconds) ms" Green}catch{Write-Status HTTP $_.Exception.Message Red}finally{[Net.ServicePointManager]::ServerCertificateValidationCallback=$old}
}

Write-LogHeader '7. KÖK NEDEN VE ÇAPRAZ KORELASYON'
$analysis=New-Object Text.StringBuilder
[void]$analysis.AppendLine('<b>[Sistem Mimarisi ve Performans Değerlendirmesi]</b><br>')
$networkQualityAvailable=($null -ne $destinationPingMetrics -and $destinationPingMetrics.Successful-gt0)
$targetJitterHigh=($networkQualityAvailable -and $destinationPingMetrics.MeanJitter-ge20);$targetJitterModerate=($networkQualityAvailable -and $destinationPingMetrics.MeanJitter-ge10 -and $destinationPingMetrics.MeanJitter-lt20);$targetLossHigh=($networkQualityAvailable -and $destinationPingMetrics.LossPercent-gt2);$appSlow=($appMetricsAvailable -and $null -ne $jmeterP95Val -and $jmeterP95Val-gt1000);$appErrorsHigh=($appMetricsAvailable -and $jmeterErrRateVal-gt5)
if((-not $networkQualityAvailable)-and(-not $appMetricsAvailable)){[void]$analysis.AppendLine('<b>SONUÇ: YETERSİZ ÖLÇÜM</b><br>Hedef ICMP kalite metrikleri ve HTTP yük metrikleri alınamadığından kesin korelasyon yapılamadı.')}
elseif($targetLossHigh-and($appSlow -or $appErrorsHigh)){[void]$analysis.AppendLine("<b>OLASI AĞ KALİTESİ SORUNU</b><br>Hedef paket yanıt kaybı %$($destinationPingMetrics.LossPercent), hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, HTTP p95 $jmeterP95Val ms ve hata oranı %$jmeterErrRateVal. Paket kaybı ile uygulama sorunları aynı ölçümde görüldü.")}
elseif($targetJitterHigh -and $appSlow){[void]$analysis.AppendLine("<b>AĞ VE UYGULAMA GECİKMESİ KORELASYONU</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, hedef RTT p95 $($destinationPingMetrics.P95) ms ve HTTP elapsed p95 $jmeterP95Val ms. Ağ değişkenliği uygulama yanıt dağılımını etkiliyor olabilir.")}
elseif($networkQualityAvailable-and(-not $targetJitterModerate)-and(-not $targetLossHigh)-and($appSlow -or $appErrorsHigh)){[void]$analysis.AppendLine("<b>OLASI SUNUCU VEYA UYGULAMA DARBOĞAZI</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms ve kayıp %$($destinationPingMetrics.LossPercent) iken HTTP p95 $jmeterP95Val ms, hata oranı %$jmeterErrRateVal. Uygulama, bağımlı servisler, veritabanı ve sunucu kaynakları incelenmelidir.")}
elseif($targetJitterModerate-and(-not $appSlow)-and(-not $appErrorsHigh)){[void]$analysis.AppendLine("<b>AĞ DEĞİŞKENLİĞİ VAR, UYGULAMA ETKİLENMEMİŞ</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms olmasına rağmen HTTP p95 $jmeterP95Val ms ve hata oranı %$jmeterErrRateVal.")}
elseif($networkQualityAvailable -and $appMetricsAvailable){[void]$analysis.AppendLine("<b>ÖLÇÜLEN DEĞERLER NORMAL</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, hedef RTT p95 $($destinationPingMetrics.P95) ms, HTTP p95 $jmeterP95Val ms ve hata oranı %$jmeterErrRateVal.")}
elseif($networkQualityAvailable){[void]$analysis.AppendLine("<b>AĞ KALİTESİ ÖLÇÜLDÜ</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, RTT p95 $($destinationPingMetrics.P95) ms ve kayıp %$($destinationPingMetrics.LossPercent). Uygulama yük testi yapılmadı.")}
else{[void]$analysis.AppendLine("<b>UYGULAMA ÖLÇÜLDÜ, AĞ METRİĞİ SINIRLI</b><br>HTTP p95 $jmeterP95Val ms ve hata oranı %$jmeterErrRateVal; hedef ICMP kalite metriği alınamadı.")}
if($null -ne $maxJitterVal -and $networkQualityAvailable -and $maxJitterVal-gt20 -and $destinationPingMetrics.MeanJitter-lt10){[void]$analysis.AppendLine('<br><b>ARA HOP ICMP VARYASYONU</b><br>Bazı ara hoplarda yüksek ICMP yanıt değişkenliği görülmesine rağmen son hedef jitter değeri düşüktür. Ara hop değişkenliği uçtan uca trafik bozulması olarak doğrulanmamıştır.')}


Write-Host (($analysis.ToString()-replace'<br>',"`n")-replace'<[^>]+>','') -ForegroundColor Yellow

if($ExportHtmlPath){
    # Re-evaluate report language immediately before rendering.
    # This guarantees that console and HTML use the same selected language.
    if ($Language -eq 'Auto') {
        $reportCulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
        if ($reportCulture -match '^tr(?:-|$)') {
            $Script:LanguageCode = 'tr'
        } else {
            $Script:LanguageCode = 'en'
        }
    }
    $ReportData.Language = if ($Script:LanguageCode -eq 'tr') { 'Türkçe' } else { 'English' }
    $ReportData.System_UICulture = [System.Globalization.CultureInfo]::CurrentUICulture.Name
    Write-LogHeader 'HTML RAPOR OLUŞTURULUYOR'
    $displayNames = @{
        Script_Version='NetDiag Script Sürümü'; Language='Rapor Dili'; System_UICulture='Sistem Arayüz Kültürü'; Yes_No_Format='Evet / Hayır Giriş Biçimi'; Target='Hedef Sunucu / Domain'; Port='Hedef TCP Portu';
        ScanLevel='Tarama Seviyesi'; Timestamp='Rapor Tarihi'; Env_User='Oturum Açan Kullanıcı';
        Env_ComputerName='İstemci Bilgisayar Adı'; Env_OS='İşletim Sistemi'; Env_CPU='CPU Bilgisi ve Kullanımı';
        Env_Memory='Sistem Belleği (RAM)'; Env_Disk='Disk Kullanımı'; Env_LocalIP='Aktif Ağ Adaptörü ve Yerel IP';
        Local_DNS_IP='Yerel DNS IPv4 Sonucu'; Public_DNS_IP='Google Public DNS IPv4 Sonucu';
        Cloudflare_DNS_IP='Cloudflare DNS IPv4 Sonucu'; DNS_Query_Time='Yerel DNS Sorgu Süresi';
        DNS_Name_Servers='Yetkili DNS Sunucuları'; Reverse_DNS='Reverse DNS (PTR) Kaydı';
        CDN_Status='CDN / Reverse Proxy Durumu'; ICMP_Status='ICMP Ping Durumu';
        Unloaded_Avg_RTT='Boştaki Ortalama Gecikme (RTT)'; Path_MTU='Path MTU Tahmini';
        Port_Matrix='TCP Port Erişilebilirlik Matrisi'; Target_Port_Status='Seçilen Portun Durumu';
        Open_Port_Count='Açık Port Sayısı'; Tested_Port_Count='Test Edilen Port Sayısı';
        Reachability_Status='Genel Erişilebilirlik Durumu'; JMeter_Threads='Eşzamanlı Sanal Kullanıcı';
        JMeter_Total_Requests='Toplam HTTP İsteği'; JMeter_Throughput_RPS='HTTP İşlem Hızı (RPS)';
        JMeter_Avg_Latency='Ortalama HTTP Yanıt Süresi'; JMeter_p90_Latency='p90 HTTP Yanıt Süresi';
        JMeter_p95_Latency='p95 HTTP Yanıt Süresi'; JMeter_Error_Rate='HTTP Hata Oranı';
        Ext_JMeter_File='Harici JMeter Sonuç Dosyası'; Ext_JMeter_p95='Harici JMeter p95';
        SSL_Subject='SSL Sertifika Konusu'; SSL_Issuer='SSL Sertifika Yayıncısı';
        SSL_Days_Left='SSL Kalan Geçerlilik Süresi'; HTTP_Code='HTTP Yanıt Kodu';
        HTTP_Total_Time='Toplam HTTP Yanıt Süresi'; ICMP_Sent='Gönderilen ICMP Paketi'; ICMP_Received='Yanıtlanan ICMP Paketi'; ICMP_Loss='Hedef ICMP Yanıt Kaybı';
        Unloaded_Min_RTT='Hedef Minimum RTT'; Unloaded_Median_RTT='Hedef Medyan RTT'; Unloaded_p95_RTT='Hedef p95 RTT'; Unloaded_Max_RTT='Hedef Maksimum RTT'; Destination_RTT_StdDev='Hedef RTT Standart Sapması'; Destination_Mean_Jitter='Hedef Ortalama Jitter'; Destination_Peak_Jitter='Hedef Peak Jitter'; Destination_Smoothed_Variation='Hedef Yumuşatılmış RTT Değişimi';
        JMeter_Engine='HTTP Yük Test Motoru'; JMeter_Method='HTTP Metodu'; JMeter_Peak_Concurrency='Ölçülen En Yüksek Eşzamanlı İstek'; JMeter_RampUp='Ramp-up Süresi'; JMeter_Warmup_Requests='Warm-up İstek Sayısı'; JMeter_Successful_Requests='Başarılı HTTP İsteği'; JMeter_Failed_Requests='Başarısız HTTP İsteği'; JMeter_Test_Duration='Toplam Yük Testi Süresi'; JMeter_Avg_Header_Time='Ortalama Header / TTFB Süresi'; JMeter_p95_Header_Time='p95 Header / TTFB Süresi'; JMeter_Avg_Download_Time='Ortalama Response İndirme Süresi'; JMeter_Avg_Elapsed='Ortalama Toplam HTTP Süresi'; JMeter_Elapsed_StdDev='HTTP Süre Standart Sapması'; JMeter_p50_Elapsed='p50 Toplam HTTP Süresi'; JMeter_p75_Elapsed='p75 Toplam HTTP Süresi'; JMeter_p90_Elapsed='p90 Toplam HTTP Süresi'; JMeter_p95_Elapsed='p95 Toplam HTTP Süresi'; JMeter_p99_Elapsed='p99 Toplam HTTP Süresi'; JMeter_Status_Distribution='HTTP Durum Kodu Dağılımı'; JMeter_Error_Distribution='HTTP Hata Tipi Dağılımı'; JMeter_Total_Data='Toplam Alınan Response Verisi'; JMeter_Average_Response_Size='Ortalama Response Boyutu'; JMeter_Download_Throughput='Response Veri Aktarım Hızı'
    }
    $rows = ''
    foreach ($x in $ReportData.GetEnumerator()) {
        $rawTitle = if ($displayNames.ContainsKey([string]$x.Key)) {
            [string]$displayNames[[string]$x.Key]
        } else {
            [string]$x.Key
        }

        $title = ConvertTo-LocalizedText $rawTitle

        if ($null -eq $x.Value) {
            $rawValue = 'N/A'
        } elseif ($x.Value -is [System.Array]) {
            $rawValue = ($x.Value | ForEach-Object { [string]$_ }) -join ', '
        } else {
            $rawValue = [string]$x.Value
        }

        # Port_Matrix intentionally contains trusted badge HTML generated by this script.
        if ($x.Key -eq 'Port_Matrix') {
            $value = ConvertTo-LocalizedText $rawValue
        } else {
            $localizedValue = ConvertTo-LocalizedText $rawValue
            $value = ConvertTo-HtmlSafe $localizedValue
        }

        $rows += "<tr><td><b>$(ConvertTo-HtmlSafe $title)</b></td><td>$value</td></tr>`n"
    }
    $route = ''
    foreach ($r in $RouteReportRows) {
        $route += @"
<tr class='$($r.CssClass)'>
    <td>$($r.Hop)</td>
    <td>$(ConvertTo-HtmlSafe $r.IP)</td>
    <td>$($r.Min)</td>
    <td>$($r.Max)</td>
    <td>$($r.Avg)</td>
    <td>$($r.Median)</td>
    <td>$($r.P95)</td>
    <td>$($r.Jitter)</td>
    <td>$($r.PeakJitter)</td>
    <td>$($r.StdDev)</td>
    <td>$($r.Loss)</td>
    <td>$(ConvertTo-HtmlSafe (ConvertTo-LocalizedText $r.Status))</td>
</tr>
"@
    }
    $routeSection = ''
    if ($route) {
        $routeTitle = ConvertTo-LocalizedText 'Hop Katmanlı Rota, Gecikme ve Jitter Analizi'
        $avgHeader = ConvertTo-LocalizedText 'Ort'
        $medianHeader = ConvertTo-LocalizedText 'Medyan'
        $lossHeader = ConvertTo-LocalizedText 'Kayıp'
        $statusHeader = ConvertTo-LocalizedText 'Durum'
        $routeSection = "<h3>$routeTitle</h3><table><thead><tr><th>Hop</th><th>IP</th><th>Min</th><th>Max</th><th>$avgHeader</th><th>$medianHeader</th><th>p95</th><th>Jitter</th><th>Peak</th><th>StdDev</th><th>$lossHeader</th><th>$statusHeader</th></tr></thead><tbody>$route</tbody></table>"
    }
    $notes='';foreach ($n in $AdvisorNotes){$notes+="<div class='advisor-item'>$(ConvertTo-HtmlSafe (ConvertTo-LocalizedText $n))</div>"};if(-not $notes){$notes="<div class='advisor-item'>$(ConvertTo-LocalizedText 'Ek uyarı yok.')</div>"}
    $localizedAnalysis = ConvertTo-LocalizedText ($analysis.ToString())
    $htmlLanguage = if ($Script:LanguageCode -eq 'tr') { 'tr' } else { 'en' }
    $htmlTitle = if ($Script:LanguageCode -eq 'tr') { 'NetDiag Raporu' } else { 'NetDiag Report' }
    $html=@"
<!doctype html><html lang='$htmlLanguage'><head><meta charset='utf-8'><title>$htmlTitle</title><style>body{font-family:Segoe UI,Arial;background:#f0f2f5;padding:25px;color:#333}.container{max-width:1200px;margin:auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 4px 20px #0001}h2{color:#005a9e;border-bottom:2px solid #005a9e;padding-bottom:10px}.subtitle{color:#5f6368;margin:-2px 0 18px 0;font-size:14px}table{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}th,td{padding:10px 14px;border:1px solid #e1e4e8;text-align:left}th{background:#0078d4;color:#fff}.analysis{background:#ebf8ff;border-left:5px solid #0078d4;padding:18px}.advisor{background:#fff8e1;border-left:5px solid #ffc107;padding:15px;margin-top:15px}.advisor-item{margin:6px 0}.badge{padding:4px 9px;border-radius:4px;font-size:12px;font-weight:bold;display:inline-block}.badge-open{background:#d4edda;color:#155724}.badge-closed{background:#f8d7da;color:#721c24}.badge-drop{background:#e2e3e5;color:#383d41}.success{background:#e6f4ea}.warning{background:#fef7e0}.danger{background:#fce8e6}.failed{background:#f1f3f4;color:#666}</style></head><body><div class='container'><h2>$(ConvertTo-LocalizedText 'NetDiag Ağ, Sistem ve Uygulama Teşhis Raporu')</h2><div class='subtitle'>$(ConvertTo-LocalizedText 'Hedef'): $(ConvertTo-HtmlSafe $Target) | Port: $Port | $(ConvertTo-LocalizedText 'Tarama'): $(ConvertTo-HtmlSafe $ScanLevel)</div><div class='analysis'>$localizedAnalysis</div><div class='advisor'><h3>$(ConvertTo-LocalizedText 'Önerilen Aksiyonlar ve Sistem Uyarıları')</h3>$notes</div><h3>$(ConvertTo-LocalizedText 'Genel Sistem, Ağ ve Uygulama Metrikleri')</h3><table><tbody>$rows</tbody></table>$routeSection</div></body></html>
"@
    $parent = Split-Path -Path $ExportHtmlPath -Parent
    if ($parent -and (-not (Test-Path -LiteralPath $parent))) {
        New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $finalReportPath = [System.IO.Path]::GetFullPath($ExportHtmlPath)
    $temporaryReportPath = "$finalReportPath.$([guid]::NewGuid().ToString('N')).tmp"
    $reportAlreadyExists = Test-Path -LiteralPath $finalReportPath -PathType Leaf

    try {
        [System.IO.File]::WriteAllText($temporaryReportPath,$html,$utf8NoBom)
        $temporaryInfo = Get-Item -LiteralPath $temporaryReportPath -ErrorAction Stop
        if ($temporaryInfo.Length -le 0) { throw (ConvertTo-LocalizedText 'Oluşturulan geçici rapor dosyası boş.') }

        if ($reportAlreadyExists) {
            $existingInfo = Get-Item -LiteralPath $finalReportPath -Force -ErrorAction Stop
            if ($existingInfo.IsReadOnly) { $existingInfo.IsReadOnly = $false }
            Remove-Item -LiteralPath $finalReportPath -Force -ErrorAction Stop
        }

        Move-Item -LiteralPath $temporaryReportPath -Destination $finalReportPath -Force -ErrorAction Stop
        $writtenInfo = Get-Item -LiteralPath $finalReportPath -ErrorAction Stop
        $expectedLength = $utf8NoBom.GetByteCount($html)

        if ($writtenInfo.Length -ne $expectedLength) {
            throw (ConvertTo-LocalizedText "Rapor doğrulaması başarısız. Beklenen boyut: $expectedLength Byte, yazılan: $($writtenInfo.Length) Byte.")
        }

        $writeAction = if ($reportAlreadyExists) { ConvertTo-LocalizedText 'Mevcut raporun üzerine yazıldı' } else { ConvertTo-LocalizedText 'Yeni rapor oluşturuldu' }
        Write-Status REPORT "${writeAction}: $finalReportPath | $($writtenInfo.Length) Byte | $($writtenInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" Green
    }
    catch {
        Write-Status REPORT (ConvertTo-LocalizedText "Rapor yazılamadı: $($_.Exception.Message)") Red
        throw
    }
    finally {
        if (Test-Path -LiteralPath $temporaryReportPath) { Remove-Item -LiteralPath $temporaryReportPath -Force -ErrorAction SilentlyContinue }
    }
}
Write-LogHeader 'DIAGNOSTIC TAMAMLANDI'
