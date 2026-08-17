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
    [ValidateSet('Low','Medium','Deep','JMeter','WebSec')][string]$ScanLevel = 'Deep',
    [ValidateRange(1,100)][int]$HopPingCount = 5,
    [switch]$EnableLoadTest,
    [ValidateRange(1,1000)][int]$JMeterThreads = 10,
    [ValidateRange(1,1000000)][int]$JMeterTotalRequests = 200,
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
    [ValidateSet('Auto','tr','en')][string]$Language = 'Auto',
    [switch]$GeoIp,
    [string]$Ports,
    [switch]$SkipGeoIp
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
    'TCP/UDP SERVİS PORT MATRİSİ'='TCP/UDP SERVICE PORT MATRIX'
    'HOP KATMANLI ROTA VE JITTER ANALİZİ'='HOP-BY-HOP ROUTE AND JITTER ANALYSIS'
    'GELİŞMİŞ HTTP EŞZAMANLI YÜK TESTİ'='ADVANCED CONCURRENT HTTP LOAD TEST'
    'WEB, SSL VE HTTP ANALİZİ'='WEB, SSL AND HTTP ANALYSIS'
    'WEB SALDIRI YÜZEYİ ANALİZİ VE ÇÖZÜM ÖNERİLERİ'='WEB ATTACK-SURFACE ANALYSIS AND SOLUTION ADVICE'
    'KÖK NEDEN VE ÇAPRAZ KORELASYON'='ROOT CAUSE AND CROSS-CORRELATION'
    'HTML RAPOR OLUŞTURULUYOR'='GENERATING HTML REPORT'
    'DIAGNOSTIC TAMAMLANDI'='DIAGNOSTIC COMPLETED'
    'Güncellemeler kontrol ediliyor'='Checking for updates'
    'Script güncel'='Script is up to date'
    'Yeni sürüm bulundu'='New version found'
    'Güncellensin mi?'='Update now?'
    'Güncellendi; script aynı terminal oturumunda yeniden başlatılıyor.'='Updated; restarting the script in the current terminal session.'
    'Script aynı terminalde yeniden başlatılamadı.'='The script could not be restarted in the current terminal.'
    'Script otomatik yeniden başlatılamadı.'='The script could not be restarted automatically.'
    'Yeni sürümü manuel başlatın'='Start the new version manually'
    'Yeniden başlatma komutu'='Restart command'

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
    'Özel portlar'='Custom ports'
    'GeoIP/ASN zenginleştirme?'='GeoIP/ASN enrichment?'
    'Web güvenliği: tüm Deep analizine ek olarak eşzamanlı HTTP yük testi, HTTP/HTTPS servisleri için yaygın web saldırı yüzeyi ve çözüm önerileri.'='Web security: all Deep analysis plus a concurrent HTTP load test, common web attack-surface checks, and solution advice for HTTP/HTTPS services.'
    'Web Saldırı Yüzeyi Özeti'='Web Attack-Surface Summary'
    'Web Saldırı Yüzeyi Bulguları'='Web Attack-Surface Findings'
    'Çözüm Önerileri'='Solution Advice'
    'Port'='Port'
    'Denetim'='Check'
    'Çözüm'='Solution'
    'Detay'='Detail'
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
    'başarılı'='Successful'
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
    'Kuyruk'='Tail'
    'örnek'='samples'
    'güvenilir'='reliable'
    'düşük örnek - p95 tercih edin'='low samples - prefer p95'
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
    'Bu rapor NetDiag sürümü tarafından oluşturuldu.'='This report was generated by NetDiag.'
    'Açık kaynak kodu, güncellemeleri ve proje ayrıntılarını GitHub üzerinde görüntüleyin.'='View the open-source code, updates, and project details on GitHub.'
    'NetDiag GitHub Projesi'='NetDiag GitHub Project'
    'Gizlilik ve Veri İşleme Bilgilendirmesi'='Privacy and Data Processing Notice'
    'NetDiag geliştiricisine tanılama verisi gönderilmez'='No diagnostic data is sent to the NetDiag developer'
    'NetDiag, tanılama sonuçlarını bir NetDiag sunucusuna, merkezi veri tabanına veya geliştiriciye göndermez.'='NetDiag does not send diagnostic results to a NetDiag server, central database, or the developer.'
    'Tanılama verileri yerel cihazda, çalıştırma sırasında işlenir; HTML raporu yalnızca kullanıcı seçerse yerel dosya olarak oluşturulur.'='Diagnostic data is processed locally on the device during execution; an HTML report is created as a local file only when the user chooses to save it.'
    'Rapor; kullanıcı adı, bilgisayar adı, yerel IP adresi, hedef adres, sistem envanteri ve ağ ölçümleri içerebilir. Raporun saklanması, paylaşılması ve erişim güvenliği kullanıcı veya raporu çalıştıran kuruluşun sorumluluğundadır.'='The report may contain the signed-in user name, computer name, local IP address, target address, system inventory, and network measurements. The user or organization running the report is responsible for its storage, sharing, and access security.'
    'Güncelleme kontrolü GitHub ile, DNS karşılaştırmaları yapılandırılmış genel DNS çözücülerle ve tanılama testleri seçilen hedef sistemle ağ iletişimi kurabilir. Tanılama sonuçları bu hizmetlere analitik amaçla gönderilmez.'='Update checks may communicate with GitHub, DNS comparisons with configured public DNS resolvers, and diagnostic tests with the selected target system. Diagnostic results are not sent to these services for analytics.'
    'GeoIP/ASN zenginleştirmesi, hedef ve yol üzerindeki IP adreslerinin konum ve ağ sahipliği bilgilerini almak için üçüncü taraf ip-api.com servisini kullanır; bu IP adresleri yalnızca bu amaçla gönderilir ve daha sonra kullanılmak üzere saklanmaz.'='GeoIP/ASN enrichment uses the third-party ip-api.com service to obtain location and network-ownership information for the target and route-hop IP addresses; these IP addresses are sent solely for this purpose and are not stored for later use.'
    'NetDiag çerez, reklam kimliği veya kullanım analitiği kullanmaz; kalıcı bir kullanıcı profili oluşturmaz.'='NetDiag does not use cookies, advertising identifiers, or usage analytics, and does not create a persistent user profile.'
    'Bu bilgilendirme hukuki danışmanlık değildir. NetDiag bir kuruluş adına çalıştırılıyorsa rapor içeriği ve kullanım biçimi için GDPR, KVKK ve kurum politikaları kapsamındaki yükümlülükler ayrıca değerlendirilmelidir.'='This notice is not legal advice. If NetDiag is run on behalf of an organization, obligations concerning the report content and its use under the GDPR, the Turkish KVKK, and organizational policies should be assessed separately.'
    'AB GDPR veri koruma ilkeleri'='EU GDPR data protection principles'
    'KVKK aydınlatma yükümlülüğü'='Turkish KVKK information obligation'
    'Hedef'='Target'
    'Tarama'='Scan'
    'Önerilen Aksiyonlar ve Sistem Uyarıları'='Recommended Actions and System Warnings'
    'Ek uyarı yok.'='No additional warnings.'
    'Genel Sistem, Ağ ve Uygulama Metrikleri'='General System, Network and Application Metrics'
    'Genel Sistem Metrikleri'='General System Metrics'
    'Ağ Metrikleri'='Network Metrics'
    'Uygulama Metrikleri'='Application Metrics'
    'Yük Testi Yapılandırması'='Load Test Configuration'
    'Yük Testi Sonuçları'='Load Test Results'
    'HTTP Zamanlaması - TTFB'='HTTP Timing - TTFB'
    'HTTP Zamanlaması - Elapsed'='HTTP Timing - Elapsed'
    'HTTP Veri ve Durum'='HTTP Data & Status'
    'HTTP Yanıtı'='HTTP Response'
    'SSL / TLS'='SSL / TLS'
    'HTTP Protokolü'='HTTP Protocol'
    'Güvenlik Başlıkları'='Security Headers'
    'Dış JMeter'='External JMeter'
    'Script Bilgisi'='Script Info'
    'Sistem Kaynakları'='System Resources'
    'Ağ Adaptörü'='Network Adapter'
    'DNS'='DNS'
    'ICMP / Ping'='ICMP / Ping'
    'TCP / UDP Portları'='TCP / UDP Ports'
    'Hedef Jitter Metrikleri'='Destination Jitter Metrics'
    'GeoIP / ASN'='GeoIP / ASN'
    'E-posta Güvenliği'='Email Security'
    'Sertifika Otoritesi'='Certificate Authority'
    'Harici MX Sağlayıcıları'='External MX Providers'
    'SPF Politika Analizi'='SPF Policy Analysis'
    'DMARC Politika Analizi'='DMARC Policy Analysis'
    'Bilgi'='Info'
    'Uyarı'='Warning'
    'Tehlike'='Danger'
    'Performans Bilgi Grafikleri'='Performance Infographics'
    'Ağ Kalitesi Özeti'='Network Quality Summary'
    'HTTP Yük Testi Özeti'='HTTP Load Test Summary'
    'HTTP Gecikme Yüzdelikleri'='HTTP Latency Percentiles'
    'Hop Bazlı Jitter Dağılımı'='Hop-by-Hop Jitter Distribution'
    'Hop Bazlı Ortalama Gecikme'='Hop-by-Hop Average Latency'
    'Ağ RTT Dağılımı'='Network RTT Distribution'
    'En Düşük'='Minimum'
    'En Yüksek'='Maximum'
    'HTTP Zamanlama Dağılımı'='HTTP Timing Breakdown'
    'Header / TTFB'='Header / TTFB'
    'İndirme'='Download'
    'Sertifika Geçerlilik Süresi'='Certificate Validity'
    'Gün'='Days'
    'Pass'='Pass'
    'Yayıncı'='Issuer'
    'Geçerlilik'='Validity'
    'İmza'='Signature'
    'Sinyal'='Signal'
    'Kanal'='Channel'
    'Çözümlenemedi'='Could not resolve'
    'Hedef GeoIP/ASN bilgisi alınamadı'='Target GeoIP/ASN information could not be retrieved'
    'SAN eşleşmesi'='SAN match'
    'Zincir'='Chain'
    'Split-DNS ihtimalini inceleyin.'='Investigate the Split-DNS possibility.'
    'Başarılı İstekler'='Successful Requests'
    'Başarısız İstekler'='Failed Requests'
    'Ortalama RTT'='Average RTT'
    'Hedef p95 RTT'='Destination p95 RTT'
    'Ortalama Jitter'='Mean Jitter'
    'Yanıt Kaybı'='Response Loss'
    'İşlem Hızı'='Throughput'
    'HTTP p95'='HTTP p95'
    'Hata Oranı'='Error Rate'
    'Peak Eşzamanlılık'='Peak Concurrency'
    'Yayılım'='Spread'
    'Kuyruk Oranı'='Tail Ratio'
    'Örnek Kalitesi'='Sample Quality'
    'p50 Gecikmesi'='p50 Latency'
    'p99 Gecikmesi'='p99 Latency'
    'Kuyruk Sağlıklı (<2x)'='Tail Healthy (<2x)'
    'Kuyruk Orta (2-3x)'='Tail Moderate (2-3x)'
    'Kuyruk Kritik (>3x)'='Tail Critical (>3x)'
    'TTFB Yayılımı'='TTFB Spread'
    'Gecikme Yayılım Analizi'='Latency Spread Analysis'
    'Zamanlama Analizi'='Timing Analysis'
    'TTFB Oranı'='TTFB Ratio'
    'Yanıt Boyutu'='Response Size'
    'İndirme Verimliliği'='Download Efficiency'
    'Kritik'='Critical'
    'p50 Header / TTFB Süresi'='p50 Header / TTFB Time'
    'p90 Header / TTFB Süresi'='p90 Header / TTFB Time'
    'p99 Header / TTFB Süresi'='p99 Header / TTFB Time'
    'Gecikme Yayılımı (p99-p50)'='Latency Spread (p99-p50)'
    'Kuyruk Oranı (p99/p50)'='Tail Ratio (p99/p50)'
    'En Düşük HTTP Süresi'='Minimum HTTP Time'
    'En Yüksek HTTP Süresi'='Maximum HTTP Time'
    'saldırı yüzeyi ve sayfa analizi yapılıyor...'='attack-surface and page analysis in progress...'
    'MX Kayıtları'='MX Records'
    'SPF Kaydı'='SPF Record'
    'DMARC Kaydı'='DMARC Record'
    'DKIM Kaydı'='DKIM Record'
    'CAA Kayıtları'='CAA Records'
    'DNS Sızıntı Özeti'='DNS Exposure Summary'
    'Bulunan Kayıtlar'='Found Records'
    'Eksik Kayıtlar'='Missing Records'
    'Bulundu'='Found'
    'Eksik'='Missing'
    'Hiçbir DNS sızıntı kaydı bulunamadı.'='No DNS exposure records were found.'
    'MX kaydı bulunamadı.'='No MX record found.'
    'SPF kaydı bulunamadı.'='No SPF record found.'
    'DMARC kaydı bulunamadı.'='No DMARC record found.'
    'DKIM kaydı bulunamadı.'='No DKIM record found.'
    'CAA kaydı bulunamadı.'='No CAA record found.'
    'Orta'='Moderate'
    'İyi'='Good'
    'Optimizasyon Önerileri'='Optimization Suggestions'
    'Sunucu taraflı optimizasyon gerekli'='Server-side optimization needed'
    'İçerik optimizasyonu gerekli'='Content optimization needed'
    'Büyük yanıt boyutu'='Large response size'
    'TTFB değişkenliği yüksek'='High TTFB variability'
    'Kuyruk latency sorunu'='Tail latency problem'
    'Zamanlama metrikleri sağlıklı görünüyor'='Timing metrics appear healthy'
    'DNS sızıntı kayıtları kontrol ediliyor (MX, SPF, DMARC, DKIM, CAA)...'='Checking DNS exposure records (MX, SPF, DMARC, DKIM, CAA)...'
    'MX records point to external mail providers'='MX kayıtları harici posta sağlayıcılarını işaret ediyor'
    'SPF policy'='SPF politikası'
    'DMARC policy'='DMARC politikası'
    'DMARC record missing'='DMARC kaydı bulunamadı'
    'SPF record missing'='SPF kaydı bulunamadı'
    'DKIM record not found'='DKIM kaydı bulunamadı'
    'Grafik oluşturmak için yeterli veri yok.'='Not enough data was available to generate the chart.'
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
    'CPU Kullanım Veri Kaynağı'='CPU Usage Data Source'
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
    'Hedef Maksimum RTT'='Destination Maximum RTT'
    'Hedef RTT Standart Sapması'='Destination RTT Standard Deviation'
    'Hedef Ortalama Jitter'='Destination Mean Jitter'
    'Hedef Peak Jitter'='Destination Peak Jitter'
    'Hedef Yumuşatılmış RTT Değişimi'='Destination Smoothed RTT Variation'
    'Path MTU Tahmini'='Path MTU Estimate'
    'TCP Port Erişilebilirlik Matrisi'='TCP Port Reachability Matrix'
    'UDP Servis Doğrulama Matrisi'='UDP Service Validation Matrix'
    'Doğrulanan UDP Servis Sayısı'='Verified UDP Service Count'
    'Yanıt Vermeyen UDP Servis Sayısı'='Unresponsive UDP Service Count'
    'Seçilen Portun Durumu'='Selected Port Status'
    'Açık Port Sayısı'='Open Port Count'
    'Test Edilen Port Sayısı'='Tested Port Count'
    'Doğrulanan Servis Sayısı'='Verified Service Count'
    'Doğrulanamayan TCP Bağlantısı'='Unverified TCP Connection Count'
    'Kapalı / Filtreli Port Sayısı'='Closed / Filtered Port Count'
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
    'HTTP Yük Testi Durumu'='HTTP Load Test Status'
    'Etkin Yük Testi URL''si'='Effective Load Test URL'
    'HTTPS Sertifika Durumu'='HTTPS Certificate Status'
    'HTTPS Sertifika Başlangıcı'='HTTPS Certificate Valid From'
    'HTTPS Sertifika Bitişi'='HTTPS Certificate Valid Until'
    'HTTPS sertifikası geçersiz veya alınamadı; doğrulanmış HTTP/80 servisine geri dönüldü.'='The HTTPS certificate was invalid or unavailable; the test fell back to the verified HTTP/80 service.'
    'Sertifika sunulmadı'='No certificate presented'
    'Sertifikanın süresi dolmuş'='Certificate expired'
    'Sertifika henüz geçerli değil'='Certificate not yet valid'
    'Sertifika geçerli'='Certificate valid'
    'Yük testi atlandı'='Load test skipped'
    'Seçilen HTTPS servisi TLS doğrulamasından geçmediği için yük testi başlatılmadı.'='The load test was not started because the selected HTTPS service did not pass TLS validation.'
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
    'Evet / Hayır Giriş Biçimi'='Yes / No Input Format'
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
    'Desteklenen TLS Sürümleri'='Supported TLS Versions'
    'Müzakere Edilen TLS Sürümü'='Negotiated TLS Version'
    'Müzakere Edilen Şifreleme'='Negotiated Cipher Suite'
    'HTTP Protokolü (ALPN)'='HTTP Protocol (ALPN)'
    'HTTP/2 Durumu'='HTTP/2 Status'
    'HTTP/3 (QUIC) Durumu'='HTTP/3 (QUIC) Status'
    'Güvenlik Başlığı Puanı'='Security Header Score'
    'Güvenlik Başlığı Denetimi'='Security Header Audit'
    'Desteklenen TLS sürümü bulunamadı.'='No supported TLS version was found.'
    'Hiçbiri (TLS handshake başarısız)'='None (TLS handshake failed)'
    'Eski TLS sürümü kabul edildi; risk oluşturabilir.'='A legacy TLS version is accepted; this may pose a risk.'
    'Desteklenen:'='Supported:'
    'Müzakere edilen ALPN:'='Negotiated ALPN:'
    'TLS ve HTTP protokol denetimi'='TLS and HTTP protocol check'
    'Hedef ASN / Ağ Sağlayıcı'='Target ASN / Network Provider'
    'Hedef Coğrafi Konum'='Target Geolocation'
    'Hedef İSS / Organizasyon'='Target ISP / Organization'
    'Yol Üzerindeki Ağlar (ASN)'='Networks on the Path (ASN)'
    'DNSSEC Durumu'='DNSSEC Status'
    'DNS-over-TLS (853) Durumu'='DNS-over-TLS (853) Status'
    'DNS-over-HTTPS Durumu'='DNS-over-HTTPS Status'
    'Çözümleyici Tutarlılığı (UDP/DoT/DoH)'='Resolver Consistency (UDP/DoT/DoH)'
    'HTTPS Sertifika SAN Alanları'='HTTPS Certificate SAN Entries'
    'SAN Hostname Eşleşmesi'='SAN Hostname Match'
    'Sertifika Zinciri Geçerliliği'='Certificate Chain Validity'
    'Sertifika Zinciri Durumları'='Certificate Chain Status'
    'İptal (Revocation) Durumu'='Revocation Status'
    'Sertifika İmza Algoritması'='Certificate Signature Algorithm'
    'Sertifika Geçerlilik Penceresi'='Certificate Validity Window'
    'Wi-Fi Ağ Adı (SSID)'='Wi-Fi Network Name (SSID)'
    'Wi-Fi Sinyal Gücü'='Wi-Fi Signal Strength'
    'Wi-Fi Kanalı'='Wi-Fi Channel'
    'Wi-Fi Radyo Tipi'='Wi-Fi Radio Type'
    'Wi-Fi Alış (RX) Hızı'='Wi-Fi Receive (RX) Rate'
    'Wi-Fi Gönderim (TX) Hızı'='Wi-Fi Transmit (TX) Rate'
    'Ağ Adaptörü Durumu'='Network Adapter Status'
    'Adaptör Bağlantı Hızı'='Adapter Link Speed'
    'Adaptör Medya Tipi'='Adapter Media Type'
    'Adaptör Paket Hataları'='Adapter Packet Errors'
    'Taranan Portlar'='Scanned Ports'
    'Özel TCP port listesi virgülle ayrılmış. Boş bırakılırsa seviye varsayılanı kullanılır.'='Custom TCP port list, comma-separated. Leave blank to use the scan-level default.'
    'Geçersiz port listesi; varsayılanlara dönülüyor.'='Invalid port list; falling back to defaults.'
    '    GeoIP/ASN zenginleştirme; hedef ve yol IP adreslerini üçüncü taraf ip-api.com servisine gönderir.'='    GeoIP/ASN enrichment sends the target and route IP addresses to the third-party ip-api.com service.'
}

# ConvertTo-LocalizedText runs once per console status line and once per HTML row.
# The sorted, regex-escaped entry list is therefore compiled once and cached.
$Script:CompiledTranslations = $null
function Get-CompiledTranslations {
    if ($null -eq $Script:CompiledTranslations) {
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($entry in (
            $Script:EnglishTranslations.GetEnumerator() |
                Sort-Object { ([string]$_.Key).Length } -Descending
        )) {
            # Do not translate a key when it occurs inside another word.
            # Example: 'Ort' must not alter 'Port' or 'Report'.
            $pattern = '(?<![\p{L}\p{N}_])' +
                [System.Text.RegularExpressions.Regex]::Escape([string]$entry.Key) +
                '(?![\p{L}\p{N}_])'
            $list.Add([pscustomobject]@{
                Regex = [System.Text.RegularExpressions.Regex]::new(
                    $pattern,
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Compiled
                )
                # Doubling '$' keeps the replacement literal in the Regex overload.
                Replacement = ([string]$entry.Value).Replace('$','$$')
            })
        }
        $Script:CompiledTranslations = $list.ToArray()
    }
    return $Script:CompiledTranslations
}

function ConvertTo-LocalizedText([object]$Text) {
    if ($null -eq $Text) { return '' }

    $result = [string]$Text
    if ($Script:LanguageCode -eq 'tr') { return $result }

    foreach ($entry in Get-CompiledTranslations) {
        $result = $entry.Regex.Replace($result, $entry.Replacement)
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

# Phrase and word lists are also compiled once; ConvertTo-LocalizedReportValue
# runs for every generated report value.
$Script:CompiledReportTranslations = $null
function Get-CompiledReportTranslations {
    if ($null -eq $Script:CompiledReportTranslations) {
        $list = New-Object 'System.Collections.Generic.List[object]'

        # Full generated phrases first. Longer phrases prevent partial translations.
        # PowerShell hashtables are case-insensitive, therefore process a tuple list
        # instead of storing case-only variants as duplicate keys.
        $phraseList = @(
            @('Uygulama yük testi yapılmadı.','Application load testing was not performed.'),
            @('Hata yok','No errors'),
            @('MX kaydı bulunamadı.','No MX record found.'),
            @('SPF kaydı bulunamadı.','No SPF record found.'),
            @('DMARC kaydı bulunamadı.','No DMARC record found.'),
            @('DKIM kaydı bulunamadı.','No DKIM record found.'),
            @('CAA kaydı bulunamadı.','No CAA record found.'),
            @('Query failed','Sorgu başarısız'),
            @('Missing','Eksik'),
            @('Not found (common selectors)','Ortak seçicilerde bulunamadı'),
            @('Paket kaybı ile uygulama sorunları aynı ölçümde görüldü.','Packet loss and application issues were observed in the same measurement.'),
            @('Ağ değişkenliği uygulama yanıt dağılımını etkiliyor olabilir.','Network variation may be affecting the application response-time distribution.'),
            @('Uygulama, bağımlı servisler, veritabanı ve sunucu kaynakları incelenmelidir.','The application, dependent services, database, and server resources should be investigated.'),
            @('Hedef ICMP kalite metriği alınamadı.','Destination ICMP quality metrics were unavailable.'),
            @('IP MTU tahmini','IP MTU estimate'),
            @('Gizli/Yanıtsız (*)','Hidden/Unresponsive (*)'),
            @('Kullanılabilir CPU sayacı bulunamadı','No available CPU counter'),
            @('gün kaldı','days remaining'),
            @('olmasına rağmen','although'),
            @('seviyesinde iken','while measured at'),
            @('ve hata oranı','and error rate'),
            @('ve kayıp','and loss'),
            @('hedef RTT','destination RTT'),
            @('Hedef jitter','Destination jitter')
        )
        foreach ($pair in $phraseList) {
            $list.Add([pscustomobject]@{
                Regex = [System.Text.RegularExpressions.Regex]::new(
                    [System.Text.RegularExpressions.Regex]::Escape([string]$pair[0]),
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Compiled
                )
                Replacement = ([string]$pair[1]).Replace('$','$$')
            })
        }

        # Generated inventory values. Word boundaries prevent Port/Report corruption.
        $wordList = @(
            @('Anlık','Current'),
            @('Toplam','Total'),
            @('Kullanılan','Used'),
            @('Boş','Free'),
            @('Doluluk','Usage'),
            @('Gün','Days'),
            @('Başarılı','Successful'),
            @('Hatalı','Failed'),
            @('Hata','Error'),
            @('Kayıp','Loss'),
            @('Ortalama','Average'),
            @('Ölçülemedi','Could not be measured'),
            @('Bilinmiyor','Unknown')
        )
        foreach ($pair in $wordList) {
            $pattern = '(?<![\p{L}\p{N}_])' +
                [System.Text.RegularExpressions.Regex]::Escape([string]$pair[0]) +
                '(?![\p{L}\p{N}_])'
            $list.Add([pscustomobject]@{
                Regex = [System.Text.RegularExpressions.Regex]::new(
                    $pattern,
                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Compiled
                )
                Replacement = ([string]$pair[1]).Replace('$','$$')
            })
        }

        $Script:CompiledReportTranslations = $list.ToArray()
    }
    return $Script:CompiledReportTranslations
}

function ConvertTo-LocalizedReportValue([object]$Value) {
    if ($null -eq $Value) { return 'N/A' }

    $text = [string]$Value
    if ($Script:LanguageCode -eq 'tr') { return $text }

    foreach ($entry in Get-CompiledReportTranslations) {
        $text = $entry.Regex.Replace($text, $entry.Replacement)
    }

    return ConvertTo-LocalizedText $text
}

function Read-LocalizedHost([string]$Prompt) {
    return Read-Host (ConvertTo-LocalizedText $Prompt)
}

# Version/commit resolution.
#
# $LocalCommit is the version baked into this file. Inside a git clone it is
# replaced by the repository HEAD (git rev-parse --short HEAD), so it stays
# accurate after every local or remote commit. It is also the value patched by
# Test-ScriptUpdate when a new version is downloaded and the value compared
# against GitHub to decide whether an update is available.
#
# $CurrentCommit is the identifier shown in the console banner and the HTML
# report. End users who run the script without git fall back to the latest
# commit reported by the GitHub API (when reachable) and to $LocalCommit when
# the machine is offline, so the reported version stays meaningful on any PC.
$GitHubApiUrl = 'https://api.github.com/repos/oguska/netdiag/commits/main'
$GitHubRawUrl = 'https://raw.githubusercontent.com/oguska/netdiag/refs/heads/main/netdiag.ps1'
$GitHubProjectUrl = 'https://github.com/oguska/netdiag'
$LocalCommit = '8511ba9'
$commitFromGit = $false
if (Get-Command git -ErrorAction SilentlyContinue) {
    try {
        $repoDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $commitProbe = & git -C $repoDir rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commitProbe)) { $LocalCommit = $commitProbe.Trim(); $commitFromGit = $true }
    } catch {}
}
$CurrentCommit = $LocalCommit
if (-not $commitFromGit) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $headers = @{ 'User-Agent' = 'NetDiag-PowerShell' }
        $commitResponse = Invoke-RestMethod -Uri $GitHubApiUrl -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $latestCommit = [string]$commitResponse.sha
        if ($latestCommit.Length -ge 7) { $CurrentCommit = $latestCommit.Substring(0,7) }
    } catch {}
}
$GdprInformationUrl = 'https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en'
$KvkkInformationUrl = 'https://www.kvkk.gov.tr/Icerik/2033/Aydinlatma-Yukumlulugu-'

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
function Get-PopulationStandardDeviation([double[]]$Values) {
    if (-not $Values -or $Values.Count -lt 2) { return 0.0 }
    $count = $Values.Count
    $sum = 0.0
    foreach ($value in $Values) { $sum += $value }
    $average = $sum / $count
    $sqSum = 0.0
    foreach ($value in $Values) {
        $diff = $value - $average
        $sqSum += $diff * $diff
    }
    return [Math]::Round([Math]::Sqrt($sqSum / $count),2)
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
    $buffer=New-Object byte[] $PayloadSize
    $options=New-Object System.Net.NetworkInformation.PingOptions
    $options.DontFragment=$DontFragment.IsPresent
    $options.Ttl=128
    try {
        for($sequence=1;$sequence -le $Count;$sequence++){
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
function Invoke-TcpConnect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateRange(100,30000)][int]$TimeoutMs = 1500
    )

    $client = [Net.Sockets.TcpClient]::new()
    $watch = [Diagnostics.Stopwatch]::StartNew()

    try {
        $async = $client.BeginConnect($ComputerName,$Port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) {
            $client.Dispose()
            return [pscustomobject]@{
                State='Filtered'; LatencyMs=$null; Client=$null; Error='Timeout'
            }
        }

        try { $client.EndConnect($async) }
        catch [Net.Sockets.SocketException] {
            $code = $_.Exception.SocketErrorCode
            $state = switch ($code) {
                'ConnectionRefused' { 'Closed' }
                'HostUnreachable'    { 'Unreachable' }
                'NetworkUnreachable' { 'Unreachable' }
                'TimedOut'           { 'Filtered' }
                default              { 'Error' }
            }
            $client.Dispose()
            return [pscustomobject]@{
                State=$state; LatencyMs=$null; Client=$null; Error=$code.ToString()
            }
        }

        $watch.Stop()
        return [pscustomobject]@{
            State='Connected'
            LatencyMs=[Math]::Round($watch.Elapsed.TotalMilliseconds,1)
            Client=$client
            Error=$null
        }
    }
    catch {
        $client.Dispose()
        return [pscustomobject]@{
            State='Error'; LatencyMs=$null; Client=$null; Error=$_.Exception.Message
        }
    }
    finally {
        $watch.Stop()
    }
}

function Read-NetworkBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [ValidateRange(1,4096)][int]$MaximumBytes = 512
    )

    $buffer = New-Object byte[] $MaximumBytes
    try {
        $read = $Stream.Read($buffer,0,$buffer.Length)
        if ($read -gt 0) { return ,$buffer[0..($read-1)] }
    }
    catch {}
    return ,@()
}

function Test-TcpService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateRange(100,30000)][int]$TimeoutMs = 1500
    )

    $connection = Invoke-TcpConnect -ComputerName $ComputerName -Port $Port -TimeoutMs $TimeoutMs
    if ($connection.State -ne 'Connected') {
        return [pscustomobject]@{
            Port=$Port
            State=$connection.State
            TcpSucceeded=$false
            ServiceVerified=$false
            Protocol=''
            LatencyMs=$connection.LatencyMs
            Evidence=$connection.Error
            Error=$connection.Error
            CertificateStatus='NotApplicable'
            CertificateSubject=$null
            CertificateIssuer=$null
            CertificateNotBefore=$null
            CertificateNotAfter=$null
            CertificateDaysRemaining=$null
        }
    }

    $client = $connection.Client
    $stream = $null
    $verified = $false
    $protocol = 'Generic TCP'
    $evidence = 'TCP handshake only'
    $certificateStatus = 'NotApplicable'
    $certificateSubject = $null
    $certificateIssuer = $null
    $certificateNotBefore = $null
    $certificateNotAfter = $null
    $certificateDaysRemaining = $null

    try {
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $stream.WriteTimeout = $TimeoutMs

        switch ($Port) {
            22 {
                $protocol = 'SSH'
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 256
                if ($reply.Count -gt 0) {
                    $banner = [Text.Encoding]::ASCII.GetString($reply)
                    if ($banner.StartsWith('SSH-')) {
                        $verified = $true
                        $evidence = $banner.Trim()
                    } else {
                        $evidence = 'TCP connected, SSH banner not received'
                    }
                } else {
                    $evidence = 'TCP connected, SSH banner not received'
                }
            }
            80 {
                $protocol = 'HTTP'
                $request = "HEAD / HTTP/1.1`r`nHost: $ComputerName`r`nConnection: close`r`n`r`n"
                $bytes = [Text.Encoding]::ASCII.GetBytes($request)
                $stream.Write($bytes,0,$bytes.Length)
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512
                if ($reply.Count -gt 0) {
                    $text = [Text.Encoding]::ASCII.GetString($reply)
                    if ($text -match '^HTTP/\d(?:\.\d)?\s+\d{3}') {
                        $verified = $true
                        $evidence = ($text -split "`r?`n")[0]
                    } else {
                        $evidence = 'TCP connected, valid HTTP status line not received'
                    }
                } else {
                    $evidence = 'TCP connected, HTTP response not received'
                }
            }
            25 {
                $protocol = 'SMTP Relay'
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512
                if ($reply.Count -gt 0) {
                    $banner = [Text.Encoding]::ASCII.GetString($reply).Trim()
                    if ($banner -match '^220[ -]') {
                        $verified = $true
                        $evidence = ($banner -split "`r?`n")[0]
                    } else {
                        $evidence = 'TCP connected, valid SMTP 220 banner not received'
                    }
                } else {
                    $evidence = 'TCP connected, SMTP banner not received'
                }
            }
            587 {
                $protocol = 'SMTP Submission / STARTTLS'
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512
                if ($reply.Count -gt 0) {
                    $banner = [Text.Encoding]::ASCII.GetString($reply).Trim()
                    if ($banner -match '^220[ -]') {
                        $verified = $true
                        $evidence = ($banner -split "`r?`n")[0]
                    } else {
                        $evidence = 'TCP connected, valid SMTP submission banner not received'
                    }
                } else {
                    $evidence = 'TCP connected, SMTP submission banner not received'
                }
            }
            110 {
                $protocol = 'POP3 / STARTTLS'
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512
                if ($reply.Count -gt 0) {
                    $banner = [Text.Encoding]::ASCII.GetString($reply).Trim()
                    if ($banner -match '^\+OK(?:\s|$)') {
                        $verified = $true
                        $evidence = ($banner -split "`r?`n")[0]
                    } else {
                        $evidence = 'TCP connected, valid POP3 +OK banner not received'
                    }
                } else {
                    $evidence = 'TCP connected, POP3 banner not received'
                }
            }
            143 {
                $protocol = 'IMAP / STARTTLS'
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512
                if ($reply.Count -gt 0) {
                    $banner = [Text.Encoding]::ASCII.GetString($reply).Trim()
                    if ($banner -match '^\*\s+OK(?:\s|$)') {
                        $verified = $true
                        $evidence = ($banner -split "`r?`n")[0]
                    } else {
                        $evidence = 'TCP connected, valid IMAP * OK banner not received'
                    }
                } else {
                    $evidence = 'TCP connected, IMAP banner not received'
                }
            }
            443 {
                $protocol = 'TLS/HTTPS'
                $certificateHolder = @{ Certificate = $null; PolicyErrors = $null; ChainStatus = @() }
                $validationCallback = {
                    param($sender,$certificate,$chain,$sslPolicyErrors)
                    if ($null -ne $certificate) {
                        $certificateHolder.Certificate = New-Object `
                            Security.Cryptography.X509Certificates.X509Certificate2 `
                            $certificate
                    }
                    $certificateHolder.PolicyErrors = $sslPolicyErrors.ToString()
                    if ($null -ne $chain) {
                        $certificateHolder.ChainStatus = @(
                            $chain.ChainStatus | ForEach-Object { $_.Status.ToString() }
                        )
                    }
                    return $true
                }
                $ssl = New-Object Net.Security.SslStream(
                    $stream,
                    $false,
                    $validationCallback
                )
                try {
                    $ssl.ReadTimeout = $TimeoutMs
                    $ssl.WriteTimeout = $TimeoutMs
                    $ssl.AuthenticateAsClient($ComputerName)

                    $cert = $certificateHolder.Certificate
                    if ($null -eq $cert -and $null -ne $ssl.RemoteCertificate) {
                        $cert = New-Object `
                            Security.Cryptography.X509Certificates.X509Certificate2 `
                            $ssl.RemoteCertificate
                    }

                    if ($null -ne $cert) {
                        $certificateSubject = $cert.Subject
                        $certificateIssuer = $cert.Issuer
                        $certificateNotBefore = $cert.NotBefore
                        $certificateNotAfter = $cert.NotAfter
                        $certificateDaysRemaining = [Math]::Floor(
                            ($cert.NotAfter - (Get-Date)).TotalDays
                        )

                        if ((Get-Date) -gt $cert.NotAfter) {
                            $certificateStatus = 'Expired'
                            $evidence = "TLS $($ssl.SslProtocol); certificate expired $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
                        }
                        elseif ((Get-Date) -lt $cert.NotBefore) {
                            $certificateStatus = 'NotYetValid'
                            $evidence = "TLS $($ssl.SslProtocol); certificate is not valid until $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
                        }
                        else {
                            $certificateStatus = 'Valid'
                            $verified = $true
                            $evidence = "TLS $($ssl.SslProtocol); certificate valid until $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
                        }
                    }
                    else {
                        $certificateStatus = 'Missing'
                        $evidence = "TLS $($ssl.SslProtocol); no remote certificate was presented"
                    }
                }
                catch {
                    $cert = $certificateHolder.Certificate
                    if ($null -ne $cert) {
                        $certificateSubject = $cert.Subject
                        $certificateIssuer = $cert.Issuer
                        $certificateNotBefore = $cert.NotBefore
                        $certificateNotAfter = $cert.NotAfter
                        $certificateDaysRemaining = [Math]::Floor(
                            ($cert.NotAfter - (Get-Date)).TotalDays
                        )
                        if ((Get-Date) -gt $cert.NotAfter) {
                            $certificateStatus = 'Expired'
                        }
                        elseif ((Get-Date) -lt $cert.NotBefore) {
                            $certificateStatus = 'NotYetValid'
                        }
                        else {
                            $certificateStatus = 'HandshakeFailed'
                        }
                    }
                    else {
                        $certificateStatus = 'MissingOrHandshakeFailed'
                    }
                    $evidence = "TCP connected, TLS handshake failed: $($_.Exception.Message)"
                }
                finally {
                    $ssl.Dispose()
                    $stream = $null
                }
            }
            465 {
                $protocol = 'SMTPS / Implicit TLS'
                $mailTlsStream = New-Object Net.Security.SslStream($stream,$false,({$true}))
                try {
                    $mailTlsStream.ReadTimeout = $TimeoutMs
                    $mailTlsStream.WriteTimeout = $TimeoutMs
                    $mailTlsStream.AuthenticateAsClient($ComputerName)
                    $cert = if ($mailTlsStream.RemoteCertificate) {
                        New-Object Security.Cryptography.X509Certificates.X509Certificate2 $mailTlsStream.RemoteCertificate
                    } else { $null }
                    if ($null -eq $cert) {
                        $certificateStatus = 'Missing'
                        $evidence = 'TLS established, but no remote certificate was presented'
                    } elseif ((Get-Date) -gt $cert.NotAfter) {
                        $certificateStatus = 'Expired'
                        $evidence = "TLS $($mailTlsStream.SslProtocol); certificate expired $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
                    } elseif ((Get-Date) -lt $cert.NotBefore) {
                        $certificateStatus = 'NotYetValid'
                        $evidence = "TLS $($mailTlsStream.SslProtocol); certificate is not valid until $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
                    } else {
                        $certificateStatus = 'Valid'
                        $verified = $true
                        $evidence = "TLS $($mailTlsStream.SslProtocol); certificate valid until $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
                    }
                } catch {
                    $certificateStatus = 'MissingOrHandshakeFailed'
                    $evidence = "TCP connected, SMTPS TLS handshake failed: $($_.Exception.Message)"
                } finally {
                    $mailTlsStream.Dispose()
                    $stream = $null
                }
            }
            993 {
                $protocol = 'IMAPS / Implicit TLS'
                $mailTlsStream = New-Object Net.Security.SslStream($stream,$false,({$true}))
                try {
                    $mailTlsStream.ReadTimeout = $TimeoutMs
                    $mailTlsStream.WriteTimeout = $TimeoutMs
                    $mailTlsStream.AuthenticateAsClient($ComputerName)
                    $cert = if ($mailTlsStream.RemoteCertificate) { New-Object Security.Cryptography.X509Certificates.X509Certificate2 $mailTlsStream.RemoteCertificate } else { $null }
                    if ($null -eq $cert) { $certificateStatus='Missing';$evidence='TLS established, but no remote certificate was presented' }
                    elseif ((Get-Date)-gt$cert.NotAfter) { $certificateStatus='Expired';$evidence="TLS $($mailTlsStream.SslProtocol); certificate expired $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))" }
                    elseif ((Get-Date)-lt$cert.NotBefore) { $certificateStatus='NotYetValid';$evidence="TLS $($mailTlsStream.SslProtocol); certificate is not valid until $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))" }
                    else { $certificateStatus='Valid';$verified=$true;$evidence="TLS $($mailTlsStream.SslProtocol); certificate valid until $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))" }
                } catch { $certificateStatus='MissingOrHandshakeFailed';$evidence="TCP connected, IMAPS TLS handshake failed: $($_.Exception.Message)" }
                finally { $mailTlsStream.Dispose();$stream=$null }
            }
            995 {
                $protocol = 'POP3S / Implicit TLS'
                $mailTlsStream = New-Object Net.Security.SslStream($stream,$false,({$true}))
                try {
                    $mailTlsStream.ReadTimeout = $TimeoutMs
                    $mailTlsStream.WriteTimeout = $TimeoutMs
                    $mailTlsStream.AuthenticateAsClient($ComputerName)
                    $cert = if ($mailTlsStream.RemoteCertificate) { New-Object Security.Cryptography.X509Certificates.X509Certificate2 $mailTlsStream.RemoteCertificate } else { $null }
                    if ($null -eq $cert) { $certificateStatus='Missing';$evidence='TLS established, but no remote certificate was presented' }
                    elseif ((Get-Date)-gt$cert.NotAfter) { $certificateStatus='Expired';$evidence="TLS $($mailTlsStream.SslProtocol); certificate expired $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))" }
                    elseif ((Get-Date)-lt$cert.NotBefore) { $certificateStatus='NotYetValid';$evidence="TLS $($mailTlsStream.SslProtocol); certificate is not valid until $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))" }
                    else { $certificateStatus='Valid';$verified=$true;$evidence="TLS $($mailTlsStream.SslProtocol); certificate valid until $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))" }
                } catch { $certificateStatus='MissingOrHandshakeFailed';$evidence="TCP connected, POP3S TLS handshake failed: $($_.Exception.Message)" }
                finally { $mailTlsStream.Dispose();$stream=$null }
            }
            3389 {
                $protocol = 'RDP'
                # TPKT + X.224 Connection Request + RDP Negotiation Request.
                [byte[]]$request = @(
                    0x03,0x00,0x00,0x13,
                    0x0e,0xe0,0x00,0x00,0x00,0x00,0x00,
                    0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00
                )
                $stream.Write($request,0,$request.Length)
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 128

                $isTpkt = $reply.Count -ge 11 -and $reply[0] -eq 0x03 -and $reply[1] -eq 0x00
                $isX224Confirm = $isTpkt -and $reply[5] -eq 0xd0
                $isRdpNegotiation = $reply.Count -ge 19 -and $reply[11] -in @(0x02,0x03)

                if ($isX224Confirm -or $isRdpNegotiation) {
                    $verified = $true
                    $evidence = 'RDP X.224 / Negotiation response received'
                } else {
                    $evidence = 'TCP connected, RDP X.224 response not received'
                }
            }
            53 {
                $protocol = 'DNS over TCP'
                $transactionId = Get-Random -Minimum 1 -Maximum 65535
                $query = [Collections.Generic.List[byte]]::new()
                $query.Add([byte]($transactionId -shr 8))
                $query.Add([byte]($transactionId -band 255))
                foreach ($value in @(0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00)) {
                    $query.Add([byte]$value)
                }
                foreach ($label in $ComputerName.Split('.')) {
                    $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
                    $query.Add([byte]$labelBytes.Length)
                    $query.AddRange($labelBytes)
                }
                foreach ($value in @(0x00,0x00,0x01,0x00,0x01)) { $query.Add([byte]$value) }
                $message = $query.ToArray()
                [byte[]]$length = @([byte]($message.Length -shr 8),[byte]($message.Length -band 255))
                $stream.Write($length,0,2)
                $stream.Write($message,0,$message.Length)
                $reply = Read-NetworkBytes -Stream $stream -MaximumBytes 512

                $idMatches = $reply.Count -ge 6 -and
                    $reply[2] -eq ($transactionId -shr 8) -and
                    $reply[3] -eq ($transactionId -band 255)
                $isResponse = $reply.Count -ge 6 -and (($reply[4] -band 0x80) -ne 0)

                if ($idMatches -and $isResponse) {
                    $verified = $true
                    $evidence = 'DNS response transaction matched'
                } else {
                    $evidence = 'TCP connected, valid DNS response not received'
                }
            }
            445 {
                $protocol = 'SMB'
                $evidence = 'TCP connected, SMB protocol not negotiated'
            }
            1433 {
                $protocol = 'Microsoft SQL Server (TDS)'
                $evidence = 'TCP connected, SQL Server TDS protocol not negotiated'
            }
            3306 {
                $protocol = 'MySQL / MariaDB'
                $evidence = 'TCP connected, MySQL protocol not negotiated'
            }
            5432 {
                $protocol = 'PostgreSQL'
                $evidence = 'TCP connected, PostgreSQL protocol not negotiated'
            }
            1521 {
                $protocol = 'Oracle Database Listener'
                $evidence = 'TCP connected, Oracle TNS protocol not negotiated'
            }
            default {
                $protocol = 'Generic TCP'
                $evidence = 'TCP handshake only; application protocol not verified'
            }
        }
    }
    catch {
        $evidence = "TCP connected, protocol validation failed: $($_.Exception.Message)"
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }

    $state = if ($verified) { 'Verified' } else { 'Unverified' }
    return [pscustomobject]@{
        Port=$Port
        State=$state
        TcpSucceeded=$true
        ServiceVerified=$verified
        Protocol=$protocol
        LatencyMs=$connection.LatencyMs
        Evidence=$evidence
        Error=$null
        CertificateStatus=$certificateStatus
        CertificateSubject=$certificateSubject
        CertificateIssuer=$certificateIssuer
        CertificateNotBefore=$certificateNotBefore
        CertificateNotAfter=$certificateNotAfter
        CertificateDaysRemaining=$certificateDaysRemaining
    }
}
function Test-UdpService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateSet(53,123,1434)][int]$Port,
        [ValidateRange(100,30000)][int]$TimeoutMs = 1500
    )

    $udp = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $protocol = switch ($Port) {
        53   { 'DNS over UDP' }
        123  { 'NTP' }
        1434 { 'SQL Server Browser' }
    }

    try {
        $addresses = @([Net.Dns]::GetHostAddresses($ComputerName))
        $address = $addresses |
            Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1
        if (-not $address) {
            throw 'No IPv4 address was available for the UDP probe.'
        }

        $remote = New-Object Net.IPEndPoint($address,$Port)
        $udp = New-Object Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($remote)

        [byte[]]$request = switch ($Port) {
            53 {
                $transactionId = Get-Random -Minimum 1 -Maximum 65535
                $query = New-Object 'System.Collections.Generic.List[byte]'
                $query.Add([byte]($transactionId -shr 8))
                $query.Add([byte]($transactionId -band 255))
                foreach ($value in @(0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00)) {
                    $query.Add([byte]$value)
                }
                foreach ($label in $ComputerName.Split('.')) {
                    $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
                    $query.Add([byte]$labelBytes.Length)
                    $query.AddRange($labelBytes)
                }
                foreach ($value in @(0x00,0x00,0x01,0x00,0x01)) {
                    $query.Add([byte]$value)
                }
                $query.ToArray()
            }
            123 {
                $packet = New-Object byte[] 48
                # LI=0, Version=3, Mode=3 (client).
                $packet[0] = 0x1B
                $packet
            }
            1434 {
                # SQL Server Resolution Protocol CLNT_UCAST_EX request.
                [byte[]](0x02)
            }
        }

        $null = $udp.Send($request,$request.Length)
        $sender = New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
        $response = $udp.Receive([ref]$sender)
        $watch.Stop()

        $verified = $false
        $evidence = ''
        switch ($Port) {
            53 {
                $idMatches = $response.Length -ge 12 -and
                    $response[0] -eq ($transactionId -shr 8) -and
                    $response[1] -eq ($transactionId -band 255)
                $isResponse = $response.Length -ge 12 -and (($response[2] -band 0x80) -ne 0)
                $verified = $idMatches -and $isResponse
                $evidence = if ($verified) {
                    'DNS response transaction matched'
                } else {
                    'A UDP response was received, but it was not a valid matching DNS response'
                }
            }
            123 {
                $mode = if ($response.Length -gt 0) { $response[0] -band 0x07 } else { -1 }
                $verified = $response.Length -ge 48 -and $mode -in @(4,5)
                $evidence = if ($verified) {
                    "NTP response received; mode $mode"
                } else {
                    'A UDP response was received, but it was not a valid NTP server response'
                }
            }
            1434 {
                $verified = $response.Length -gt 1
                if ($verified) {
                    $text = [Text.Encoding]::ASCII.GetString($response).Trim([char]0)
                    $evidence = if ([string]::IsNullOrWhiteSpace($text)) {
                        "SQL Server Browser response received ($($response.Length) bytes)"
                    } else {
                        "SQL Server Browser response: $text"
                    }
                } else {
                    $evidence = 'A UDP response was received, but it was not a valid SQL Server Browser response'
                }
            }
        }

        return [pscustomobject]@{
            Port=$Port
            Transport='UDP'
            Protocol=$protocol
            State=if($verified){'Verified'}else{'ResponseUnverified'}
            ServiceVerified=$verified
            LatencyMs=[Math]::Round($watch.Elapsed.TotalMilliseconds,1)
            Evidence=$evidence
            Error=$null
        }
    }
    catch [Net.Sockets.SocketException] {
        $watch.Stop()
        $socketCode = $_.Exception.SocketErrorCode
        $state = if ($socketCode -in @('TimedOut','WouldBlock')) {
            'NoResponse'
        } elseif ($socketCode -eq 'ConnectionReset') {
            'ClosedOrRejected'
        } else {
            'Error'
        }
        $evidence = switch ($state) {
            'NoResponse'       { 'No UDP response; open, filtered, or silently dropped cannot be distinguished' }
            'ClosedOrRejected' { 'UDP probe was rejected by the remote host or an intermediate device' }
            default            { $socketCode.ToString() }
        }
        return [pscustomobject]@{
            Port=$Port
            Transport='UDP'
            Protocol=$protocol
            State=$state
            ServiceVerified=$false
            LatencyMs=$null
            Evidence=$evidence
            Error=$socketCode.ToString()
        }
    }
    catch {
        $watch.Stop()
        return [pscustomobject]@{
            Port=$Port
            Transport='UDP'
            Protocol=$protocol
            State='Error'
            ServiceVerified=$false
            LatencyMs=$null
            Evidence=$_.Exception.Message
            Error=$_.Exception.Message
        }
    }
    finally {
        if ($udp) { $udp.Dispose() }
    }
}

function Test-TlsVersions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateRange(100,30000)][int]$TimeoutMs = 1500
    )
    $probes = @(
        @{ Name='TLS 1.3'; Flag=[System.Security.Authentication.SslProtocols]12288 },
        @{ Name='TLS 1.2'; Flag=[System.Security.Authentication.SslProtocols]3072 },
        @{ Name='TLS 1.1'; Flag=[System.Security.Authentication.SslProtocols]768 },
        @{ Name='TLS 1.0'; Flag=[System.Security.Authentication.SslProtocols]192 }
    )
    $accepted = New-Object 'System.Collections.Generic.List[string]'
    $cipherSuite = 'N/A'
    foreach ($probe in $probes) {
        $tcp = $null
        $ssl = $null
        $ok = $false
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $ar = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { continue }
            $tcp.EndConnect($ar)
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({$true}))
            $ssl.ReadTimeout = $TimeoutMs
            $ssl.WriteTimeout = $TimeoutMs
            $ssl.AuthenticateAsClient($ComputerName, $null, $probe.Flag, $false)
            $ok = $true
            if ($accepted.Count -eq 0) {
                $suite = $ssl.PSObject.Properties['NegotiatedCipherSuite']
                if ($null -ne $suite -and [string]$suite.Value) {
                    $cipherSuite = [string]$suite.Value
                } else {
                    $cipherSuite = "Cipher: $($ssl.CipherAlgorithm) ($($ssl.CipherStrength) bit)"
                }
            }
        } catch {}
        finally {
            if ($ssl) { $ssl.Dispose() }
            if ($tcp) { $tcp.Dispose() }
        }
        if ($ok) { $accepted.Add($probe.Name) }
    }
    return [pscustomobject]@{
        AcceptedVersions = $accepted.ToArray()
        BestProtocol = if ($accepted.Count -gt 0) { $accepted[0] } else { 'N/A' }
        CipherSuite = $cipherSuite
    }
}

function Get-NegotiatedAlpn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateRange(100,30000)][int]$TimeoutMs = 1500
    )
    if ('System.Net.Security.SslClientAuthenticationOptions' -as [type]) {
        $tcp = $null
        $ssl = $null
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $ar = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return 'N/A (connect timeout)' }
            $tcp.EndConnect($ar)
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({$true}))
            $opts = New-Object System.Net.Security.SslClientAuthenticationOptions
            $opts.TargetHost = $ComputerName
            $alpnList = New-Object 'System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]'
            $alpnList.Add([System.Net.Security.SslApplicationProtocol]::Http2)
            $alpnList.Add([System.Net.Security.SslApplicationProtocol]::Http11)
            $opts.ApplicationProtocols = $alpnList
            $opts.EnabledSslProtocols = (
                [System.Security.Authentication.SslProtocols]12288 -bor
                [System.Security.Authentication.SslProtocols]3072
            )
            $ssl.AuthenticateAsClient($opts)
            $negotiated = $ssl.PSObject.Properties['NegotiatedApplicationProtocol']
            $alpn = if ($null -ne $negotiated -and [string]$negotiated.Value) {
                [string]$negotiated.Value
            } else {
                $null
            }
            if ([string]::IsNullOrWhiteSpace($alpn)) { return 'None (ALPN not negotiated)' }
            return $alpn
        } catch {
            return "N/A ($($_.Exception.Message))"
        }
        finally {
            if ($ssl) { $ssl.Dispose() }
            if ($tcp) { $tcp.Dispose() }
        }
    }
    return 'N/A (ALPN not supported by runtime)'
}

function Test-HttpVersion3 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [ValidateRange(1,120)][int]$TimeoutSec = 5
    )
    if ($PSVersionTable.PSVersion -lt [Version]'7.2') {
        return 'N/A (requires PowerShell 7.2+ / .NET 6+)'
    }
    $client = $null
    $response = $null
    try {
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $request = New-Object System.Net.Http.HttpRequestMessage
        $request.Method = [System.Net.Http.HttpMethod]::Get
        $request.RequestUri = [Uri]$Url
        $request.Version = [Version]::new(3, 0)
        $request.VersionPolicy = [System.Net.Http.HttpVersionPolicy]::RequestVersionExact
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $negotiated = [string]$response.Version
        if ($negotiated -eq '3.0') {
            return 'Supported (HTTP/3 negotiated over UDP/443)'
        }
        return "Not used (server negotiated HTTP/$negotiated)"
    } catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)canceled|timed out|timeout') {
            return 'Unsupported (no HTTP/3/QUIC response received within the timeout)'
        }
        return "Unavailable ($message)"
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

function Test-SecurityHeaderAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][ValidateSet('http','https')][string]$Protocol
    )
    $headerMap = @{}
    try {
        foreach ($key in $Response.Headers.Keys) {
            $value = $Response.Headers[$key]
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $value = @($value) -join ', '
            }
            $headerMap[[string]$key] = [string]$value
        }
    } catch {}

    $checks = @(
        @{ Name='Strict-Transport-Security' },
        @{ Name='Content-Security-Policy' },
        @{ Name='X-Content-Type-Options' },
        @{ Name='X-Frame-Options' },
        @{ Name='Referrer-Policy' },
        @{ Name='Permissions-Policy' }
    )
    $items = New-Object 'System.Collections.Generic.List[object]'
    $passCount = 0
    $failCount = 0
    foreach ($check in $checks) {
        $found = $null
        foreach ($k in $headerMap.Keys) {
            if ($k -ieq $check.Name) { $found = $headerMap[$k]; break }
        }
        $status = 'Fail'
        $detail = 'Missing'
        if ($null -ne $found) {
            switch ($check.Name) {
                'Strict-Transport-Security' {
                    if ($found -match '(?i)max-age=(\d+)') {
                        if ([long]$matches[1] -ge 15552000) {
                            $status = 'Pass'; $detail = "Present, max-age=$($matches[1]) (>= 180 days)"
                        } else {
                            $status = 'Warn'; $detail = "Present, max-age=$($matches[1]) (< 180 days)"
                        }
                    } else {
                        $status = 'Warn'; $detail = 'Present without a valid max-age'
                    }
                }
                'Content-Security-Policy' {
                    if (-not [string]::IsNullOrWhiteSpace($found)) {
                        $status = 'Pass'; $detail = 'Present'
                    } else {
                        $status = 'Fail'; $detail = 'Empty'
                    }
                }
                'X-Content-Type-Options' {
                    if ($found -match '(?i)nosniff') { $status = 'Pass'; $detail = 'nosniff' }
                    else { $status = 'Warn'; $detail = $found }
                }
                'X-Frame-Options' {
                    if ($found -match '(?i)(DENY|SAMEORIGIN)') { $status = 'Pass'; $detail = $found }
                    else { $status = 'Warn'; $detail = $found }
                }
                'Referrer-Policy' {
                    if (-not [string]::IsNullOrWhiteSpace($found)) { $status = 'Pass'; $detail = $found }
                    else { $status = 'Warn'; $detail = 'Empty' }
                }
                'Permissions-Policy' {
                    if (-not [string]::IsNullOrWhiteSpace($found)) { $status = 'Pass'; $detail = $found }
                    else { $status = 'Warn'; $detail = 'Empty' }
                }
            }
        }
        if ($status -eq 'Pass') { $passCount++ }
        if ($status -eq 'Fail') { $failCount++ }
        $items.Add([pscustomobject]@{ Name = $check.Name; Status = $status; Detail = $detail })
    }

    $serverValue = $null
    foreach ($k in $headerMap.Keys) { if ($k -ieq 'Server') { $serverValue = $headerMap[$k]; break } }
    $badges = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $items) {
        $cssClass = switch ($item.Status) {
            'Pass' { 'badge-open' }
            'Warn' { 'badge-warning' }
            default { 'badge-closed' }
        }
        $badges.Add("<span class='badge $cssClass'>$($item.Name): $($item.Status)</span>")
    }
    if ($serverValue) {
        $badges.Add("<span class='badge badge-drop'>Server: $serverValue</span>")
    }

    return [pscustomobject]@{
        ScoreText = "$passCount/$($checks.Count) Pass"
        BadgesHtml = ($badges -join ' ')
        Items = $items.ToArray()
        ServerValue = $serverValue
        HasFailures = ($failCount -gt 0)
    }
}

function Test-WebSecuritySurface {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateSet('http','https')][string]$Protocol,
        [ValidateRange(1,120)][int]$TimeoutSec = 5
    )
    $items = New-Object 'System.Collections.Generic.List[object]'
    $baseUrl = "${Protocol}://${ComputerName}:${Port}/"
    $probeHeaders = @{ 'User-Agent' = 'NetDiag-WebSec/1.0'; 'Accept' = '*/*' }
    $old = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $optionsResponse = $null
        try {
            $optionsResponse = Invoke-WebRequest -Uri $baseUrl -Method Options -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        } catch { $optionsResponse = $null }

        $allowValue = $null
        if ($optionsResponse -and $optionsResponse.Headers) {
            foreach ($k in $optionsResponse.Headers.Keys) { if ($k -ieq 'Allow') { $allowValue = $optionsResponse.Headers[$k]; break } }
        }
        if ($allowValue) {
            $allowed = @($allowValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() })
            $items.Add([pscustomobject]@{ Check='HTTP Methods'; Status='Info'; Detail="Allow: $($allowed -join ', ')" })
            if ($allowed -contains 'PUT') { $items.Add([pscustomobject]@{ Check='PUT'; Status='Danger'; Detail='PUT is allowed' }) }
            if ($allowed -contains 'DELETE') { $items.Add([pscustomobject]@{ Check='DELETE'; Status='Danger'; Detail='DELETE is allowed' }) }
            if ($allowed -contains 'PATCH') { $items.Add([pscustomobject]@{ Check='PATCH'; Status='Warn'; Detail='PATCH is allowed' }) }
        } elseif ($optionsResponse) {
            $items.Add([pscustomobject]@{ Check='HTTP Methods'; Status='Info'; Detail='OPTIONS returned no Allow header' })
        }

        $traceEnabled = $false
        try {
            $traceResponse = Invoke-WebRequest -Uri $baseUrl -Method Trace -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            $traceEnabled = $true
        } catch { $traceEnabled = $false }
        if ($traceEnabled) {
            $items.Add([pscustomobject]@{ Check='TRACE Method'; Status='Danger'; Detail='TRACE is enabled (cross-site tracing risk)' })
        } else {
            $items.Add([pscustomobject]@{ Check='TRACE Method'; Status='Pass'; Detail='TRACE not enabled' })
        }

        $getResponse = $null
        try {
            $getResponse = Invoke-WebRequest -Uri $baseUrl -Method Get -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        } catch { $getResponse = $null }

        if ($getResponse -and $getResponse.Headers) {
            $serverValue = $null
            $xPoweredValues = New-Object 'System.Collections.Generic.List[string]'
            foreach ($k in $getResponse.Headers.Keys) {
                if ($k -ieq 'Server') { $serverValue = [string]$getResponse.Headers[$k] }
                elseif ($k -ieq 'X-Powered-By') { $xPoweredValues.Add([string]$getResponse.Headers[$k]) }
            }
            if ($serverValue) {
                $items.Add([pscustomobject]@{ Check='Server Banner'; Status='Warn'; Detail="Server: $serverValue" })
            } else {
                $items.Add([pscustomobject]@{ Check='Server Banner'; Status='Pass'; Detail='No Server header disclosed' })
            }
            if ($xPoweredValues.Count -gt 0) {
                $items.Add([pscustomobject]@{ Check='X-Powered-By'; Status='Warn'; Detail=("X-Powered-By: " + ($xPoweredValues -join ', ')) })
            }

            $bodyText = ''
            try { $bodyText = [string]$getResponse.Content } catch { $bodyText = '' }
            if ($bodyText -match '(?im)(<title>[^<]*index of[^<]*</title>|index of /\s*<|directory listing for|parent directory</a>|listing directory)') {
                $items.Add([pscustomobject]@{ Check='Directory Listing'; Status='Danger'; Detail='Directory listing appears enabled on /' })
            } else {
                $items.Add([pscustomobject]@{ Check='Directory Listing'; Status='Pass'; Detail='No obvious directory listing on /' })
            }

            $cookieFindings = New-Object 'System.Collections.Generic.List[string]'
            foreach ($k in $getResponse.Headers.Keys) {
                if ($k -ieq 'Set-Cookie') {
                    $cookieHeader = [string]$getResponse.Headers[$k]
                    foreach ($cookieChunk in @($cookieHeader -split ',(?=[^;=\s]+=)')) {
                        $cookieName = (($cookieChunk -split ';')[0]).Trim()
                        if (-not $cookieName) { continue }
                        if ($cookieChunk -notmatch '(?i)\bSecure\b') { $cookieFindings.Add("$cookieName lacks Secure") }
                        if ($cookieChunk -notmatch '(?i)\bHttpOnly\b') { $cookieFindings.Add("$cookieName lacks HttpOnly") }
                        if ($cookieChunk -notmatch '(?i)\bSameSite\b') { $cookieFindings.Add("$cookieName lacks SameSite") }
                    }
                }
            }
            if ($cookieFindings.Count -gt 0) {
                $items.Add([pscustomobject]@{ Check='Cookie Flags'; Status='Warn'; Detail=($cookieFindings -join '; ') })
            }

            try {
                $secAudit = Test-SecurityHeaderAudit -Response $getResponse -Protocol $Protocol
                foreach ($secItem in $secAudit.Items) {
                    if ($secItem.Status -ne 'Pass') {
                        $items.Add([pscustomobject]@{ Check=$secItem.Name; Status=$secItem.Status; Detail=$secItem.Detail })
                    }
                }
            } catch {}
        }

        if ($Protocol -eq 'http') {
            $redirectState = 'no_http'
            $redirectLocation = ''
            try {
                $tcp = New-Object Net.Sockets.TcpClient
                $asyncResult = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
                if ($asyncResult.AsyncWaitHandle.WaitOne(($TimeoutSec * 1000), $false)) {
                    $tcp.EndConnect($asyncResult)
                    $stream = $tcp.GetStream()
                    $stream.ReadTimeout = $TimeoutSec * 1000
                    $stream.WriteTimeout = $TimeoutSec * 1000
                    $requestText = "GET / HTTP/1.1`r`nHost: $ComputerName`r`nConnection: close`r`n`r`n"
                    $requestBytes = [Text.Encoding]::ASCII.GetBytes($requestText)
                    $stream.Write($requestBytes, 0, $requestBytes.Length)
                    $rawResponse = [Text.Encoding]::ASCII.GetString((Read-NetworkBytes -Stream $stream -MaximumBytes 1024))
                    $statusLine = ($rawResponse -split "`r?`n")[0]
                    if ($statusLine -match '^HTTP/\S+\s+(\d{3})') {
                        $statusCode = [int]$matches[1]
                        foreach ($headerLine in ($rawResponse -split "`r?`n")) {
                            if ($headerLine -match '(?i)^Location:\s*(.+)$') { $redirectLocation = $matches[1].Trim(); break }
                        }
                        if ($statusCode -ge 300 -and $statusCode -lt 400) {
                            $redirectState = if ($redirectLocation -match '^https://') { 'to_https' } else { 'not_to_https' }
                        } else {
                            $redirectState = 'no_redirect'
                        }
                    }
                }
                $tcp.Close()
            } catch { $redirectState = 'error' }
            if ($redirectState -eq 'to_https') {
                $items.Add([pscustomobject]@{ Check='HTTP to HTTPS'; Status='Pass'; Detail='HTTP/80 redirects to HTTPS' })
            } elseif ($redirectState -eq 'no_redirect') {
                $items.Add([pscustomobject]@{ Check='HTTP to HTTPS'; Status='Danger'; Detail='HTTP/80 serves content without an HTTPS redirect' })
            } elseif ($redirectState -eq 'not_to_https') {
                $items.Add([pscustomobject]@{ Check='HTTP to HTTPS'; Status='Warn'; Detail="HTTP/80 redirects but not to HTTPS (Location: $redirectLocation)" })
            }
        }
    }
    catch {
        $items.Add([pscustomobject]@{ Check='Probe'; Status='Error'; Detail=$_.Exception.Message })
    }
    finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $old
    }
    return $items.ToArray()
}

function Test-WebPageAnalyzer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateSet('http','https')][string]$Protocol,
        [ValidateRange(1,120)][int]$TimeoutSec = 5
    )
    $items = New-Object 'System.Collections.Generic.List[object]'
    $baseUrl = "${Protocol}://${ComputerName}:${Port}/"
    $probeHeaders = @{ 'User-Agent' = 'NetDiag-WebSec/1.0'; 'Accept' = '*/*' }
    $old = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $openProbeStream = {
            param($probeTarget, [Net.Sockets.TcpClient]$probeTcp)
            $probeNet = $probeTcp.GetStream()
            $probeNet.ReadTimeout = $TimeoutSec * 1000
            $probeNet.WriteTimeout = $TimeoutSec * 1000
            if ($Protocol -eq 'https') {
                $probeSsl = New-Object Net.Security.SslStream($probeNet, $false, { $true })
                $probeSsl.AuthenticateAsClient($probeTarget)
                return $probeSsl
            }
            return $probeNet
        }

        $rawGetProbe = {
            param([string]$rawPath, [hashtable]$extraHeaders, [int]$maximumBytes)
            $probeTcp = New-Object Net.Sockets.TcpClient
            try {
                $connectResult = $probeTcp.BeginConnect($ComputerName, $Port, $null, $null)
                if (-not $connectResult.AsyncWaitHandle.WaitOne(($TimeoutSec * 1000), $false)) { return '' }
                $probeTcp.EndConnect($connectResult)
                $probeNet = & $openProbeStream $ComputerName $probeTcp
                if (-not $probeNet) { return '' }
                try {
                    $requestText = "GET $rawPath HTTP/1.1`r`nHost: ${ComputerName}:${Port}`r`nUser-Agent: NetDiag-WebSec/1.0`r`nConnection: close`r`n"
                    foreach ($headerName in $extraHeaders.Keys) { $requestText += "${headerName}: $($extraHeaders[$headerName])`r`n" }
                    $requestText += "`r`n"
                    $requestBytes = [Text.Encoding]::ASCII.GetBytes($requestText)
                    $probeNet.Write($requestBytes, 0, $requestBytes.Length)
                    return [Text.Encoding]::ASCII.GetString((Read-NetworkBytes -Stream $probeNet -MaximumBytes $maximumBytes))
                } finally {
                    try { $probeNet.Dispose() } catch {}
                }
            } catch { return '' }
            finally { try { $probeTcp.Close() } catch {} }
        }

        $pageResponse = $null
        try { $pageResponse = Invoke-WebRequest -Uri $baseUrl -Method Get -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop } catch { $pageResponse = $null }
        if (-not $pageResponse) { return @($items.ToArray()) }
        $bodyText = ''
        try { $bodyText = [string]$pageResponse.Content } catch { $bodyText = '' }
        $responseHeaders = @{}
        if ($pageResponse.Headers) { foreach ($headerKey in $pageResponse.Headers.Keys) { $responseHeaders[$headerKey] = [string]$pageResponse.Headers[$headerKey] } }

        $rateLimitPatterns = @('x-ratelimit','x-rate-limit','ratelimit','retry-after','x-requests-per')
        $wafMarkers = @('cloudflare','cloudfront','akamai','sucuri','incapsula','imperva','barracuda','fastly','x-cdn','cf-ray','x-waf','aws')
        $floodEvidence = New-Object 'System.Collections.Generic.List[string]'
        foreach ($headerKey in $responseHeaders.Keys) {
            $headerValue = $responseHeaders[$headerKey]
            foreach ($ratePattern in $rateLimitPatterns) { if ($headerKey -like "*$ratePattern*") { $floodEvidence.Add("Rate limiting ($headerKey)"); break } }
            foreach ($wafMarker in $wafMarkers) { if ($headerValue -match $wafMarker -or $headerKey -match $wafMarker) { $floodEvidence.Add("WAF/CDN (${headerKey}: $wafMarker)"); break } }
        }
        if ($floodEvidence.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='HTTP Flood'; Status='Pass'; Detail=("Flood mitigation evidence: " + ($floodEvidence -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='HTTP Flood'; Status='Warn'; Detail='No rate-limiting or WAF/CDN evidence found; GET/POST floods could exhaust server CPU and memory' })
        }

        $heldConnections = 0
        $connectFailures = 0
        $maxHoldMilliseconds = 0
        foreach ($attempt in @(1,2)) {
            $tcp = New-Object Net.Sockets.TcpClient
            $probeNet = $null
            try {
                $connectResult = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
                if (-not $connectResult.AsyncWaitHandle.WaitOne(($TimeoutSec * 1000), $false)) { $connectFailures++; continue }
                $tcp.EndConnect($connectResult)
                $probeNet = & $openProbeStream $ComputerName $tcp
                if (-not $probeNet) { $connectFailures++; continue }
                $partialRequest = "GET / HTTP/1.1`r`nHost: ${ComputerName}:${Port}`r`nUser-Agent: NetDiag-WebSec/1.0`r`nX-NetDiag: "
                $partialBytes = [Text.Encoding]::ASCII.GetBytes($partialRequest)
                $probeNet.Write($partialBytes, 0, $partialBytes.Length)
                $probeBuffer = New-Object byte[] 1
                $readResult = $probeNet.BeginRead($probeBuffer, 0, 1, $null, $null)
                $stopwatch = [Diagnostics.Stopwatch]::StartNew()
                $responded = $false
                $closed = $false
                while ($stopwatch.ElapsedMilliseconds -lt ($TimeoutSec * 1000)) {
                    Start-Sleep -Milliseconds 150
                    if ($readResult.IsCompleted) { if ($probeBuffer[0] -ne 0) { $responded = $true } else { $closed = $true }; break }
                }
                $stopwatch.Stop()
                if ($readResult.IsCompleted) { try { $null = $probeNet.EndRead($readResult) } catch {} }
                if ($stopwatch.ElapsedMilliseconds -gt $maxHoldMilliseconds) { $maxHoldMilliseconds = [int]$stopwatch.ElapsedMilliseconds }
                if ($responded) { break }
                if (-not $closed) { $heldConnections++ }
            } catch { $connectFailures++ }
            finally {
                try { if ($probeNet) { $probeNet.Dispose() } } catch {}
                try { $tcp.Close() } catch {}
            }
        }
        if ($connectFailures -ge 2) {
            $items.Add([pscustomobject]@{ Check='Slowloris'; Status='Error'; Detail='Slowloris probe connections could not be established' })
        } elseif ($heldConnections -ge 1) {
            $items.Add([pscustomobject]@{ Check='Slowloris'; Status='Warn'; Detail="Server kept $heldConnections open connection(s) alive for >${maxHoldMilliseconds} ms with a partial request; Slowloris-style resource tie-up is possible" })
        } else {
            $items.Add([pscustomobject]@{ Check='Slowloris'; Status='Pass'; Detail='Server closed or answered partial requests quickly (connection timeout configured)' })
        }

        $formBlocks = @([regex]::Matches($bodyText, '(?is)<form\b[^>]*>.*?</form>'))
        $postFormsWithoutToken = New-Object 'System.Collections.Generic.List[string]'
        $injectionCandidates = New-Object 'System.Collections.Generic.List[string]'
        $seenCandidate = @{}
        foreach ($formBlock in $formBlocks) {
            $action = '/'
            if ($formBlock.Value -match '(?i)\baction\s*=\s*["'']([^"'']+)["'']') { $action = $matches[1] }
            $method = 'get'
            if ($formBlock.Value -match '(?i)\bmethod\s*=\s*["''](post|get)["'']') { $method = $matches[1].ToLowerInvariant() }
            $hasCsrfToken = $formBlock.Value -match '(?i)\bname\s*=\s*["''](?:[^"'']*(?:csrf|token|authenticity)[^"'']*)["'']'
            foreach ($inputMatch in @([regex]::Matches($formBlock.Value, '(?i)<input\b[^>]*\bname\s*=\s*["'']([^"'']+)["'']'))) {
                $fieldName = $inputMatch.Groups[1].Value
                if ($fieldName -and -not $seenCandidate.ContainsKey($fieldName)) { $seenCandidate[$fieldName] = $true; $injectionCandidates.Add($fieldName) }
            }
            if ($method -eq 'post' -and -not $hasCsrfToken) { $postFormsWithoutToken.Add($action) }
        }
        if ($postFormsWithoutToken.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='CSRF'; Status='Warn'; Detail=("POST form(s) without a visible CSRF token: " + ($postFormsWithoutToken -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='CSRF'; Status='Pass'; Detail='No POST form without a visible CSRF token found' })
        }

        foreach ($commonParam in @('id','q','search','name','page','user','category','file','url','pid','product','cmd','query','login','email')) {
            if (-not $seenCandidate.ContainsKey($commonParam)) { $seenCandidate[$commonParam] = $true; $injectionCandidates.Add($commonParam) }
        }
        $probeParams = @($injectionCandidates | Select-Object -First 3)
        $sqlErrorPattern = '(?i)sql\s*syntax|sqlstate|ora-\d{5}|unclosed quotation|microsoft\s+ole\s+db|mysql_\w+\(|postgresql.*error|syntax\s+error\s+near|you\s+have\s+an\s+error\s+in\s+your\s+sql|quoted\s+string\s+not\s+properly\s+terminated|division\s+by\s+zero\s+in|sqlite'

        $sqlInjectionFound = $null
        foreach ($param in $probeParams) {
            if ($sqlInjectionFound) { break }
            foreach ($payload in @("'", "1%27OR%271%27%3D%271", "1%27AND%20%27x%27%3D%27x")) {
                try {
                    $probe = Invoke-WebRequest -Uri "${baseUrl}?${param}=${payload}" -Method Get -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
                    $probeBody = ''
                    try { $probeBody = [string]$probe.Content } catch { $probeBody = '' }
                    if ($probeBody -match $sqlErrorPattern) { $sqlInjectionFound = $param; break }
                } catch {}
            }
        }
        if ($sqlInjectionFound) {
            $items.Add([pscustomobject]@{ Check='SQL Injection'; Status='Danger'; Detail="SQL error signature found while probing parameter '$sqlInjectionFound'; SQL injection is possible" })
        } else {
            $items.Add([pscustomobject]@{ Check='SQL Injection'; Status='Pass'; Detail='No SQL error signature observed in URL parameter probes' })
        }

        $xssReflected = $null
        foreach ($param in $probeParams) {
            if ($xssReflected) { break }
            $payload = '%3Cscript%3Enetdiagxss%3C%2Fscript%3E'
            try {
                $probe = Invoke-WebRequest -Uri "${baseUrl}?${param}=${payload}" -Method Get -Headers $probeHeaders -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
                $probeBody = ''
                try { $probeBody = [string]$probe.Content } catch { $probeBody = '' }
                if ($probeBody -match '(?i)<script>netdiagxss</script>|netdiagxss') { $xssReflected = $param; break }
            } catch {}
        }
        if ($xssReflected) {
            $items.Add([pscustomobject]@{ Check='XSS'; Status='Warn'; Detail="JavaScript payload reflected by parameter '$xssReflected'; reflected XSS is possible" })
        } else {
            $items.Add([pscustomobject]@{ Check='XSS'; Status='Pass'; Detail='No obvious reflection of a script payload in URL parameter probes' })
        }

        $hostHeaderValue = 'netdiag-test.invalid'
        $hostReflected = $false
        $hostResponseStatus = ''
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $probeNet = $null
            try {
                $connectResult = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
                if ($connectResult.AsyncWaitHandle.WaitOne(($TimeoutSec * 1000), $false)) {
                    $tcp.EndConnect($connectResult)
                    $probeNet = & $openProbeStream $ComputerName $tcp
                    if ($probeNet) {
                        $requestText = "GET / HTTP/1.1`r`nHost: $hostHeaderValue`r`nUser-Agent: NetDiag-WebSec/1.0`r`nConnection: close`r`n`r`n"
                        $requestBytes = [Text.Encoding]::ASCII.GetBytes($requestText)
                        $probeNet.Write($requestBytes, 0, $requestBytes.Length)
                        $rawHostResponse = [Text.Encoding]::ASCII.GetString((Read-NetworkBytes -Stream $probeNet -MaximumBytes 2048))
                        if ($rawHostResponse -match '^HTTP/\S+\s+(\d{3})') { $hostResponseStatus = $matches[1] }
                        if ($rawHostResponse -match [regex]::Escape($hostHeaderValue)) { $hostReflected = $true }
                    }
                }
            }
            finally {
                try { if ($probeNet) { $probeNet.Dispose() } } catch {}
                try { $tcp.Close() } catch {}
            }
        } catch {}
        if ($hostReflected) {
            $items.Add([pscustomobject]@{ Check='HTTP Host Header'; Status='Warn'; Detail="Arbitrary Host header value was reflected in the response; host-header poisoning (cache/password reset) is possible" })
        } elseif ($hostResponseStatus -eq '200') {
            $items.Add([pscustomobject]@{ Check='HTTP Host Header'; Status='Warn'; Detail='Unknown Host header was accepted with a 200 response; host-header validation may be missing' })
        } elseif ($hostResponseStatus) {
            $items.Add([pscustomobject]@{ Check='HTTP Host Header'; Status='Pass'; Detail="Unknown Host header rejected (HTTP $hostResponseStatus); no reflection observed" })
        } else {
            $items.Add([pscustomobject]@{ Check='HTTP Host Header'; Status='Error'; Detail='Host header probe did not produce a response' })
        }

        $crlfFound = $false
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $probeNet = $null
            try {
                $connectResult = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
                if ($connectResult.AsyncWaitHandle.WaitOne(($TimeoutSec * 1000), $false)) {
                    $tcp.EndConnect($connectResult)
                    $probeNet = & $openProbeStream $ComputerName $tcp
                    if ($probeNet) {
                        $requestText = "GET /?q=%0d%0aX-NetDiag-Test:%20netdiagcrlf%0d%0aX-Extra:%201 HTTP/1.1`r`nHost: ${ComputerName}:${Port}`r`nUser-Agent: NetDiag-WebSec/1.0`r`nConnection: close`r`n`r`n"
                        $requestBytes = [Text.Encoding]::ASCII.GetBytes($requestText)
                        $probeNet.Write($requestBytes, 0, $requestBytes.Length)
                        $rawCrlfResponse = [Text.Encoding]::ASCII.GetString((Read-NetworkBytes -Stream $probeNet -MaximumBytes 2048))
                        if ($rawCrlfResponse -match '(?im)^X-NetDiag-Test:\s*netdiagcrlf') { $crlfFound = $true }
                    }
                }
            }
            finally {
                try { if ($probeNet) { $probeNet.Dispose() } } catch {}
                try { $tcp.Close() } catch {}
            }
        } catch {}
        if ($crlfFound) {
            $items.Add([pscustomobject]@{ Check='CRLF Injection'; Status='Danger'; Detail='Injected CRLF header was returned by the server; HTTP response splitting is possible' })
        } else {
            $items.Add([pscustomobject]@{ Check='CRLF Injection'; Status='Pass'; Detail='No injected header observed in the response' })
        }

        $openRedirectFound = $null
        foreach ($redirectParam in @('url','redirect','next','return','rurl','dest','destination','go')) {
            if ($openRedirectFound) { break }
            $openRedirectUrl = 'http://evil.example/netdiag-open-redirect'
            $redirectResponse = & $rawGetProbe ("/?${redirectParam}=" + [Uri]::EscapeDataString($openRedirectUrl)) @{} 1536
            if ($redirectResponse -match '^HTTP/\S+\s+30\d' -and $redirectResponse -match '(?im)^Location:\s*' + [regex]::Escape($openRedirectUrl)) { $openRedirectFound = $redirectParam; break }
            if ($redirectResponse -match '(?i)(location\.href|location\.replace|document\.location|window\.location)\s*=\s*[''"][^''"]*' + [regex]::Escape($openRedirectUrl)) { $openRedirectFound = $redirectParam; break }
        }
        if ($openRedirectFound) {
            $items.Add([pscustomobject]@{ Check='Open Redirect'; Status='Warn'; Detail="Parameter '$openRedirectFound' produced a redirect to an external URL; open-redirect (phishing) risk" })
        } else {
            $items.Add([pscustomobject]@{ Check='Open Redirect'; Status='Pass'; Detail='No external-URL redirect observed in common redirect parameters' })
        }

        $corsProbeOrigin = 'http://evil.example'
        $corsRawResponse = & $rawGetProbe '/' @{ 'Origin' = $corsProbeOrigin } 2048
        $corsAllowOrigin = ''
        $corsAllowCredentials = ''
        foreach ($corsLine in @($corsRawResponse -split "`r?`n")) {
            if ($corsLine -match '(?i)^Access-Control-Allow-Origin:\s*([^\r\n]+)') { $corsAllowOrigin = $matches[1].Trim() }
            if ($corsLine -match '(?i)^Access-Control-Allow-Credentials:\s*([^\r\n]+)') { $corsAllowCredentials = $matches[1].Trim() }
        }
        if ($corsAllowOrigin -eq $corsProbeOrigin) {
            if ($corsAllowCredentials -match '^true$') {
                $items.Add([pscustomobject]@{ Check='CORS'; Status='Danger'; Detail='Arbitrary Origin reflected in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials: true; cross-origin credentialed data theft is possible' })
            } else {
                $items.Add([pscustomobject]@{ Check='CORS'; Status='Warn'; Detail='Access-Control-Allow-Origin reflects the request Origin header; any site could read same-origin responses' })
            }
        } elseif ($corsAllowOrigin -and $corsAllowOrigin -ne '*') {
            $items.Add([pscustomobject]@{ Check='CORS'; Status='Pass'; Detail="CORS does not reflect an arbitrary Origin (Access-Control-Allow-Origin: $corsAllowOrigin)" })
        } else {
            $items.Add([pscustomobject]@{ Check='CORS'; Status='Pass'; Detail='No permissive CORS Allow-Origin reflection observed' })
        }

        $sensitivePathProbes = @(
            @{ Url='/.git/HEAD'; Pattern='(?i)ref:\s*refs/heads' },
            @{ Url='/.git/config'; Pattern='(?i)\[core\]' },
            @{ Url='/.env'; Pattern='(?i)(secret|password|api[_-]?key|token|aws_)=' },
            @{ Url='/WEB-INF/web.xml'; Pattern='(?i)(<web-app|servlet-class)' },
            @{ Url='/server-status'; Pattern='(?i)apache\s+server\s+status' },
            @{ Url='/.htaccess'; Pattern='(?i)(RewriteEngine|Deny\s+from|AllowOverride)' },
            @{ Url='/.DS_Store'; Pattern='Bud1' }
        )
        $exposedFiles = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sensitiveProbe in $sensitivePathProbes) {
            if ($exposedFiles.Count -ge 3) { break }
            $sensitiveResponse = & $rawGetProbe $sensitiveProbe.Url @{} 1536
            if ($sensitiveResponse -match '^HTTP/\S+\s+200' -and $sensitiveResponse -match $sensitiveProbe.Pattern) { $exposedFiles.Add($sensitiveProbe.Url) }
        }
        if ($exposedFiles.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Sensitive File Exposure'; Status='Danger'; Detail=("Sensitive file(s) accessible over HTTP: " + ($exposedFiles -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='Sensitive File Exposure'; Status='Pass'; Detail='No well-known sensitive files (.git, .env, WEB-INF, server-status, .htaccess) were exposed' })
        }

        $traversalFound = $null
        foreach ($traversalPayload in @('/..%2f..%2f..%2f..%2fetc%2fpasswd','/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd','/%2e%2e/%2e%2e/%2e%2e/etc/passwd')) {
            $traversalResponse = & $rawGetProbe $traversalPayload @{} 1536
            if ($traversalResponse -match '^HTTP/\S+\s+200' -and $traversalResponse -match '(?m)^root:[^:]*:0:0:|/etc/passwd') { $traversalFound = $traversalPayload; break }
        }
        if ($traversalFound) {
            $items.Add([pscustomobject]@{ Check='Path Traversal'; Status='Danger'; Detail=("Encoded traversal probe returned /etc/passwd content (payload: $traversalFound); directory traversal is possible" ) })
        } else {
            $items.Add([pscustomobject]@{ Check='Path Traversal'; Status='Pass'; Detail='No file-system content returned for encoded traversal probes' })
        }

        if ($Protocol -eq 'https') {
            $mixedContentMatches = @([regex]::Matches($bodyText, '(?i)\b(?:src|href)\s*=\s*[''"]http://[^''"]+'))
            if ($mixedContentMatches.Count -gt 0) {
                $sampleMixedUrls = @($mixedContentMatches | ForEach-Object { $_.Value } | Select-Object -First 3)
                $items.Add([pscustomobject]@{ Check='Mixed Content'; Status='Warn'; Detail=("HTTPS page references $($mixedContentMatches.Count) http:// resource(s): " + ($sampleMixedUrls -join '; ')) })
            } else {
                $items.Add([pscustomobject]@{ Check='Mixed Content'; Status='Pass'; Detail='No http:// resource references found on the HTTPS page' })
            }
        }

        $scriptTagMatches = @([regex]::Matches($bodyText, '(?i)<script\b[^>]*\bsrc\s*=\s*[''"]([^''"]+)[''"][^>]*>'))
        $scriptsWithoutSri = New-Object 'System.Collections.Generic.List[string]'
        foreach ($scriptMatch in $scriptTagMatches) {
            if ($scriptMatch.Value -notmatch '(?i)\bintegrity\s*=') { $scriptsWithoutSri.Add($scriptMatch.Groups[1].Value) }
        }
        if ($scriptTagMatches.Count -gt 0 -and $scriptsWithoutSri.Count -gt 0) {
            $sampleScripts = @($scriptsWithoutSri | Select-Object -First 3)
            $items.Add([pscustomobject]@{ Check='Subresource Integrity'; Status='Info'; Detail=("$($scriptsWithoutSri.Count) of $($scriptTagMatches.Count) external script(s) lack Subresource Integrity checks: " + ($sampleScripts -join '; ')) })
        } elseif ($scriptTagMatches.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Subresource Integrity'; Status='Pass'; Detail='All external scripts include Subresource Integrity (integrity=) attributes' })
        }

        $robotsRaw = & $rawGetProbe '/robots.txt' @{} 2048
        if ($robotsRaw -match '^HTTP/\S+\s+200') {
            $robotsDisallow = [regex]::Matches($robotsRaw, '(?mi)^\s*Disallow:\s*\S')
            $robotsSitemap = [regex]::Matches($robotsRaw, '(?mi)^\s*Sitemap:\s*\S')
            if ($robotsSitemap.Count -eq 0 -and $robotsDisallow.Count -gt 0) {
                $items.Add([pscustomobject]@{ Check='robots.txt'; Status='Warn'; Detail="robots.txt contains $($robotsDisallow.Count) Disallow rule(s) but no Sitemap directive" })
            } elseif ($robotsDisallow.Count -eq 0) {
                $items.Add([pscustomobject]@{ Check='robots.txt'; Status='Warn'; Detail='robots.txt allows access to all paths; no Disallow rules are defined' })
            } else {
                $items.Add([pscustomobject]@{ Check='robots.txt'; Status='Pass'; Detail="robots.txt present with $($robotsDisallow.Count) Disallow rule(s) and $($robotsSitemap.Count) Sitemap directive(s)" })
            }
        } else {
            $items.Add([pscustomobject]@{ Check='robots.txt'; Status='Info'; Detail='No robots.txt found on the server' })
        }

        $clientAccessFiles = @('/clientaccesspolicy.xml', '/crossdomain.xml')
        $clientAccessExposed = New-Object 'System.Collections.Generic.List[string]'
        foreach ($caFile in $clientAccessFiles) {
            $caResponse = & $rawGetProbe $caFile @{} 1536
            if ($caResponse -match '^HTTP/\S+\s+200' -and $caResponse -match '(?i)(<allow-access-from|<domain-config|<cross-domain-policy)') {
                $clientAccessExposed.Add($caFile)
            }
        }
        if ($clientAccessExposed.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Client Access Policy'; Status='Warn'; Detail=("Cross-domain policy file(s) exposed: " + ($clientAccessExposed -join '; ') + "; may allow unauthorized cross-origin access") })
        } else {
            $items.Add([pscustomobject]@{ Check='Client Access Policy'; Status='Pass'; Detail='No clientaccesspolicy.xml or crossdomain.xml found' })
        }

        $secTxtRaw = & $rawGetProbe '/.well-known/security.txt' @{} 2048
        if ($secTxtRaw -match '^HTTP/\S+\s+200' -and $secTxtRaw -match '(?i)(Contact|Contact:|Policy:|Encryption:)') {
            $items.Add([pscustomobject]@{ Check='security.txt'; Status='Pass'; Detail='security.txt found with disclosure contact information' })
        } elseif ($secTxtRaw -match '^HTTP/\S+\s+200') {
            $items.Add([pscustomobject]@{ Check='security.txt'; Status='Warn'; Detail='security.txt found but is missing required fields (Contact/Policy/Encryption)' })
        } else {
            $items.Add([pscustomobject]@{ Check='security.txt'; Status='Warn'; Detail='No security.txt found at /.well-known/security.txt; vulnerability disclosure contact is not published' })
        }

        $sensitiveFilePatterns = @(
            @{ Url='/.git/HEAD'; Pattern='(?i)ref:\s*refs/heads' },
            @{ Url='/.env'; Pattern='(?i)(secret|password|api[_-]?key|token|aws_)=' },
            @{ Url='/.env.bak'; Pattern='(?i)(secret|password|api[_-]?key|token)=' },
            @{ Url='/config.php.bak'; Pattern='(?i)(password|db_pass|mysql_connect|mysqli_connect)' },
            @{ Url='/config.php~'; Pattern='(?i)(password|db_pass|mysql_connect|mysqli_connect)' },
            @{ Url='/config.yml'; Pattern='(?i)(password|secret|api_key|token):' },
            @{ Url='/config.json'; Pattern='(?i)"(password|secret|api_key|token)"\s*:' },
            @{ Url='/database.sql'; Pattern='(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)' },
            @{ Url='/dump.sql'; Pattern='(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)' },
            @{ Url='/backup.zip'; Pattern='(?s)PK\x03\x04' },
            @{ Url='/backup.tar.gz'; Pattern='(?s)\x1f\x8b\x08' },
            @{ Url='/db.sql'; Pattern='(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)' },
            @{ Url='/debug.log'; Pattern='(?i)(stack trace|exception|traceback|at\s+\S+\.\w+\(\))' },
            @{ Url='/phpinfo.php'; Pattern='(?i)phpinfo\(\)' },
            @{ Url='/WEB-INF/web.xml'; Pattern='(?i)(<web-app|servlet-class)' },
            @{ Url='/server-status'; Pattern='(?i)apache\s+server\s+status' },
            @{ Url='/.htaccess'; Pattern='(?i)(RewriteEngine|Deny\s+from|AllowOverride)' }
        )
        $sensitiveHits = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sensitivePattern in $sensitiveFilePatterns) {
            if ($sensitiveHits.Count -ge 3) { break }
            $sensitiveResponse = & $rawGetProbe $sensitivePattern.Url @{} 1536
            if ($sensitiveResponse -match '^HTTP/\S+\s+200' -and $sensitiveResponse -match $sensitivePattern.Pattern) { $sensitiveHits.Add($sensitivePattern.Url) }
        }
        if ($sensitiveHits.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Sensitive Files'; Status='Danger'; Detail=("Sensitive file(s) accessible: " + ($sensitiveHits -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='Sensitive Files'; Status='Pass'; Detail='No known sensitive files (backups, dumps, configs, debug logs, .env, phpinfo) were accessible' })
        }

        $disclosureMarkers = @('x-debug','x-debug-token','x-debug-bar','x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator','x-drupal','x-varnish','x-oss','x-request-id','x-runtime','x-trace','server:')
        $disclosureFound = New-Object 'System.Collections.Generic.List[string]'
        foreach ($headerKey in $responseHeaders.Keys) {
            foreach ($marker in $disclosureMarkers) {
                if ($headerKey -like "*$marker*") {
                    $disclosureFound.Add("${headerKey}: $(($responseHeaders[$headerKey]).Substring(0, [Math]::Min(40, ($responseHeaders[$headerKey]).Length)))")
                    break
                }
            }
        }
        if ($pageResponse.StatusCode -ge 500) {
            if ($bodyText -match '(?i)(stack trace|exception|traceback|debug|error in|line \d+|file:.*line:)') { $disclosureFound.Add('Verbose error page with stack trace or debug info') }
        }
        if ($disclosureFound.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Information Disclosure'; Status='Warn'; Detail=("Information-disclosure markers found: " + ($disclosureFound -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='Information Disclosure'; Status='Pass'; Detail='No information-disclosure markers found in response headers or error pages' })
        }

        $cleartextCredentialForms = New-Object 'System.Collections.Generic.List[string]'
        foreach ($formBlock in $formBlocks) {
            $action = '/'
            if ($formBlock.Value -match '(?i)\baction\s*=\s*["'']([^"'']+)["'']') { $action = $matches[1] }
            $hasPasswordField = $formBlock.Value -match '(?i)<input\b[^>]*\btype\s*=\s*["'']password["'']'
            if ($hasPasswordField) {
                $formIsHttp = $false
                if ($action -match '^https?://') { $formIsHttp = $action -match '^http://' }
                elseif ($Protocol -eq 'http') { $formIsHttp = $true }
                if ($formIsHttp) { $cleartextCredentialForms.Add($action) }
            }
        }
        if ($cleartextCredentialForms.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Cleartext Credentials'; Status='Danger'; Detail=("Password field(s) found in forms submitting to plain HTTP: " + ($cleartextCredentialForms -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='Cleartext Credentials'; Status='Pass'; Detail='No password fields found submitting to plain HTTP' })
        }

        $commentPatterns = @('(?i)<!--.*?(password|secret|api[_-]?key|token|todo|fixme|hack|bug|debug|internal|admin)', '(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*[''"][^''"]{4,}', '(?i)(mysql_connect|mysqli_connect|pg_connect|new\s+PDO)\s*\(')
        $commentMatches = New-Object 'System.Collections.Generic.List[string]'
        foreach ($commentPattern in $commentPatterns) {
            $foundComments = @([regex]::Matches($bodyText, $commentPattern))
            foreach ($cm in $foundComments) {
                if ($commentMatches.Count -ge 3) { break }
                $snippet = $cm.Value.Substring(0, [Math]::Min(80, $cm.Value.Length))
                if (-not ($commentMatches -contains $snippet)) { $commentMatches.Add($snippet) }
            }
        }
        if ($commentMatches.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Commented Code'; Status='Info'; Detail=("Sensitive commented code or debug info found: " + ($commentMatches -join '; ')) })
        } else {
            $items.Add([pscustomobject]@{ Check='Commented Code'; Status='Pass'; Detail='No sensitive commented code or debug information found in page source' })
        }

        $loginPaths = @('/wp-login.php','/wp-admin/','/administrator/','/login','/signin','/auth','/cpanel','/phpmyadmin/','/console')
        $accessiblePaths = New-Object 'System.Collections.Generic.List[string]'
        $loginFormFound = $false
        foreach ($fb in $formBlocks) {
            if ($fb.Value -match '(?i)<input\b[^>]*\btype\s*=\s*["'']password["'']') { $loginFormFound = $true; break }
        }
        foreach ($loginPath in $loginPaths) {
            $loginProbe = & $rawGetProbe $loginPath @{} 1024
            if ($loginProbe -match '^HTTP/\S+\s+200' -or $loginProbe -match '^HTTP/\S+\s+3\d\d') { $accessiblePaths.Add($loginPath) }
        }
        if ($loginFormFound -and $accessiblePaths.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Login Interface'; Status='Info'; Detail="Login form on page; accessible admin/login paths: " + ($accessiblePaths -join '; ') })
        } elseif ($loginFormFound) {
            $items.Add([pscustomobject]@{ Check='Login Interface'; Status='Info'; Detail='Login form detected on the page' })
        } elseif ($accessiblePaths.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Login Interface'; Status='Info'; Detail="Accessible admin/login paths: " + ($accessiblePaths -join '; ') })
        }

        $jsLibPatterns = @(
            @{ Pattern='(?i)jquery[.-](\d+\.\d+\.\d+)'; Name='jQuery' },
            @{ Pattern='(?i)bootstrap[.-](\d+\.\d+\.\d+)'; Name='Bootstrap' },
            @{ Pattern='(?i)angular[.-](\d+\.\d+\.\d+)'; Name='AngularJS' },
            @{ Pattern='(?i)prototype[.-](\d+\.\d+\.\d+)'; Name='Prototype.js' },
            @{ Pattern='(?i)mootools[.-](\d+\.\d+\.\d+)'; Name='MooTools' },
            @{ Pattern='(?i)script\.aculo\.us[.-](\d+\.\d+\.\d+)'; Name='Script.aculo.us' },
            @{ Pattern='(?i)dojo[.-](\d+\.\d+\.\d+)'; Name='Dojo' },
            @{ Pattern='(?i)backbone[.-](\d+\.\d+\.\d+)'; Name='Backbone.js' },
            @{ Pattern='(?i)underscore[.-](\d+\.\d+\.\d+)'; Name='Underscore.js' }
        )
        $outdatedLibs = New-Object 'System.Collections.Generic.List[string]'
        foreach ($lib in $jsLibPatterns) {
            $libMatches = @([regex]::Matches($bodyText, $lib.Pattern))
            foreach ($lm in $libMatches) {
                $version = $lm.Groups[1].Value
                $outdatedLibs.Add("$($lib.Name) v$version")
            }
        }
        $outdatedLibs = @($outdatedLibs | Select-Object -Unique)
        if ($outdatedLibs.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Outdated JS Libraries'; Status='Warn'; Detail=("Potentially outdated JavaScript libraries detected: " + ($outdatedLibs -join '; ')) })
        }

        $adminPaths = @('/admin/','/admin.php','/administrator/','/manager/','/panel/','/dashboard/','/phpmyadmin/','/pma/','/adminer.php','/wp-admin/','/cgi-bin/','/server-info','/server-status')
        $exposedAdminPaths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($adminPath in $adminPaths) {
            if ($exposedAdminPaths.Count -ge 3) { break }
            $adminProbe = & $rawGetProbe $adminPath @{} 1024
            if ($adminProbe -match '^HTTP/\S+\s+200') { $exposedAdminPaths.Add($adminPath) }
        }
        if ($exposedAdminPaths.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Admin Pages'; Status='Warn'; Detail=("Potentially exposed admin pages: " + ($exposedAdminPaths -join '; ')) })
        }

        $configIssues = New-Object 'System.Collections.Generic.List[string]'
        if ($responseHeaders.ContainsKey('Allow') -and $responseHeaders['Allow'] -match '(?i)TRACK|TRACE') { $configIssues.Add('HTTP TRACK/TRACE method appears enabled') }
        if ($Protocol -eq 'https') {
            $hstsPresent = @($responseHeaders.Keys | Where-Object { $_ -match '(?i)^Strict-Transport-Security$' })
            $cspPresent = @($responseHeaders.Keys | Where-Object { $_ -match '(?i)^Content-Security-Policy$' })
            $xctoPresent = @($responseHeaders.Keys | Where-Object { $_ -match '(?i)^X-Content-Type-Options$' })
            $xfoPresent = @($responseHeaders.Keys | Where-Object { $_ -match '(?i)^X-Frame-Options$' })
            if ($hstsPresent.Count -eq 0) { $configIssues.Add('HSTS header missing on HTTPS site') }
            if ($cspPresent.Count -eq 0) { $configIssues.Add('Content-Security-Policy header missing') }
            if ($xctoPresent.Count -eq 0) { $configIssues.Add('X-Content-Type-Options header missing') }
            if ($xfoPresent.Count -eq 0) { $configIssues.Add('X-Frame-Options header missing') }
        }
        if ($pageResponse.StatusCode -ge 500 -and $bodyText -match '(?i)(stack trace|exception|traceback|debug|error in|line \d+|file:.*line:)') { $configIssues.Add('Server returns verbose error pages with stack traces') }
        if ($configIssues.Count -gt 0) {
            $items.Add([pscustomobject]@{ Check='Server Misconfiguration'; Status='Warn'; Detail=("Configuration issues found: " + ($configIssues -join '; ')) })
        }

        if ($Protocol -eq 'http') {
            $items.Add([pscustomobject]@{ Check='Man-in-the-Middle'; Status='Danger'; Detail='Plain HTTP carries traffic in clear text; traffic can be intercepted or altered between the user and the server' })
        } else {
            $hstsHeader = @($responseHeaders.Keys | Where-Object { $_ -match '(?i)^Strict-Transport-Security$' })
            if ($hstsHeader.Count -gt 0) {
                $items.Add([pscustomobject]@{ Check='Man-in-the-Middle'; Status='Pass'; Detail='TLS encrypts traffic and HSTS is configured' })
            } else {
                $items.Add([pscustomobject]@{ Check='Man-in-the-Middle'; Status='Warn'; Detail='TLS encrypts traffic but HSTS is missing; first-request downgrade attacks remain possible' })
            }
        }
    }
    catch {
        $items.Add([pscustomobject]@{ Check='Page Analyzer'; Status='Error'; Detail=$_.Exception.Message })
    }
    finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $old
    }
    return @($items.ToArray())
}

function Get-GeoIpInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$IPAddresses,
        [ValidateRange(1,30)][int]$TimeoutSec = 6
    )
    try {
        $body = @($IPAddresses | ForEach-Object {
            @{ query = $_; fields = 'query,country,regionName,city,isp,org,as,asname' }
        }) | ConvertTo-Json -Depth 4
        $headers = @{ 'User-Agent' = 'NetDiag-PowerShell' }
        $resp = Invoke-RestMethod -Uri 'http://ip-api.com/batch' -Method Post -Body $body `
            -ContentType 'application/json' -Headers $headers -TimeoutSec $TimeoutSec -ErrorAction Stop
        return @($resp)
    } catch {
        return @()
    }
}

function Get-DnsSecurityStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$LocalA,
        [string[]]$CloudflareUdpA,
        [ValidateRange(1,30)][int]$HttpTimeoutSec = 5
    )

    $dnss = 'Not DNSSEC signed'
    try {
        $dnssecResults = @(Resolve-DnsName $Name -Type A -DnssecOk -Server '1.1.1.1' -ErrorAction Stop)
        $rrsig = @($dnssecResults | Where-Object { $_.Type -eq 'RRSIG' -or $_.QueryType -eq 'RRSIG' })
        if ($rrsig.Count -gt 0) { $dnss = 'Signed (RRSIG validated via 1.1.1.1)' }
    } catch {
        if ($_.Exception.Message -match '(?i)server failure|servfail|failed|validation') {
            $dnss = 'Validation failed (SERVFAIL from validating resolver)'
        } else {
            $dnss = 'Status unavailable'
        }
    }

    $dotResults = New-Object 'System.Collections.Generic.List[string]'
    $dotResolvers = @(
        @{ Host = '1.1.1.1'; Sni = 'cloudflare-dns.com' },
        @{ Host = '8.8.8.8'; Sni = 'dns.google' }
    )
    foreach ($dotResolver in $dotResolvers) {
        $ok = $false
        $elapsed = $null
        $tc = $null
        $ssl = $null
        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $tc = New-Object Net.Sockets.TcpClient
            $ar = $tc.BeginConnect($dotResolver.Host, 853, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(3500, $false)) { throw 'DoT connect timeout' }
            $tc.EndConnect($ar)
            $ssl = New-Object Net.Security.SslStream($tc.GetStream(), $false, {$true})
            $ssl.ReadTimeout = 3500
            $ssl.WriteTimeout = 3500
            $ssl.AuthenticateAsClient($dotResolver.Sni)

            $transactionId = Get-Random -Minimum 1 -Maximum 65535
            $query = [Collections.Generic.List[byte]]::new()
            $query.Add([byte]($transactionId -shr 8))
            $query.Add([byte]($transactionId -band 255))
            foreach ($value in @(0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00)) { $query.Add([byte]$value) }
            foreach ($label in $Name.Split('.')) {
                $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
                $query.Add([byte]$labelBytes.Length)
                $query.AddRange($labelBytes)
            }
            foreach ($value in @(0x00,0x00,0x01,0x00,0x01)) { $query.Add([byte]$value) }
            $message = $query.ToArray()
            [byte[]]$length = @([byte]($message.Length -shr 8),[byte]($message.Length -band 255))
            $ssl.Write($length, 0, 2)
            $ssl.Write($message, 0, $message.Length)
            $ssl.Flush()
            $reply = Read-NetworkBytes -Stream $ssl -MaximumBytes 512
            $sw.Stop()
            $elapsed = [Math]::Round($sw.Elapsed.TotalMilliseconds)
            $idMatches = $reply.Count -ge 6 -and
                $reply[2] -eq ($transactionId -shr 8) -and
                $reply[3] -eq ($transactionId -band 255)
            $isResponse = $reply.Count -ge 6 -and (($reply[4] -band 0x80) -ne 0)
            $ok = ($idMatches -and $isResponse)
        } catch {
            if ($sw) { $sw.Stop() }
            $ok = $false
        } finally {
            if ($ssl) { try { $ssl.Dispose() } catch {} }
            if ($tc) { try { $tc.Dispose() } catch {} }
        }
        if ($ok) { $dotResults.Add("$($dotResolver.Host):853 OK (${elapsed} ms)") }
        else { $dotResults.Add("$($dotResolver.Host):853 FAIL") }
    }

    $dohResults = New-Object 'System.Collections.Generic.List[string]'
    $dohAnswers = @()
    $dohEndpoints = @(
        @{ Label = 'cloudflare-dns.com'; Uri = "https://cloudflare-dns.com/dns-query?name=$Name&type=A" },
        @{ Label = 'dns.google'; Uri = "https://dns.google/resolve?name=$Name&type=A" }
    )
    $oldSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        foreach ($ep in $dohEndpoints) {
            try {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $json = Invoke-RestMethod -Uri $ep.Uri -Headers @{ Accept = 'application/dns-json' } `
                    -TimeoutSec $HttpTimeoutSec -ErrorAction Stop
                $sw.Stop()
                if ($json.Status -eq 0) {
                    $answers = @($json.Answer | Where-Object { $_.type -eq 1 } | Select-Object -ExpandProperty data)
                    if ($ep.Label -like 'cloudflare*') { $dohAnswers = $answers }
                    $dohResults.Add("$($ep.Label): OK ($([Math]::Round($sw.Elapsed.TotalMilliseconds)) ms)")
                } else {
                    $dohResults.Add("$($ep.Label): RCODE $($json.Status)")
                }
            } catch {
                $dohResults.Add("$($ep.Label): FAIL")
            }
        }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $oldSecurityProtocol
    }

    $distinctSets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($set in @($LocalA, $CloudflareUdpA, $dohAnswers)) {
        $clean = @($set | Where-Object { $_ } | Sort-Object -Unique)
        if ($clean.Count -gt 0) { $distinctSets.Add($clean) }
    }
    $uniqueSets = New-Object 'System.Collections.Generic.List[object]'
    $uniqueKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($set in $distinctSets) {
        $key = ($set -join ',')
        if (-not $uniqueKeys.Contains($key)) { $uniqueKeys.Add($key); $uniqueSets.Add($set) }
    }
    if ($uniqueSets.Count -eq 0) { $consistency = 'No answer to compare' }
    elseif ($uniqueSets.Count -eq 1) { $consistency = 'Consistent (all resolvers returned the same IP set)' }
    else { $consistency = 'Differences detected between resolvers' }

    return [pscustomobject]@{
        DNSSEC = $dnss
        DoT = ($dotResults -join '; ')
        DoH = ($dohResults -join '; ')
        Consistency = $consistency
    }
}

function Test-CertificateChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ExpectedName,
        [switch]$UseRevocation
    )
    $sanDns = New-Object 'System.Collections.Generic.List[string]'
    $sanIps = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($ext in $Certificate.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.17') {
                $formatted = $ext.Format($true)
                foreach ($line in ($formatted -split "`r?`n")) {
                    if ($line -match 'DNS Name=(.+?)\s*$') { $sanDns.Add($matches[1].Trim()) }
                    elseif ($line -match 'IP Address=(.+?)\s*$') { $sanIps.Add($matches[1].Trim()) }
                }
            }
        }
    } catch {}
    $sanText = New-Object 'System.Collections.Generic.List[string]'
    if ($sanDns.Count -gt 0) { $sanText.Add('DNS: ' + ($sanDns -join ', ')) }
    if ($sanIps.Count -gt 0) { $sanText.Add('IP: ' + ($sanIps -join ', ')) }
    $san = if ($sanText.Count -gt 0) { $sanText -join '; ' } else { $Certificate.Subject }

    $matched = $false
    if ($ExpectedName) {
        $parsed = $null
        if ([Net.IPAddress]::TryParse($ExpectedName, [ref]$parsed)) {
            $matched = $sanIps -contains $ExpectedName
        } else {
            $expected = $ExpectedName.TrimEnd('.').ToLowerInvariant()
            foreach ($entry in $sanDns) {
                $name = $entry.TrimEnd('.').ToLowerInvariant()
                if ($name -eq $expected) { $matched = $true; break }
                if ($name.StartsWith('*.') -and $expected.EndsWith($name.Substring(1))) { $matched = $true; break }
            }
        }
    }

    $chainValid = $false
    $chainStatus = New-Object 'System.Collections.Generic.List[string]'
    $revocation = 'N/A'
    try {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = if ($UseRevocation) {
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        } else {
            [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        }
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chainValid = $chain.Build($Certificate)
        $statusFlags = New-Object 'System.Collections.Generic.List[object]'
        foreach ($el in $chain.ChainElements) {
            foreach ($st in $el.ChainElementStatus) {
                if ($st.Status -ne [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError) {
                    $statusFlags.Add($st.Status)
                    $chainStatus.Add($st.Status.ToString())
                }
            }
        }
        $revoked = $statusFlags.Contains([Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked)
        $unknown = $statusFlags.Contains([Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown)
        if ($revoked) { $revocation = 'Revoked' }
        elseif ($unknown) { $revocation = 'Could not verify (revocation status unknown)' }
        elseif ($UseRevocation) { $revocation = 'No revocation detected' }
    } catch {
        $chainValid = $false
        $chainStatus.Add("Chain build error: $($_.Exception.Message)")
    }

    return [pscustomobject]@{
        San = $san
        SanMatch = $matched
        ChainValid = $chainValid
        ChainStatus = if ($chainStatus.Count -gt 0) { $chainStatus -join '; ' } else { 'OK' }
        Revocation = $revocation
    }
}

function Get-WifiInfo {
    [CmdletBinding()]
    param()
    $result = [ordered]@{}
    try {
        $wlanRaw = & netsh wlan show interfaces 2>$null
        if (-not $wlanRaw) { return $null }
        $joined = $wlanRaw -join "`n"
        if ($joined -match '(?im)^\s*(SSID|SSID Numarası)\s*:\s*(.+)\s*$') { $result.Ssid = $matches[2].Trim() }
        if ($joined -match '(?im)^\s*(Signal|Sinyal)\s*:\s*(\d{1,3})\s*%') { $result.SignalPercent = $matches[2] }
        if ($joined -match '(?im)^\s*(Radio type|Radyo türü)\s*:\s*(.+)\s*$') { $result.RadioType = $matches[2].Trim() }
        if ($joined -match '(?im)^\s*(Channel|Kanal)\s*:\s*(\d+)') { $result.Channel = $matches[2] }
        if ($joined -match '(?im)^\s*(Receive rate \(Mbps\)|Alma hızı \(Mbps\)|Alış hızı \(Mbps\))\s*:\s*(\d+)') { $result.RxMbps = $matches[2] }
        if ($joined -match '(?im)^\s*(Transmit rate \(Mbps\)|Gönderme hızı \(Mbps\)|Gönderim hızı \(Mbps\))\s*:\s*(\d+)') { $result.TxMbps = $matches[2] }
        if ($result.Count -eq 0) { return $null }
        return [pscustomobject]$result
    } catch {
        return $null
    }
}

function Get-AdapterHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InterfaceDescription
    )
    try {
        $stats = Get-NetAdapterStatistics -ErrorAction Stop |
            Where-Object { $_.InterfaceDescription -eq $InterfaceDescription } |
            Select-Object -First 1
        if (-not $stats) { return $null }
        return [pscustomobject]@{
            RxErrors = $stats.ReceivedPacketErrors
            TxErrors = $stats.OutboundPacketErrors
            RxDiscarded = $stats.ReceivedDiscardedPackets
            TxDiscarded = $stats.OutboundDiscardedPackets
        }
    } catch {
        return $null
    }
}

function Test-ScriptUpdate {
    Write-Host "[*] $(ConvertTo-LocalizedText 'Güncellemeler kontrol ediliyor')..." -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $headers=@{'User-Agent'='NetDiag-PowerShell'}
        $response=Invoke-RestMethod -Uri $GitHubApiUrl -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $latest=[string]$response.sha
        if ($latest.Length -lt 7) { throw 'Geçersiz commit yanıtı.' }
        $latest=$latest.Substring(0,7)
        if ($LocalCommit -eq $latest) { Write-Status UPDATE "Script güncel ($CurrentCommit)." Green;return }
        Write-Status UPDATE (ConvertTo-LocalizedText "Güncelleme mevcut. Yerel sürüm: $LocalCommit | uzak sürüm: $latest") Yellow
        Write-Host (ConvertTo-LocalizedText '    Güncelleme mevcut script dosyasını doğruladıktan sonra değiştirecektir.') -ForegroundColor DarkGray
        $yesNoLabel = Get-LocalizedYesNoLabel
        $updateAnswer = Read-LocalizedHost " -> Güncellensin mi? ($yesNoLabel)"
        if (-not $Host.UI.RawUI -or -not (Test-LocalizedYesResponse -Answer $updateAnswer -DefaultYes $false)) { return }
        $tempFile=Join-Path ([IO.Path]::GetTempPath()) ("netdiag_{0}.ps1" -f [guid]::NewGuid().ToString('N'))
        try {
            $raw=(Invoke-WebRequest -Uri $GitHubRawUrl -Headers $headers -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop).Content
            if ([string]::IsNullOrWhiteSpace($raw) -or $raw -notmatch '(?i)CmdletBinding|param\s*\(') { throw 'İndirilen içerik PowerShell scripti görünmüyor.' }
            $raw=($raw -replace '(?<=LocalCommit\s*=\s*["''])([a-f0-9]{7})(?=["''])',$latest)
            [IO.File]::WriteAllText($tempFile,$raw,(New-Object Text.UTF8Encoding($false)))
            $tokens=$null;$parseErrors=$null
            [Management.Automation.Language.Parser]::ParseFile($tempFile,[ref]$tokens,[ref]$parseErrors)|Out-Null
            if ($parseErrors.Count -gt 0) { throw "Yeni sürüm parse doğrulamasından geçemedi: $($parseErrors[0].Message)" }
            Copy-Item $tempFile $PSCommandPath -Force
            Write-Status UPDATE 'Güncellendi; script aynı terminal oturumunda yeniden başlatılıyor.' Green

            # Invoke the updated script in the CURRENT PowerShell host.
            # Do not use Start-Process: it opens a separate pwsh/powershell console window
            # instead of continuing in the active Windows Terminal tab.
            $restartParameters = @{
                Language = $Script:LanguageCode
            }

            try {
                & $PSCommandPath @restartParameters
                exit
            }
            catch {
                Write-Status UPDATE (ConvertTo-LocalizedText "Script aynı terminalde yeniden başlatılamadı: $($_.Exception.Message)") Red
                Write-Host (ConvertTo-LocalizedText 'Yeni sürümü manuel başlatın') -ForegroundColor Yellow
                Write-Host "$(ConvertTo-LocalizedText 'Yeniden başlatma komutu'): & `"$PSCommandPath`" -Language $Script:LanguageCode" -ForegroundColor Yellow
                return
            }
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
    Write-Host (ConvertTo-LocalizedText '    Özel TCP port listesi virgülle ayrılmış. Boş bırakılırsa seviye varsayılanı kullanılır.') -ForegroundColor DarkGray
    $Ports = Read-LocalizedHost ' -> Özel portlar [opsiyonel]'
    Write-Host "`n$(ConvertTo-LocalizedText 'Test seviyesini seçin:')" -ForegroundColor Yellow
    Write-Host " [1] Low     - $(ConvertTo-LocalizedText 'Hızlı erişilebilirlik: envanter, DNS, ICMP, MTU ve seçilen TCP portu.')" -ForegroundColor White
    Write-Host " [2] Medium  - $(ConvertTo-LocalizedText 'Standart ağ analizi: Low testlerine ek olarak temel port matrisi ve rota/jitter.')" -ForegroundColor White
    Write-Host " [3] Deep    - $(ConvertTo-LocalizedText 'Ayrıntılı teşhis: geniş port matrisi, rota/jitter, SSL ve HTTP analizi.')" -ForegroundColor White
    Write-Host " [4] JMeter  - $(ConvertTo-LocalizedText 'Yük testi: Deep ağ ölçümlerine ek olarak gelişmiş eşzamanlı HTTP testi.')" -ForegroundColor White
    Write-Host " [5] WebSec  - $(ConvertTo-LocalizedText 'Web güvenliği: tüm Deep analizine ek olarak eşzamanlı HTTP yük testi, HTTP/HTTPS servisleri için yaygın web saldırı yüzeyi ve çözüm önerileri.')" -ForegroundColor White
    do {$v=Read-LocalizedHost ' -> Seviye [3]';if(-not $v){$v='3'}}while($v -notin @('1','2','3','4','5'))
    $ScanLevel=@{'1'='Low';'2'='Medium';'3'='Deep';'4'='JMeter';'5'='WebSec'}[$v]
    if ($ScanLevel -ne 'Low') {
        Write-Host (ConvertTo-LocalizedText '    Her rota adımına gönderilecek ICMP paketi sayısı. Daha yüksek değer daha güvenilir fakat daha yavaştır.') -ForegroundColor DarkGray
        $v = Read-LocalizedHost ' -> Hop başına ping [5]'; if ($v) { $HopPingCount = [int]$v }
    }
    if($ScanLevel -in @('JMeter','WebSec')){
        Write-Host (ConvertTo-LocalizedText '    Aynı anda gönderilebilecek en yüksek HTTP isteği sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Eşzamanlı kullanıcı [10]';if($v){$JMeterThreads=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Ana yük testi boyunca gönderilecek toplam HTTP isteği.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Toplam istek [200]';if($v){$JMeterTotalRequests=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Yanıt gövdesinde aranacak metin. Boş bırakılırsa içerik doğrulaması yapılmaz.') -ForegroundColor DarkGray
        $JMeterAssertText=Read-LocalizedHost ' -> Assertion metni [opsiyonel]'
        Write-Host (ConvertTo-LocalizedText '    Uçtan uca RTT ve jitter için hedefe gönderilecek ICMP paketi sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Hedef jitter paket sayısı [20]';if($v){$DestinationPingCount=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Ölçüme dahil edilmeyen, bağlantı ve önbellekleri hazırlayan istek sayısı.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Warm-up istek sayısı [5]';if($v){$JMeterWarmupRequests=[int]$v}
        Write-Host (ConvertTo-LocalizedText '    Eşzamanlı yükün kademeli olarak artırılacağı süre.') -ForegroundColor DarkGray
        $v=Read-LocalizedHost ' -> Ramp-up süresi saniye [2]';if($v){$JMeterRampUpSeconds=[int]$v}
    } elseif ($ScanLevel -in @('Low','Medium','Deep')) {
        $v=Read-LocalizedHost ' -> Harici JTL/CSV yolu [opsiyonel]';if($v-and(Test-Path $v)){$JMeterCsvPath=$v}
    }
    $yesNoLabel = Get-LocalizedYesNoLabel
    $defaultYesLabel = Get-LocalizedDefaultYesLabel
    Write-Host (ConvertTo-LocalizedText '    GeoIP/ASN zenginleştirme; hedef ve yol IP adreslerini üçüncü taraf ip-api.com servisine gönderir.') -ForegroundColor DarkGray
    $v = Read-LocalizedHost " -> GeoIP/ASN zenginleştirme? ($yesNoLabel) [$defaultYesLabel]"
    if (-not (Test-LocalizedYesResponse -Answer $v -DefaultYes $true)) { $SkipGeoIp = $true }
    Write-Host (ConvertTo-LocalizedText '    Rapor; ölçümleri, korelasyon sonucunu, uyarıları ve hop tablosunu içerir.') -ForegroundColor DarkGray
    $v = Read-LocalizedHost " -> HTML rapor kaydedilsin mi? ($yesNoLabel) [$defaultYesLabel]"
    if (Test-LocalizedYesResponse -Answer $v -DefaultYes $true) {
        $dir=if($PSScriptRoot){$PSScriptRoot}else{(Get-Location).Path}
        $default=Join-Path $dir ("NetDiag_NetworkReport_{0}.html" -f ($Target-replace'[^a-zA-Z0-9]','_'))
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
    $wifiInfo = Get-WifiInfo
    $adapterHealth = if ($adapter) { Get-AdapterHealth -InterfaceDescription $adapter.InterfaceDescription } else { $null }
    $cpuLoad = $null
    $cpuLoadSource = $null

    # 1. Preferred source: formatted performance data. It does not require the
    # Win32_Processor.LoadPercentage provider to publish a value.
    try {
        $perfCpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
            -Filter "Name='_Total'" `
            -ErrorAction Stop
        if ($null -ne $perfCpu.PercentProcessorTime) {
            $cpuLoad = [Math]::Round([double]$perfCpu.PercentProcessorTime)
            $cpuLoadSource = 'CIM Performance Counter'
        }
    } catch {}

    # 2. Fallback: Get-Counter when the formatted CIM class is unavailable.
    if ($null -eq $cpuLoad) {
        try {
            $counter = Get-Counter '\Processor(_Total)\% Processor Time' `
                -SampleInterval 1 `
                -MaxSamples 2 `
                -ErrorAction Stop
            $counterValues = @(
                $counter.CounterSamples |
                    Where-Object { $null -ne $_.CookedValue } |
                    Select-Object -ExpandProperty CookedValue
            )
            if ($counterValues.Count -gt 0) {
                $cpuLoad = [Math]::Round(
                    ($counterValues | Measure-Object -Average).Average
                )
                $cpuLoadSource = 'Performance Counter'
            }
        } catch {}
    }

    # 3. Last fallback: Win32_Processor.LoadPercentage.
    if ($null -eq $cpuLoad) {
        $cpuLoadSamples = @(
            Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
                Where-Object { $null -ne $_.LoadPercentage } |
                Select-Object -ExpandProperty LoadPercentage
        )
        if ($cpuLoadSamples.Count -gt 0) {
            $cpuLoad = [Math]::Round(
                ($cpuLoadSamples | Measure-Object -Average).Average
            )
            $cpuLoadSource = 'Win32_Processor'
        }
    }

    if ($null -eq $cpuLoad) {
        $cpuLoad = 'N/A'
        $cpuLoadSource = if ($Script:LanguageCode -eq 'tr') {
            'Kullanılabilir CPU sayacı bulunamadı'
        } else {
            'No available CPU counter'
        }
    }
    $cpuCurrentLabel = if ($Script:LanguageCode -eq 'tr') {
        'Anlık'
    } else {
        'Current'
    }
    $total=[Math]::Round($os.TotalVisibleMemorySize/1MB,1);$free=[Math]::Round($os.FreePhysicalMemory/1MB,1);$used=[Math]::Round($total-$free,1);$pct=if($total){[Math]::Round($used/$total*100)}else{0}
    $diskText=($disks|ForEach-Object{$size=[Math]::Round($_.Size/1GB,1);$df=[Math]::Round($_.FreeSpace/1GB,1);$dp=if($_.Size){[Math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100)}else{0};"$($_.DeviceID) (Toplam ${size}GB, Boş ${df}GB, Doluluk %$dp)"})-join' | '
    $ReportData.Env_User="$env:USERDOMAIN\$env:USERNAME";$ReportData.Env_ComputerName=$env:COMPUTERNAME;$ReportData.Env_OS=$os.Caption.Trim();$ReportData.Env_CPU="$($cpu.Name) ($cpuCurrentLabel %$cpuLoad)";$ReportData.Env_CPU_Source=$cpuLoadSource;    $ReportData.Env_Memory="Toplam ${total}GB | Kullanılan ${used}GB (%$pct)";$ReportData.Env_Disk=$diskText;$ReportData.Env_LocalIP="$ip ($adapterName)"
    $ReportData.Wifi_Ssid=if($wifiInfo){$wifiInfo.Ssid}else{'N/A'};$ReportData.Wifi_Signal_Percent=if($wifiInfo){$wifiInfo.SignalPercent}else{'N/A'};$ReportData.Wifi_Channel=if($wifiInfo){$wifiInfo.Channel}else{'N/A'};$ReportData.Wifi_Radio_Type=if($wifiInfo){$wifiInfo.RadioType}else{'N/A'};$ReportData.Wifi_Rx_Mbps=if($wifiInfo){$wifiInfo.RxMbps}else{'N/A'};$ReportData.Wifi_Tx_Mbps=if($wifiInfo){$wifiInfo.TxMbps}else{'N/A'}
    $ReportData.Adapter_Status=if($adapter){$adapter.Status}else{'N/A'};$ReportData.Adapter_Link_Speed=if($adapter){$adapter.LinkSpeed}else{'N/A'};$ReportData.Adapter_Media=if($adapter){$adapter.MediaType}else{'N/A'};$ReportData.Adapter_Packet_Errors=if($adapterHealth){"RX $($adapterHealth.RxErrors) / TX $($adapterHealth.TxErrors) errors; RX $($adapterHealth.RxDiscarded) / TX $($adapterHealth.TxDiscarded) discarded"}else{'N/A'}
    if($wifiInfo -and $wifiInfo.Ssid){Write-Status WIFI "$($wifiInfo.Ssid) | Sinyal %$($wifiInfo.SignalPercent) | Kanal $($wifiInfo.Channel) | $($wifiInfo.RadioType) | RX $($wifiInfo.RxMbps) Mbps / TX $($wifiInfo.TxMbps) Mbps" $(if([int]$wifiInfo.SignalPercent -ge 50){'Green'}else{'Yellow'})}
    Write-Status ENV "CPU %$cpuLoad ($cpuLoadSource) | RAM %$pct | IP $ip" $(if($cpuLoad-eq'N/A'){'Yellow'}else{'Green'})
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
    if(($ScanLevel -in @('Medium','Deep','JMeter','WebSec')) -and $Target -ne $targetIP){try{$pub=@(Resolve-DnsName $Target -Server 8.8.8.8 -ErrorAction Stop|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress -Unique);if($pub){$ReportData.Public_DNS_IP=$pub-join', ';if($targetIP -notin $pub){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] DNS MISMATCH: Yerel $targetIP, public $($pub-join', '). Split-DNS ihtimalini inceleyin.")}else{$AdvisorNotes.Add("[!] DNS MISMATCH: Local $targetIP, public $($pub-join', '). Investigate the Split-DNS possibility.")}}}}catch{}}
    try{$ptr=(Resolve-DnsName $targetIP -Type PTR -ErrorAction Stop).NameHost;if($ptr){$ReportData.Reverse_DNS=$ptr-join', '}}catch{}
    if($Target -ne $targetIP -and $ScanLevel -in @('Medium','Deep','JMeter','WebSec')){
        $dnsSec=Get-DnsSecurityStatus -Name $Target -LocalA $ips -CloudflareUdpA $cloudflare -HttpTimeoutSec $HttpTimeoutSec
        $ReportData.DNSSEC_Status=$dnsSec.DNSSEC;$ReportData.DNS_DoT_Status=$dnsSec.DoT;$ReportData.DNS_DoH_Status=$dnsSec.DoH;$ReportData.DNS_Resolver_Consistency=$dnsSec.Consistency
        Write-Status DNSSEC $dnsSec.DNSSEC $(if($dnsSec.DNSSEC -like 'Signed*'){'Green'}elseif($dnsSec.DNSSEC -like 'Validation failed*'){'Red'}else{'Yellow'})
        Write-Status DoT $dnsSec.DoT Green
        Write-Status DoH $dnsSec.DoH Green
        Write-Status 'DNS-CONSISTENCY' $dnsSec.Consistency $(if($dnsSec.Consistency -like 'Consistent*'){'Green'}else{'Yellow'})
        if($dnsSec.Consistency -notlike 'Consistent*' -and $dnsSec.Consistency -ne 'No answer to compare'){
            if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] $($dnsSec.Consistency); farklı DNS çözümleyicileri farklı IP seti döndürdü.")}else{$AdvisorNotes.Add("[!] $($dnsSec.Consistency); different DNS resolvers returned different IP sets.")}
        }
        if($dnsSec.DNSSEC -like 'Signed*'){
            if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[i] Alan adı DNSSEC imzalı; kimlik doğrulama zinciri güçlendirilmiş.')}else{$AdvisorNotes.Add('[i] The domain is DNSSEC-signed; the authentication chain is strengthened.')}
        }
    }

    # DNS exposure checks: MX, TXT (SPF/DMARC/DKIM), CAA
    if ($Target -ne $targetIP -and $ScanLevel -in @('Medium','Deep','JMeter','WebSec')) {
        Write-Status DNS 'DNS sızıntı kayıtları kontrol ediliyor (MX, SPF, DMARC, DKIM, CAA)...' Cyan
        $dnsExposure = @()
        $dnsExposureFound = New-Object 'System.Collections.Generic.List[string]'
        $dnsExposureMissing = New-Object 'System.Collections.Generic.List[string]'

        # MX records
        try {
            $mxRecords = @(Resolve-DnsName $Target -Type MX -ErrorAction SilentlyContinue | Sort-Object Preference | Select-Object Preference, NameExchange -Unique)
            if ($mxRecords.Count -gt 0) {
                $mxList = [string]::Join('; ', @($mxRecords | ForEach-Object { "Priority $($_.Preference): $($_.NameExchange)" }))
                $ReportData.DNS_MX_Records = $mxList
                $dnsExposure += [pscustomobject]@{ Type='MX'; Detail=$mxList; Risk='Info' }
                $dnsExposureFound.Add('MX') | Out-Null
                # Check for external mail providers
                $externalMx = $mxRecords | Where-Object { $_.NameExchange -notmatch "\.$(($Target -split '\.')[-2..-1] -join '\.')$" }
                if ($externalMx.Count -gt 0) {
                    $extList = [string]::Join('; ', @($externalMx | ForEach-Object { $_.NameExchange }))
                    $dnsExposure += [pscustomobject]@{ Type='MX-External'; Detail="External mail providers: $extList"; Risk='Warn' }
                    if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] MX kayıtları harici posta sağlayıcılarını işaret ediyor: $extList")}else{$AdvisorNotes.Add("[!] MX records point to external mail providers: $extList")}
                }
            } else {
                $ReportData.DNS_MX_Records = 'MX kaydı bulunamadı.'
                $dnsExposure += [pscustomobject]@{ Type='MX'; Detail='MX kaydı bulunamadı.'; Risk='Info' }
                $dnsExposureMissing.Add('MX') | Out-Null
                Write-Status 'DNS-MX' 'MX kaydı bulunamadı.' Yellow
            }
        } catch { $ReportData.DNS_MX_Records = 'Query failed'; $dnsExposureMissing.Add('MX') | Out-Null }

        # SPF record (TXT with v=spf1)
        try {
            $txtRecords = @(Resolve-DnsName $Target -Type TXT -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue)
            $spfRecord = $txtRecords | Where-Object { $_ -like 'v=spf1*' } | Select-Object -First 1
            if ($spfRecord) {
                $ReportData.DNS_SPF_Record = $spfRecord
                $dnsExposure += [pscustomobject]@{ Type='SPF'; Detail=$spfRecord; Risk='Info' }
                $dnsExposureFound.Add('SPF') | Out-Null
                # Check SPF all mechanism
                if ($spfRecord -notmatch '\-all') {
                    if ($spfRecord -match '~all') { $risk='Warn'; $msg='SPF uses soft fail (~all); consider hard fail (-all)' }
                    elseif ($spfRecord -match '\+all') { $risk='Danger'; $msg='SPF allows all (+all); misconfiguration risk' }
                    else { $risk='Warn'; $msg='SPF missing explicit all mechanism' }
                    $dnsExposure += [pscustomobject]@{ Type='SPF-Policy'; Detail=$msg; Risk=$risk }
                    if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] SPF politikası: $msg")}else{$AdvisorNotes.Add("[!] SPF policy: $msg")}
                }
            } else {
                $ReportData.DNS_SPF_Record = 'SPF kaydı bulunamadı.'
                $dnsExposure += [pscustomobject]@{ Type='SPF'; Detail='SPF kaydı bulunamadı.'; Risk='Warn' }
                $dnsExposureMissing.Add('SPF') | Out-Null
                Write-Status 'DNS-SPF' 'SPF kaydı bulunamadı.' Yellow
                if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] SPF kaydı bulunamadı; e-posta sahteciliği riski.')}else{$AdvisorNotes.Add('[!] SPF record missing; email spoofing risk.')}
            }
        } catch { $ReportData.DNS_SPF_Record = 'Query failed'; $dnsExposureMissing.Add('SPF') | Out-Null }

        # DMARC record
        try {
            $dmarcRecords = @(Resolve-DnsName "_dmarc.$Target" -Type TXT -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue)
            $dmarcRecord = $dmarcRecords | Where-Object { $_ -like 'v=DMARC1*' } | Select-Object -First 1
            if ($dmarcRecord) {
                $ReportData.DNS_DMARC_Record = $dmarcRecord
                $dnsExposure += [pscustomobject]@{ Type='DMARC'; Detail=$dmarcRecord; Risk='Info' }
                $dnsExposureFound.Add('DMARC') | Out-Null
                # Check DMARC policy
                if ($dmarcRecord -notmatch 'p=reject') {
                    if ($dmarcRecord -match 'p=quarantine') { $risk='Warn'; $msg='DMARC policy is quarantine; consider p=reject' }
                    elseif ($dmarcRecord -match 'p=none') { $risk='Warn'; $msg='DMARC policy is none (monitor only); no enforcement' }
                    else { $risk='Warn'; $msg='DMARC missing explicit policy' }
                    $dnsExposure += [pscustomobject]@{ Type='DMARC-Policy'; Detail=$msg; Risk=$risk }
                    if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] DMARC politikası: $msg")}else{$AdvisorNotes.Add("[!] DMARC policy: $msg")}
                }
            } else {
                $ReportData.DNS_DMARC_Record = 'DMARC kaydı bulunamadı.'
                $dnsExposure += [pscustomobject]@{ Type='DMARC'; Detail='DMARC kaydı bulunamadı.'; Risk='Warn' }
                $dnsExposureMissing.Add('DMARC') | Out-Null
                Write-Status 'DNS-DMARC' 'DMARC kaydı bulunamadı.' Yellow
                if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] DMARC kaydı bulunamadı; e-posta sahteciliği koruması yok.')}else{$AdvisorNotes.Add('[!] DMARC record missing; no email spoofing protection.')}
            }
        } catch { $ReportData.DNS_DMARC_Record = 'Query failed'; $dnsExposureMissing.Add('DMARC') | Out-Null }

        # DKIM selectors (common ones)
        $dkimSelectors = @('default','selector1','selector2','google','k1','k2','mail','dkim','s1','s2')
        $dkimFound = $false
        foreach ($sel in $dkimSelectors) {
            try {
                $dkimRecords = @(Resolve-DnsName "$sel._domainkey.$Target" -Type TXT -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue)
                $dkimRecord = $dkimRecords | Where-Object { $_ -like 'v=DKIM1*' } | Select-Object -First 1
                if ($dkimRecord) {
                    $ReportData.DNS_DKIM_Record = "Selector: $sel - $dkimRecord"
                    $dnsExposure += [pscustomobject]@{ Type='DKIM'; Detail="Selector ${sel}: $dkimRecord"; Risk='Info' }
                    $dnsExposureFound.Add('DKIM') | Out-Null
                    $dkimFound = $true
                    break
                }
            } catch {}
        }
        if (-not $dkimFound) {
            $ReportData.DNS_DKIM_Record = 'DKIM kaydı bulunamadı.'
            $dnsExposure += [pscustomobject]@{ Type='DKIM'; Detail='DKIM kaydı bulunamadı.'; Risk='Warn' }
            $dnsExposureMissing.Add('DKIM') | Out-Null
            Write-Status 'DNS-DKIM' 'DKIM kaydı bulunamadı.' Yellow
            if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] DKIM kaydı bulunamadı; e-posta imzalama yapılandırılmamış olabilir.')}else{$AdvisorNotes.Add('[!] DKIM record not found; email signing may not be configured.')}
        }

        # CAA records
        try {
            $caaRecords = @(Resolve-DnsName $Target -Type CAA -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Strings -ErrorAction SilentlyContinue)
            if ($caaRecords.Count -gt 0) {
                $ReportData.DNS_CAA_Records = $caaRecords -join '; '
                $dnsExposure += [pscustomobject]@{ Type='CAA'; Detail=$ReportData.DNS_CAA_Records; Risk='Info' }
                $dnsExposureFound.Add('CAA') | Out-Null
            } else {
                $ReportData.DNS_CAA_Records = 'CAA kaydı bulunamadı.'
                $dnsExposure += [pscustomobject]@{ Type='CAA'; Detail='CAA kaydı bulunamadı.'; Risk='Info' }
                $dnsExposureMissing.Add('CAA') | Out-Null
                Write-Status 'DNS-CAA' 'CAA kaydı bulunamadı.' Green
            }
        } catch { $ReportData.DNS_CAA_Records = 'Query failed'; $dnsExposureMissing.Add('CAA') | Out-Null }

        # Store exposure summary
        $ReportData.DNS_Exposure_Summary = [string]::Join(' | ', @($dnsExposure | ForEach-Object { "$($_.Type): $($_.Risk)" }))
        $ReportData.DNS_Exposure_Details = $dnsExposure
        $ReportData.DNS_Exposure_Found = @($dnsExposureFound)
        $ReportData.DNS_Exposure_Missing = @($dnsExposureMissing)
        if ($dnsExposureFound.Count -gt 0) {
            $foundSummary = [string]::Join(', ', @($dnsExposureFound))
            $missingSummary = if ($dnsExposureMissing.Count -gt 0) { [string]::Join(', ', @($dnsExposureMissing)) } else { '-' }
            Write-Status 'DNS-EXPOSURE' "$(ConvertTo-LocalizedText 'Bulunan Kayıtlar'): $foundSummary | $(ConvertTo-LocalizedText 'Eksik Kayıtlar'): $missingSummary" Cyan
        } else {
            Write-Status 'DNS-EXPOSURE' 'Hiçbir DNS sızıntı kaydı bulunamadı.' Green
        }
    }
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
    Write-LogHeader '3. TCP/UDP SERVİS PORT MATRİSİ'
    $customPortList = $null
    if ($Ports) {
        $customPortList = @($Ports -split '[,\s;]+' |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ } |
            Where-Object { $_ -ge 1 -and $_ -le 65535 } |
            Sort-Object -Unique)
        if ($customPortList.Count -eq 0) {
            Write-Status PORT (ConvertTo-LocalizedText 'Geçersiz port listesi; varsayılanlara dönülüyor.') Yellow
            $customPortList = $null
        }
    }
    $tcpPortList = if ($customPortList) {
        @($customPortList) + $Port | Select-Object -Unique
    } else {
        switch ($ScanLevel) {
            'Low'    { @($Port) }
            'Medium' { @(80,443,$Port) }
            default  { @(80,443,8080,8443,22,25,110,143,465,587,993,995,53,3389,445,23,21,$Port) }
        }
    }
    $tcpPortList = @($tcpPortList | Select-Object -Unique)
    $ReportData.Port_List = $tcpPortList -join ', '
    $badges=New-Object 'System.Collections.Generic.List[string]'

    foreach ($cp in ($tcpPortList | Select-Object -Unique)) {
        $r = Test-TcpService -ComputerName $Target -Port $cp -TimeoutMs $TcpTimeoutMs
        $portResults.Add($r)

        if ($cp -eq $Port -and $r.TcpSucceeded) { $targetTcpReachable = $true }

        $displayState = switch ($r.State) {
            'Verified' {
                if ($Script:LanguageCode -eq 'tr') { 'SERVİS DOĞRULANDI' }
                else { 'SERVICE VERIFIED' }
            }
            'Unverified' {
                if ($Script:LanguageCode -eq 'tr') { 'TCP BAĞLANDI, SERVİS DOĞRULANAMADI' }
                else { 'TCP CONNECTED, SERVICE NOT VERIFIED' }
            }
            'Closed' { if ($Script:LanguageCode -eq 'tr') { 'KAPALI' } else { 'CLOSED' } }
            'Filtered' { if ($Script:LanguageCode -eq 'tr') { 'FİLTRELİ / TIMEOUT' } else { 'FILTERED / TIMEOUT' } }
            'Unreachable' { if ($Script:LanguageCode -eq 'tr') { 'ERİŞİLEMİYOR' } else { 'UNREACHABLE' } }
            default { if ($Script:LanguageCode -eq 'tr') { 'HATA' } else { 'ERROR' } }
        }

        $color = switch ($r.State) {
            'Verified'   { 'Green' }
            'Unverified' { 'Yellow' }
            'Closed'     { 'Red' }
            'Unreachable'{ 'Red' }
            default      { 'DarkGray' }
        }

        $latencyText = if ($null -ne $r.LatencyMs) { "$($r.LatencyMs) ms" } else { 'N/A' }
        Write-Status "TCP-$cp" "$displayState | $($r.Protocol) | $latencyText | $($r.Evidence)" $color

        $cssClass = switch ($r.State) {
            'Verified'   { 'badge-open' }
            'Unverified' { 'badge-warning' }
            default      { 'badge-closed' }
        }

        $safeProtocol = ConvertTo-HtmlSafe $r.Protocol
        $safeEvidence = ConvertTo-HtmlSafe $r.Evidence
        $badges.Add("<span class='badge $cssClass'>Port ${cp}: $displayState ($safeProtocol)</span>")
    }

    $ReportData.Port_Matrix = $badges -join ' '
    $primary = $portResults | Where-Object { $_.Port -eq $Port } | Select-Object -First 1
    $ReportData.Target_Port_Status = if ($primary) {
        "$($primary.State) | $($primary.Protocol) | $($primary.Evidence)"
    } else {
        'Test edilmedi'
    }
    $ReportData.Verified_Service_Count = @($portResults | Where-Object { $_.ServiceVerified }).Count
    $ReportData.Unverified_TCP_Count = @($portResults | Where-Object { $_.State -eq 'Unverified' }).Count
    $ReportData.Closed_Filtered_Count = @($portResults | Where-Object { $_.State -in @('Closed','Filtered','Unreachable','Error') }).Count
    $ReportData.Tested_Port_Count = $portResults.Count
    $selectedServiceVerified = [bool]($primary -and $primary.ServiceVerified)
    $selectedServiceProtocol = if ($primary) { $primary.Protocol } else { $null }
    $http80Result = $portResults | Where-Object { $_.Port -eq 80 } | Select-Object -First 1
    $http80Verified = [bool]($http80Result -and $http80Result.ServiceVerified)

    $openTcpPorts = @($portResults | Where-Object { $_.TcpSucceeded } | Select-Object -ExpandProperty Port)
    $dbPorts = @($openTcpPorts | Where-Object { $_ -in @(1433,3306,5432,1521,6379,27017,9200) })
    if ($dbPorts.Count -gt 0) {
        $dbList = ($dbPorts | Sort-Object) -join ', '
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add("[!] Veritabanı servisleri internete açık: $dbList. Sürüm açıkları, sözlük saldırısı ve veri sızıntısı riski doğurur; erişim VPN/whitelist ile kısıtlanmalı veya servis kapatılmalıdır.")
        } else {
            $AdvisorNotes.Add("[!] Database services are exposed to the internet: $dbList. This risks version exploits, dictionary attacks, and data leakage; access should be restricted to VPN/allow-lists or the service should be disabled.")
        }
    }
    if (3389 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[!] RDP (3389) açık. İnternete açık RDP sözlük saldırılarının birincil hedefidir; VPN/RDP Gateway arkasına alınmalı, NLA zorunlu tutulmalı ve güçlü kimlik doğrulama uygulanmalıdır.')
        } else {
            $AdvisorNotes.Add('[!] RDP (3389) is open. Internet-exposed RDP is a primary brute-force target; place it behind a VPN/RDP Gateway, enforce NLA, and use strong authentication.')
        }
    }
    if (445 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[!] SMB (445) açık. İnternete açık SMB brute-force ve yanal hareket riski taşır; erişim kısıtlanmalı veya servis kapatılmalıdır.')
        } else {
            $AdvisorNotes.Add('[!] SMB (445) is open. Internet-exposed SMB carries brute-force and lateral-movement risk; restrict access or disable the service.')
        }
    }
    if (23 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[!] Telnet (23) açık; şifrelemesiz eski bir protokoldür. Kimlik bilgileri düz metin gönderilir; SSH ile değiştirilmelidir.')
        } else {
            $AdvisorNotes.Add('[!] Telnet (23) is open; it is a legacy unencrypted protocol. Credentials are sent in plaintext; it should be replaced with SSH.')
        }
    }
    if (21 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[!] FTP (21) açık; kimlik bilgileri ve veri şifrelemesiz aktarılır. SFTP/FTPS kullanılmalıdır.')
        } else {
            $AdvisorNotes.Add('[!] FTP (21) is open; credentials and data are transferred in plaintext. SFTP/FTPS should be used.')
        }
    }
    if (22 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[i] SSH (22) açık. Anahtar tabanlı kimlik doğrulama kullanıldığından emin olun; mümkünse parola girişi kapatılmalıdır.')
        } else {
            $AdvisorNotes.Add('[i] SSH (22) is open. Ensure key-based authentication is used; disable password login where possible.')
        }
    }
    if (80 -in $openTcpPorts) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[i] HTTP/80 açık. HTTP trafiğinin HTTPS adresine yönlendirildiğinden emin olun; aksi halde trafik şifrelemesiz kalır.')
        } else {
            $AdvisorNotes.Add('[i] HTTP/80 is open. Ensure HTTP traffic redirects to HTTPS; otherwise traffic remains unencrypted.')
        }
    }
    if ($customPortList) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add("[i] Tarama özel port listesiyle yapıldı (-Ports): $($customPortList -join ', ').")
        } else {
            $AdvisorNotes.Add("[i] Scan performed with a custom port list (-Ports): $($customPortList -join ', ').")
        }
    }

    if ($primary -and $Port -in @(443,8443)) {
        $ReportData.HTTPS_Certificate_Status = $primary.CertificateStatus
        if ($primary.CertificateNotBefore) {
            $ReportData.HTTPS_Certificate_NotBefore = $primary.CertificateNotBefore.ToString('yyyy-MM-dd HH:mm:ss')
        }
        if ($primary.CertificateNotAfter) {
            $ReportData.HTTPS_Certificate_NotAfter = $primary.CertificateNotAfter.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    $unverifiedCount = @($portResults | Where-Object { $_.State -eq 'Unverified' }).Count
    if ($ScanLevel -in @('Deep','JMeter','WebSec')) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[i] SQL Server Browser UDP/1434 üzerinden aktif olarak sorgulanır; yanıt alınırsa servis doğrulanır.')
        } else {
            $AdvisorNotes.Add('[i] SQL Server Browser is actively queried over UDP/1434; the service is verified when a valid response is received.')
        }
    }

    $mailPortsScanned = @($tcpPortList | Where-Object { $_ -in @(25,110,143,465,587,993,995) })
    if ($ScanLevel -in @('Deep','JMeter','WebSec') -and $mailPortsScanned.Count -gt 0) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add("[i] E-posta portları test edildi: $($mailPortsScanned -join ', '). STARTTLS portlarında ilk servis bannerı doğrulanır; kimlik doğrulama yapılmaz.")
        } else {
            $AdvisorNotes.Add("[i] Mail ports tested: $($mailPortsScanned -join ', '). STARTTLS ports validate the initial service banner; no authentication is attempted.")
        }
    }

    if ($unverifiedCount -ge 3) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[!] Birden fazla ilgisiz port yalnızca TCP handshake verdi. Transparent proxy, güvenlik cihazı veya TCP interception olasıdır; bu portlar açık servis olarak doğrulanmadı.')
        } else {
            $AdvisorNotes.Add('[!] Multiple unrelated ports completed only a TCP handshake. A transparent proxy, security device, or TCP interception may be present; these ports were not verified as open services.')
        }
    }

    if ($primary -and $primary.ServiceVerified) {
        $ReportData.Reachability_Status = if ($Script:LanguageCode -eq 'tr') {
            "TCP/$Port servisi doğrulandı: $($primary.Protocol)"
        } else {
            "TCP/$Port service verified: $($primary.Protocol)"
        }
    }
    elseif ($primary -and $primary.TcpSucceeded) {
        $ReportData.Reachability_Status = if ($Script:LanguageCode -eq 'tr') {
            "TCP/$Port bağlantısı kuruldu ancak uygulama servisi doğrulanamadı"
        } else {
            "TCP/$Port connected but the application service was not verified"
        }
    }
    else {
        $ReportData.Reachability_Status = if ($Script:LanguageCode -eq 'tr') {
            "TCP/$Port kapalı, filtreli veya erişilemez"
        } else {
            "TCP/$Port is closed, filtered, or unreachable"
        }
    }
}


$udpResults = New-Object 'System.Collections.Generic.List[object]'
if ($dnsOk -and $ScanLevel -in @('Deep','JMeter','WebSec')) {
    $udpBadges = New-Object 'System.Collections.Generic.List[string]'
    foreach ($udpPort in @(53,123,1434)) {
        $udpResult = Test-UdpService `
            -ComputerName $Target `
            -Port $udpPort `
            -TimeoutMs $TcpTimeoutMs
        $udpResults.Add($udpResult)

        $displayState = switch ($udpResult.State) {
            'Verified' {
                if ($Script:LanguageCode -eq 'tr') { 'SERVİS DOĞRULANDI' }
                else { 'SERVICE VERIFIED' }
            }
            'ResponseUnverified' {
                if ($Script:LanguageCode -eq 'tr') { 'YANIT ALINDI, SERVİS DOĞRULANAMADI' }
                else { 'RESPONSE RECEIVED, SERVICE NOT VERIFIED' }
            }
            'NoResponse' {
                if ($Script:LanguageCode -eq 'tr') { 'YANIT YOK / BELİRSİZ' }
                else { 'NO RESPONSE / INDETERMINATE' }
            }
            'ClosedOrRejected' {
                if ($Script:LanguageCode -eq 'tr') { 'KAPALI VEYA REDDEDİLDİ' }
                else { 'CLOSED OR REJECTED' }
            }
            default {
                if ($Script:LanguageCode -eq 'tr') { 'HATA' }
                else { 'ERROR' }
            }
        }

        $color = switch ($udpResult.State) {
            'Verified'           { 'Green' }
            'ResponseUnverified' { 'Yellow' }
            'NoResponse'         { 'DarkGray' }
            default              { 'Red' }
        }
        $latencyText = if ($null -ne $udpResult.LatencyMs) {
            "$($udpResult.LatencyMs) ms"
        } else {
            'N/A'
        }
        Write-Status "UDP-$udpPort" `
            "$displayState | $($udpResult.Protocol) | $latencyText | $($udpResult.Evidence)" `
            $color

        $cssClass = switch ($udpResult.State) {
            'Verified'           { 'badge-open' }
            'ResponseUnverified' { 'badge-warning' }
            default              { 'badge-drop' }
        }
        $udpBadges.Add(
            "<span class='badge $cssClass'>UDP/${udpPort}: $displayState ($($udpResult.Protocol))</span>"
        )
    }

    $ReportData.UDP_Port_Matrix = $udpBadges -join ' '
    $ReportData.Verified_UDP_Service_Count = @(
        $udpResults | Where-Object { $_.ServiceVerified }
    ).Count
    $ReportData.Unresponsive_UDP_Service_Count = @(
        $udpResults | Where-Object { $_.State -eq 'NoResponse' }
    ).Count

    if ($Script:LanguageCode -eq 'tr') {
        $AdvisorNotes.Add('[i] UDP yanıtı alınamaması portun kesin kapalı olduğunu kanıtlamaz; servis açık, filtreli veya sessizce düşürülüyor olabilir.')
    } else {
        $AdvisorNotes.Add('[i] No UDP response does not prove that a port is closed; the service may be open, filtered, or silently dropping probes.')
    }
}

$maxJitterVal=$null;$routeMetricsAvailable=$false;$destinationHopJitter=$null
if($dnsOk-and($ScanLevel -in @('Medium','Deep','JMeter','WebSec'))){
    Write-LogHeader '4. HOP KATMANLI ROTA VE JITTER ANALİZİ'
    try{$trace=Test-NetConnection $targetIP -TraceRoute -WarningAction SilentlyContinue;$hops=@($trace.TraceRoute)}catch{$hops=@()}
    $idx=1
    $hiddenHopLabel = if ($Script:LanguageCode -eq 'tr') {
        'Gizli/Yanıtsız (*)'
    } else {
        'Hidden/Unresponsive (*)'
    }
    foreach ($hop in $hops){
        if(-not $hop -or $hop -in @('...','0.0.0.0','::')){$RouteReportRows.Add([pscustomobject]@{Hop=$idx;IP=$hiddenHopLabel;Min='N/A';Max='N/A';Avg='N/A';Median='N/A';P95='N/A';Jitter='N/A';PeakJitter='N/A';StdDev='N/A';Loss='N/A';Status='ICMP yanıtlamıyor';CssClass='failed';Destination=$false});$idx++;continue}
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

$jmeterP95Val=$null;$jmeterErrRateVal=$null;$appMetricsAvailable=$false;$jmeterP50Val=$null;$jmeterP99Val=$null;$jmeterTailRatio=$null;$jmeterSpreadVal=$null;$jmeterSamplesCount=0
$ReportData.GeoIP_Target_ASN='N/A';$ReportData.GeoIP_Target_Location='N/A';$ReportData.GeoIP_Target_ISP='N/A';$ReportData.GeoIP_Hop_ASN='N/A'
$geoIpNotice=$false
if(-not $SkipGeoIp -and $targetIP){
    $geoIpNotice=$true
    $hopIps=@($RouteReportRows|Where-Object{$_.IP-match'^\d{1,3}(\.\d{1,3}){3}$'}|Select-Object -ExpandProperty IP|Select-Object -Unique)
    $lookupIps=@($hopIps)+@($targetIP)|Select-Object -Unique
    $geoResults=@(Get-GeoIpInfo -IPAddresses $lookupIps)
    $geoMap=@{}
    foreach($g in $geoResults){if($g.query){$geoMap[$g.query]=$g}}
    if($geoMap.ContainsKey($targetIP) -and $geoMap[$targetIP].as){
        $gt=$geoMap[$targetIP]
        $ReportData.GeoIP_Target_ASN="$($gt.as) ($($gt.asname))"
        $ReportData.GeoIP_Target_Location="$($gt.city), $($gt.regionName), $($gt.country)"
        $ReportData.GeoIP_Target_ISP=$gt.isp
        Write-Status GEOIP "Hedef: $($gt.as) ($($gt.asname)) | $($gt.city), $($gt.country) | ISP: $($gt.isp)" Green
    } else {
        Write-Status GEOIP 'Hedef GeoIP/ASN bilgisi alınamadı' Yellow
    }
    $hopAsnLines=New-Object 'System.Collections.Generic.List[string]'
    foreach($row in $RouteReportRows){
        if($row.IP-match'^\d{1,3}(\.\d{1,3}){3}$' -and $geoMap.ContainsKey($row.IP) -and $geoMap[$row.IP].as){
            $hopAsnLines.Add("Hop$($row.Hop) $($row.IP): $($geoMap[$row.IP].as) ($($geoMap[$row.IP].asname))")
        }
    }
    if($hopAsnLines.Count-gt 0){$ReportData.GeoIP_Hop_ASN=$hopAsnLines-join' | ';Write-Status GEOIP "Yol: $($ReportData.GeoIP_Hop_ASN)" Green}
    if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[i] GeoIP/ASN zenginleştirme ip-api.com üzerinden yapıldı; IP adresleri yalnızca bu amaçla üçüncü taraf bir servise gönderildi.')}else{$AdvisorNotes.Add('[i] GeoIP/ASN enrichment was performed via ip-api.com; IP addresses were sent to a third-party service solely for this purpose.')}
}
$loadTestSkipped=$false
$loadTestSkipReason=$null
if($ScanLevel -in @('JMeter','WebSec') -or $EnableLoadTest){
    Write-LogHeader '5. GELİŞMİŞ HTTP EŞZAMANLI YÜK TESTİ'
    $protocol=if($Port -in @(443,8443)){'https'}else{'http'}
    $effectiveLoadProtocol = $protocol
    $effectiveLoadPort = $Port
    $loadFallbackUsed = $false

    $requiresTlsValidation = ($protocol -eq 'https')
    if ($requiresTlsValidation -and (-not $selectedServiceVerified) -and $http80Verified) {
        $effectiveLoadProtocol = 'http'
        $effectiveLoadPort = 80
        $loadFallbackUsed = $true
        $fallbackMessage = if ($Script:LanguageCode -eq 'tr') {
            'HTTPS sertifikası geçersiz veya alınamadı; doğrulanmış HTTP/80 servisine geri dönüldü.'
        } else {
            'The HTTPS certificate was invalid or unavailable; the test fell back to the verified HTTP/80 service.'
        }
        $AdvisorNotes.Add("[!] $fallbackMessage")
        Write-Status LOAD $fallbackMessage Yellow
    }

    $url="${effectiveLoadProtocol}://${Target}:${effectiveLoadPort}/"
    $ReportData.Effective_Load_Test_URL = $url

    if ($requiresTlsValidation -and (-not $selectedServiceVerified) -and (-not $http80Verified)) {
        $loadTestSkipped = $true
        $loadTestSkipReason = if ($Script:LanguageCode -eq 'tr') {
            'HTTPS doğrulanamadı ve HTTP/80 üzerinde doğrulanmış bir fallback servisi bulunamadı; yük testi başlatılmadı.'
        } else {
            'HTTPS could not be verified and no verified HTTP/80 fallback service was available; the load test was not started.'
        }
        $ReportData.Load_Test_Status = $loadTestSkipReason
        $AdvisorNotes.Add("[!] $loadTestSkipReason")
        Write-Status LOAD $loadTestSkipReason Yellow
    }
    else {
    $code=@'
using System;using System.Collections.Concurrent;using System.Diagnostics;using System.IO;using System.Net;using System.Net.Http;using System.Threading;using System.Threading.Tasks;
public class NetDiagRunnerV2{
 public class Result{public int Sequence;public DateTime StartedUtc;public double HeaderMs;public double ElapsedMs;public double DownloadMs;public long Bytes;public bool Success;public bool AssertionFailed;public int StatusCode;public string ErrorType;public string Error;}
 public class TestOutput{public ConcurrentBag<Result> Results;public int PeakConcurrency;}
 static int activeRequests=0,peakConcurrency=0;
 static void UpdatePeak(int current){int observed;do{observed=peakConcurrency;if(current<=observed)return;}while(Interlocked.CompareExchange(ref peakConcurrency,current,observed)!=observed);}
 static async Task<Result> ExecuteRequest(HttpClient client,string url,string method,string assertion,int timeoutSeconds,int maxResponseBytes,int sequence){var r=new Result{Sequence=sequence,StartedUtc=DateTime.UtcNow,Success=false,ErrorType="",Error=""};int active=Interlocked.Increment(ref activeRequests);UpdatePeak(active);var total=Stopwatch.StartNew();try{using(var cts=new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))using(var req=new HttpRequestMessage(method=="HEAD"?HttpMethod.Head:HttpMethod.Get,url)){var header=Stopwatch.StartNew();using(var response=await client.SendAsync(req,HttpCompletionOption.ResponseHeadersRead,cts.Token).ConfigureAwait(false)){header.Stop();r.HeaderMs=header.Elapsed.TotalMilliseconds;r.StatusCode=(int)response.StatusCode;long bytes=0;string text="";if(method!="HEAD"){using(var stream=await response.Content.ReadAsStreamAsync().ConfigureAwait(false))using(var memory=new MemoryStream()){var buffer=new byte[8192];while(true){int read=await stream.ReadAsync(buffer,0,buffer.Length,cts.Token).ConfigureAwait(false);if(read<=0)break;bytes+=read;if(bytes>maxResponseBytes)throw new InvalidOperationException("ResponseSizeLimitExceeded");memory.Write(buffer,0,read);}if(!String.IsNullOrEmpty(assertion)){memory.Position=0;using(var reader=new StreamReader(memory)){text=reader.ReadToEnd();}}}}total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.DownloadMs=Math.Max(0,r.ElapsedMs-r.HeaderMs);r.Bytes=bytes;bool httpOk=r.StatusCode>=200&&r.StatusCode<400;bool assertOk=true;if(!String.IsNullOrEmpty(assertion)){assertOk=text.IndexOf(assertion,StringComparison.Ordinal)>=0;if(!assertOk){r.AssertionFailed=true;r.ErrorType="AssertionFailed";r.Error="Assertion text was not found.";}}r.Success=httpOk&&assertOk;if(!httpOk){r.ErrorType="HttpStatus";r.Error="HTTP "+r.StatusCode;}}}}catch(TaskCanceledException ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType="Timeout";r.Error=ex.Message;}catch(HttpRequestException ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType="HttpRequestException";r.Error=ex.InnerException!=null?ex.InnerException.Message:ex.Message;}catch(Exception ex){total.Stop();r.ElapsedMs=total.Elapsed.TotalMilliseconds;r.ErrorType=ex.GetType().Name;r.Error=ex.InnerException!=null?ex.InnerException.Message:ex.Message;}finally{Interlocked.Decrement(ref activeRequests);}return r;}
 public static TestOutput Run(string url,int totalRequests,int threads,string assertion,int timeoutSeconds,int warmupRequests,int rampUpSeconds,int thinkTimeMs,int maxResponseBytes,string method){activeRequests=0;peakConcurrency=0;var results=new ConcurrentBag<Result>();var handler=new HttpClientHandler();handler.ServerCertificateCustomValidationCallback=(a,b,c,d)=>true;handler.AutomaticDecompression=DecompressionMethods.GZip|DecompressionMethods.Deflate;handler.MaxConnectionsPerServer=Math.Max(threads,2);using(var client=new HttpClient(handler)){client.Timeout=Timeout.InfiniteTimeSpan;client.DefaultRequestHeaders.Add("User-Agent","NetDiag/2.0");var warmOptions=new ParallelOptions{MaxDegreeOfParallelism=Math.Max(threads,2)};if(warmupRequests==1){ExecuteRequest(client,url,method,assertion,timeoutSeconds,maxResponseBytes,-1).GetAwaiter().GetResult();}else if(warmupRequests>1){Parallel.For(0,warmupRequests,warmOptions,w=>{ExecuteRequest(client,url,method,assertion,timeoutSeconds,maxResponseBytes,-(w+1)).GetAwaiter().GetResult();});}var options=new ParallelOptions{MaxDegreeOfParallelism=threads};Parallel.For(0,totalRequests,options,index=>{if(rampUpSeconds>0&&totalRequests>1){double ratio=index/(double)(totalRequests-1);int delay=(int)(ratio*rampUpSeconds*1000);if(delay>0)Thread.Sleep(delay);}var r=ExecuteRequest(client,url,method,assertion,timeoutSeconds,maxResponseBytes,index+1).GetAwaiter().GetResult();results.Add(r);if(thinkTimeMs>0)Thread.Sleep(thinkTimeMs);});}return new TestOutput{Results=results,PeakConcurrency=peakConcurrency};}
}
'@
    if(-not('NetDiagRunnerV2'-as[type])){Add-Type -TypeDefinition $code -Language CSharp}
    $testWatch=[Diagnostics.Stopwatch]::StartNew();$output=[NetDiagRunnerV2]::Run($url,$JMeterTotalRequests,$JMeterThreads,$JMeterAssertText,$HttpTimeoutSec,$JMeterWarmupRequests,$JMeterRampUpSeconds,$JMeterThinkTimeMs,$JMeterMaxResponseBytes,$JMeterHttpMethod);$testWatch.Stop();$results=@($output.Results.ToArray())
    if($results.Count){
        $ReportData.Load_Test_Status = if($Script:LanguageCode-eq'tr'){'Tamamlandı'}else{'Completed'}
        $appMetricsAvailable=$true;$successful=@($results|Where-Object{$_.Success});$failed=@($results|Where-Object{-not $_.Success});$elapsed=@($successful|Select-Object -ExpandProperty ElapsedMs|Sort-Object);$headers=@($successful|Select-Object -ExpandProperty HeaderMs|Sort-Object);$downloads=@($successful|Select-Object -ExpandProperty DownloadMs|Sort-Object)
        $successCount=$successful.Count;$failCount=$failed.Count;$errorRate=[Math]::Round(($failCount/[double]$results.Count)*100,2);$duration=[Math]::Round($testWatch.Elapsed.TotalSeconds,3);$rps=if($duration-gt0){[Math]::Round($results.Count/$duration,2)}else{0}
        if($elapsed.Count){$avgElapsed=[Math]::Round(($elapsed|Measure-Object -Average).Average,2);$stdElapsed=Get-PopulationStandardDeviation $elapsed;$p50=[Math]::Round((Get-Percentile $elapsed 50),2);$p75=[Math]::Round((Get-Percentile $elapsed 75),2);$p90=[Math]::Round((Get-Percentile $elapsed 90),2);$p95=[Math]::Round((Get-Percentile $elapsed 95),2);$p99=[Math]::Round((Get-Percentile $elapsed 99),2);$minElapsed=[Math]::Round($elapsed[0],2);$maxElapsed=[Math]::Round($elapsed[-1],2);$tailRatio=if($p50-gt0){[Math]::Round($p99/$p50,1)}else{$null};$spread=if($null-ne$tailRatio){[Math]::Round($p99-$p50,2)}else{$null};$avgHeader=[Math]::Round(($headers|Measure-Object -Average).Average,2);$p50Header=[Math]::Round((Get-Percentile $headers 50),2);$p90Header=[Math]::Round((Get-Percentile $headers 90),2);$p95Header=[Math]::Round((Get-Percentile $headers 95),2);$p99Header=[Math]::Round((Get-Percentile $headers 99),2);$ttfbSpread=if($null-ne$p50Header -and $null-ne$p99Header){[Math]::Round($p99Header-$p50Header,2)}else{$null};$avgDownload=[Math]::Round(($downloads|Measure-Object -Average).Average,2)}else{$avgElapsed=$stdElapsed=$p50=$p75=$p90=$p95=$p99=$minElapsed=$maxElapsed=$tailRatio=$spread=$avgHeader=$p50Header=$p90Header=$p95Header=$p99Header=$ttfbSpread=$avgDownload=$null}
        $displayAvgHeader=if($null-ne$avgHeader){$avgHeader}else{'N/A'};$displayP50Header=if($null-ne$p50Header){$p50Header}else{'N/A'};$displayP90Header=if($null-ne$p90Header){$p90Header}else{'N/A'};$displayP95Header=if($null-ne$p95Header){$p95Header}else{'N/A'};$displayP99Header=if($null-ne$p99Header){$p99Header}else{'N/A'};$displayTtfbSpread=if($null-ne$ttfbSpread){"$ttfbSpread ms"}else{'N/A'};$displayAvgElapsed=if($null-ne$avgElapsed){$avgElapsed}else{'N/A'};$displayP50=if($null-ne$p50){$p50}else{'N/A'};$displayP90=if($null-ne$p90){$p90}else{'N/A'};$displayP95=if($null-ne$p95){$p95}else{'N/A'};$displayP99=if($null-ne$p99){$p99}else{'N/A'};$displayTailRatio=if($null-ne$tailRatio){"${tailRatio}x"}else{'N/A'};$displaySpread=if($null-ne$spread){"$spread ms"}else{'N/A'};$displayMinElapsed=if($null-ne$minElapsed){"$minElapsed ms"}else{'N/A'};$displayMaxElapsed=if($null-ne$maxElapsed){"$maxElapsed ms"}else{'N/A'};
        $jmeterP95Val=$p95;$jmeterP50Val=$p50;$jmeterP99Val=$p99;$jmeterTailRatio=$tailRatio;$jmeterSpreadVal=$spread;$jmeterSamplesCount=$results.Count;$jmeterErrRateVal=$errorRate;$totalBytes=($successful|Measure-Object Bytes -Sum).Sum;if($null -eq $totalBytes){$totalBytes=0};$avgBytes=if($successCount){[Math]::Round($totalBytes/[double]$successCount)}else{0};$mbps=if($duration-gt0){[Math]::Round((($totalBytes*8)/$duration)/1000000,3)}else{0}
        $statusDist=(@($results|Group-Object StatusCode|Sort-Object Name|ForEach-Object{"HTTP $($_.Name): $($_.Count)"}))-join' | ';$errorDist=(@($failed|Group-Object ErrorType|Sort-Object Count -Descending|ForEach-Object{"$($_.Name): $($_.Count)"}))-join' | ';if(-not $errorDist){$errorDist='Hata yok'}
        $ReportData.JMeter_Engine='NetDiag HTTP Load Engine v2';$ReportData.JMeter_Method=$JMeterHttpMethod;$ReportData.JMeter_Threads=$JMeterThreads;$ReportData.JMeter_Peak_Concurrency=$output.PeakConcurrency;$ReportData.JMeter_RampUp="$JMeterRampUpSeconds saniye";$ReportData.JMeter_Warmup_Requests=$JMeterWarmupRequests;$ReportData.JMeter_Total_Requests=$results.Count;$ReportData.JMeter_Successful_Requests=$successCount;$ReportData.JMeter_Failed_Requests=$failCount;$ReportData.JMeter_Test_Duration="$duration saniye";$ReportData.JMeter_Throughput_RPS="$rps req/sec";$ReportData.JMeter_Avg_Header_Time=if($null-ne$avgHeader){"$avgHeader ms"}else{'N/A'};$ReportData.JMeter_p95_Header_Time=if($null-ne$p95Header){"$p95Header ms"}else{'N/A'};$ReportData.JMeter_Avg_Download_Time=if($null-ne$avgDownload){"$avgDownload ms"}else{'N/A'};$ReportData.JMeter_Avg_Elapsed=if($null-ne$avgElapsed){"$avgElapsed ms"}else{'N/A'};$ReportData.JMeter_Elapsed_StdDev=if($null-ne$stdElapsed){"$stdElapsed ms"}else{'N/A'};$ReportData.JMeter_p50_Elapsed=if($null-ne$p50){"$p50 ms"}else{'N/A'};$ReportData.JMeter_p75_Elapsed=if($null-ne$p75){"$p75 ms"}else{'N/A'};$ReportData.JMeter_p90_Elapsed=if($null-ne$p90){"$p90 ms"}else{'N/A'};$ReportData.JMeter_p95_Elapsed=if($null-ne$p95){"$p95 ms"}else{'N/A'};$ReportData.JMeter_p99_Elapsed=if($null-ne$p99){"$p99 ms"}else{'N/A'};$ReportData.JMeter_Error_Rate="%$errorRate";$ReportData.JMeter_Status_Distribution=$statusDist;$ReportData.JMeter_Error_Distribution=$errorDist;$ReportData.JMeter_Total_Data="$([Math]::Round($totalBytes/1MB,3)) MB";$ReportData.JMeter_Average_Response_Size="$avgBytes Byte";        $ReportData.JMeter_Download_Throughput="$mbps Mbps";$ReportData.JMeter_TTFB_p50=if($null-ne$p50Header){"$p50Header ms"}else{'N/A'};$ReportData.JMeter_TTFB_p90=if($null-ne$p90Header){"$p90Header ms"}else{'N/A'};$ReportData.JMeter_TTFB_p99=if($null-ne$p99Header){"$p99Header ms"}else{'N/A'};$ReportData.JMeter_TTFB_Spread=if($null-ne$ttfbSpread){"$ttfbSpread ms"}else{'N/A'};$ReportData.JMeter_Tail_Ratio=if($null-ne$tailRatio){"${tailRatio}x"}else{'N/A'};$ReportData.JMeter_Spread_ms=if($null-ne$spread){"$spread ms"}else{'N/A'};$ReportData.JMeter_Min_Elapsed=if($null-ne$minElapsed){"$minElapsed ms"}else{'N/A'};$ReportData.JMeter_Max_Elapsed=if($null-ne$maxElapsed){"$maxElapsed ms"}else{'N/A'}
        Write-Status LOAD "RPS $rps | Peak $($output.PeakConcurrency) | Başarılı $successCount | Hatalı $failCount | Hata %$errorRate" $(if($errorRate-gt5){'Red'}elseif($errorRate-gt0){'Yellow'}else{'Green'});Write-Status TTFB "p50 $displayP50Header | p95 $displayP95Header | p99 $displayP99Header | Yayılım $displayTtfbSpread" $(if($null-ne$p99Header -and $p99Header-gt1000){'Yellow'}else{'Green'});Write-Status ELAPSED "p50 $displayP50 | p95 $displayP95 | p99 $displayP99 | Yayılım $displaySpread | Kuyruk $displayTailRatio" $(if($null-ne$tailRatio -and $tailRatio-ge3){'Red'}elseif($null-ne$p95 -and $p95-gt1000){'Yellow'}else{'Green'});Write-Status QUALITY "$jmeterSamplesCount örnek | p99 $(if($jmeterSamplesCount-ge200){'güvenilir'}else{'düşük örnek - p95 tercih edin'})" $(if($jmeterSamplesCount-ge200){'Green'}else{'Yellow'});Write-Status DATA "Toplam $([Math]::Round($totalBytes/1MB,3)) MB | Ort $avgBytes Byte | $mbps Mbps" Cyan
    }
    }
}
if($JMeterCsvPath-and(Test-Path $JMeterCsvPath)){try{$csv=@(Import-Csv $JMeterCsvPath);$elapsedCsv=@($csv|ForEach-Object{if($_.elapsed -ne $null){[double]$_.elapsed}}|Sort-Object);if($elapsedCsv.Count){$ReportData.Ext_JMeter_File=Split-Path $JMeterCsvPath -Leaf;$ReportData.Ext_JMeter_p95="$(Get-Percentile $elapsedCsv 95) ms"}}catch{Write-Status CSV $_.Exception.Message Red}}


if($dnsOk -and $ScanLevel -in @('Deep','WebSec') -and ($Port -in @(80,443,8080,8443))){
    Write-LogHeader '6. WEB, SSL VE HTTP ANALİZİ'
    $protocol=if($Port -in @(443,8443)){'https'}else{'http'};$url="${protocol}://${Target}:${Port}/"
    $ReportData.TLS_Supported_Versions='N/A';$ReportData.TLS_Negotiated_Protocol='N/A';$ReportData.TLS_Negotiated_Cipher='N/A';$ReportData.HTTP_Version_ALPN='N/A';$ReportData.HTTP3_QUIC_Status='N/A';$ReportData.Security_Header_Score='N/A';$ReportData.Security_Headers='N/A'
    $ReportData.HTTPS_Cert_SAN='N/A';$ReportData.HTTPS_Cert_SAN_Match='N/A';$ReportData.HTTPS_Cert_Chain='N/A';$ReportData.HTTPS_Cert_Chain_Status='N/A';$ReportData.HTTPS_Cert_Revocation='N/A';$ReportData.HTTPS_Cert_Signature='N/A';$ReportData.HTTPS_Cert_Valid='N/A'
    if($protocol -eq 'https' -and $targetTcpReachable){
        $tc=$null;$ss=$null;$cert=$null
        try{$tc=New-Object Net.Sockets.TcpClient;$ar=$tc.BeginConnect($targetIP,$Port,$null,$null);if(-not $ar.AsyncWaitHandle.WaitOne($TcpTimeoutMs,$false)){throw 'SSL TCP timeout'};$tc.EndConnect($ar);$ss=New-Object Net.Security.SslStream($tc.GetStream(),$false,({$true}));$ss.ReadTimeout=$HttpTimeoutSec*1000;$ss.WriteTimeout=$HttpTimeoutSec*1000;$ss.AuthenticateAsClient($Target);$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ss.RemoteCertificate;$days=[Math]::Floor(($cert.NotAfter-(Get-Date)).TotalDays);$ReportData.SSL_Subject=$cert.Subject;$ReportData.SSL_Issuer=$cert.Issuer;$ReportData.SSL_Days_Left="$days Gün";Write-Status SSL "$days gün kaldı" $(if($days-lt30){'Yellow'}else{'Green'})}catch{Write-Status SSL $_.Exception.Message Red}finally{if($ss){$ss.Dispose()};if($tc){$tc.Dispose()}}
        if($cert){
            $chainInfo=Test-CertificateChain -Certificate $cert -ExpectedName $Target -UseRevocation
            $now=(Get-Date)
            $ReportData.HTTPS_Cert_SAN=$chainInfo.San
            $ReportData.HTTPS_Cert_SAN_Match=if($chainInfo.SanMatch){'Yes'}else{'No'}
            $ReportData.HTTPS_Cert_Chain=if($chainInfo.ChainValid){'Valid'}else{'Invalid'}
            $ReportData.HTTPS_Cert_Chain_Status=$chainInfo.ChainStatus
            $ReportData.HTTPS_Cert_Revocation=$chainInfo.Revocation
            $ReportData.HTTPS_Cert_Valid=if($cert.NotBefore -le $now -and $cert.NotAfter -ge $now){'Valid'}else{'Expired / Not yet valid'}
            $sigName=if($cert.SignatureAlgorithm.FriendlyName){$cert.SignatureAlgorithm.FriendlyName}else{$cert.SignatureAlgorithm.Value}
            $ReportData.HTTPS_Cert_Signature=$sigName
            $certColor=if($chainInfo.ChainValid -and $chainInfo.SanMatch){'Green'}else{'Yellow'}
            Write-Status CERT "SAN eşleşmesi: $($ReportData.HTTPS_Cert_SAN_Match) | Zincir: $($ReportData.HTTPS_Cert_Chain) | Revocation: $($chainInfo.Revocation) | İmza: $sigName" $certColor
            if(-not $chainInfo.SanMatch){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] Sertifika SAN alanı istenen hostname ile eşleşmiyor; bağlantı güveni sorgulanabilir.')}else{$AdvisorNotes.Add('[!] The certificate SAN does not match the requested hostname; connection trust may be questionable.')}}
            if(-not $chainInfo.ChainValid){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] Sertifika zinciri doğrulaması başarısız: $($chainInfo.ChainStatus)")}else{$AdvisorNotes.Add("[!] Certificate chain validation failed: $($chainInfo.ChainStatus)")}}
            if($chainInfo.Revocation -eq 'Revoked'){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] Sertifika iptal edilmiş (revoked) durumda.')}else{$AdvisorNotes.Add('[!] The certificate is revoked.')}}
            if($null -ne $days){
                if($days -lt 0){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] SSL sertifikasının süresi dolmuş; derhal yenilenmelidir.')}else{$AdvisorNotes.Add('[!] The SSL certificate has expired; it must be renewed immediately.')}}
                elseif($days -lt 30){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add("[!] SSL sertifikası $days gün içinde sona erecek; yenileme planlanmalıdır.")}else{$AdvisorNotes.Add("[!] The SSL certificate expires in $days days; plan a renewal.")}}
            }
        }

        $tlsProbe=Test-TlsVersions -ComputerName $targetIP -Port $Port -TimeoutMs $TcpTimeoutMs
        if($tlsProbe.AcceptedVersions.Count -gt 0){
            $ReportData.TLS_Supported_Versions=($tlsProbe.AcceptedVersions -join ', ')
            $ReportData.TLS_Negotiated_Protocol=$tlsProbe.BestProtocol
            $ReportData.TLS_Negotiated_Cipher=$tlsProbe.CipherSuite
            Write-Status TLS "$(ConvertTo-LocalizedText 'Desteklenen:') $($tlsProbe.AcceptedVersions -join ', ') | $($tlsProbe.CipherSuite)" Green
            if($tlsProbe.AcceptedVersions -contains 'TLS 1.0' -or $tlsProbe.AcceptedVersions -contains 'TLS 1.1'){
                Write-Status TLS 'Eski TLS sürümü kabul edildi; risk oluşturabilir.' Yellow
                if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] TLS 1.0 veya TLS 1.1 kabul edildi; bu sürümler modern güvenlik standartlarını karşılamaz. TLS 1.2/1.3 yapılandırması önerilir.')}else{$AdvisorNotes.Add('[!] TLS 1.0 or TLS 1.1 is accepted; these versions do not meet modern security standards. TLS 1.2/1.3 configuration is recommended.')}
            }
        } else {
            $ReportData.TLS_Supported_Versions='Hiçbiri (TLS handshake başarısız)'
            Write-Status TLS 'Desteklenen TLS sürümü bulunamadı.' Yellow
        }

        $alpn=Get-NegotiatedAlpn -ComputerName $targetIP -Port $Port -TimeoutMs $TcpTimeoutMs
        $ReportData.HTTP_Version_ALPN=$alpn
        Write-Status ALPN "$(ConvertTo-LocalizedText 'Müzakere edilen ALPN:') $alpn" $(if($alpn -eq 'h2'){'Green'}else{'Yellow'})
        if($alpn -eq 'h2'){$ReportData.HTTP2_Status='Supported (HTTP/2 negotiated via ALPN)'}else{$ReportData.HTTP2_Status=$alpn}

        $http3=Test-HttpVersion3 -Url $url -TimeoutSec $HttpTimeoutSec
        $ReportData.HTTP3_QUIC_Status=$http3
        Write-Status HTTP3 $http3 $(if($http3 -like 'Supported*'){'Green'}else{'Yellow'})
        if($http3 -like 'Supported*'){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[i] Hedef HTTP/3 (QUIC) destekliyor; UDP/443 üzerinden yük testi için ayrıca değerlendirilebilir.')}else{$AdvisorNotes.Add('[i] The target supports HTTP/3 (QUIC); it may be considered separately for load testing over UDP/443.')}}
    }
    $secAudit=$null
    try{$old=[Net.ServicePointManager]::ServerCertificateValidationCallback;[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$sw=[Diagnostics.Stopwatch]::StartNew();$wp=@{Uri=$url;Method='Get';TimeoutSec=$HttpTimeoutSec;ErrorAction='Stop';UseBasicParsing=$true};$wr=Invoke-WebRequest @wp;$sw.Stop();$ReportData.HTTP_Code=$wr.StatusCode;$ReportData.HTTP_Total_Time="$($sw.ElapsedMilliseconds) ms";Write-Status HTTP "Status $($wr.StatusCode), toplam $($sw.ElapsedMilliseconds) ms" Green
        if($wr.Headers){
            $secAudit=Test-SecurityHeaderAudit -Response $wr -Protocol $protocol
            $ReportData.Security_Header_Score=$secAudit.ScoreText
            $ReportData.Security_Headers=$secAudit.BadgesHtml
            Write-Status SEC "$(ConvertTo-LocalizedText 'Güvenlik Başlığı Puanı'): $($secAudit.ScoreText)" $(if($secAudit.HasFailures){'Red'}else{'Green'})
            foreach($secItem in $secAudit.Items){
                $secColor=switch($secItem.Status){'Pass'{'Green'};'Warn'{'Yellow'};default{'Red'}}
                Write-Status "SEC-$($secItem.Name)" "$($secItem.Status): $($secItem.Detail)" $secColor
            }
            if($secAudit.HasFailures){if($Script:LanguageCode-eq'tr'){$AdvisorNotes.Add('[!] Bazı güvenlik başlıkları eksik; gizlilik, bütünlük ve tarayıcı güvenliği risklerini azaltmak için HTTP yanıt başlıkları güçlendirilmelidir.')}else{$AdvisorNotes.Add('[!] Some security headers are missing; HTTP response headers should be hardened to reduce privacy, integrity, and browser security risks.')}}
        }
    }catch{Write-Status HTTP $_.Exception.Message Red}finally{[Net.ServicePointManager]::ServerCertificateValidationCallback=$old}
}

$webSecRows = @()
$webSecSummaryText = ''
$webSecAdvices = @()
if ($dnsOk -and $ScanLevel -eq 'WebSec') {
    Write-LogHeader '6b. WEB SALDIRI YÜZEYİ ANALİZİ VE ÇÖZÜM ÖNERİLERİ'
    $webSecRows = New-Object 'System.Collections.Generic.List[object]'
    $webSecAdvices = New-Object 'System.Collections.Generic.List[string]'
    $webSecAdvised = @{}
    $dangerCount = 0
    $warnCount = 0
    $webPortsProbed = @()
    $protocolByPort = @{}
    foreach ($pr in $portResults) { if (-not $protocolByPort.ContainsKey($pr.Port)) { $protocolByPort[$pr.Port] = $pr.Protocol } }
    $knownNonWeb = @('SSH','SMTP Relay','SMTP Submission / STARTTLS','POP3 / STARTTLS','IMAP / STARTTLS','SMTPS / Implicit TLS','IMAPS / Implicit TLS','POP3S / Implicit TLS','RDP','SMB','Telnet','FTP')

    foreach ($wp in @($openTcpPorts | Sort-Object)) {
        $knownProto = $null
        if ($protocolByPort.ContainsKey($wp)) { $knownProto = $protocolByPort[$wp] }
        if ($knownProto -and $knownProto -in $knownNonWeb) { continue }

        $wpProto = if ($wp -in @(443,8443)) { 'https' } else { 'http' }
        $isWeb = $wp -in @(80,443,8080,8443)
        if (-not $isWeb) {
            foreach ($tryProto in @($wpProto, $(if ($wpProto -eq 'http') { 'https' } else { 'http' }))) {
                try {
                    $null = Invoke-WebRequest -Uri "${tryProto}://${Target}:${wp}/" -Method Head -Headers @{ 'User-Agent' = 'NetDiag-WebSec/1.0' } -TimeoutSec $HttpTimeoutSec -UseBasicParsing -ErrorAction Stop
                    $wpProto = $tryProto
                    $isWeb = $true
                    break
                } catch { }
            }
        }
        if (-not $isWeb) { continue }
        $webPortsProbed += $wp
        Write-Status "WEBSEC-$wp" "$(ConvertTo-LocalizedText "$wpProto servisi doğrulandı; saldırı yüzeyi ve sayfa analizi yapılıyor...")" Cyan
        $surfaceItems = @(Test-WebSecuritySurface -ComputerName $Target -Port $wp -Protocol $wpProto -TimeoutSec $HttpTimeoutSec) + @(Test-WebPageAnalyzer -ComputerName $Target -Port $wp -Protocol $wpProto -TimeoutSec $HttpTimeoutSec)
        foreach ($surfaceItem in $surfaceItems) {
            $surfaceItem | Add-Member -NotePropertyName Port -NotePropertyValue $wp -Force
            $webSecRows.Add($surfaceItem)
            $itemColor = switch ($surfaceItem.Status) {
                'Danger' { 'Red' }
                'Fail'   { 'Red' }
                'Warn'   { 'Yellow' }
                'Pass'   { 'Green' }
                default  { 'DarkGray' }
            }
            Write-Status "WEBSEC-$wp-$($surfaceItem.Check)" "$($surfaceItem.Status): $($surfaceItem.Detail)" $itemColor
            if ($surfaceItem.Status -in @('Danger','Fail')) { $dangerCount++ }
            elseif ($surfaceItem.Status -eq 'Warn') { $warnCount++ }
        }
    }

    if ($webPortsProbed.Count -eq 0) {
        if ($Script:LanguageCode -eq 'tr') {
            $AdvisorNotes.Add('[i] WebSec seviyesinde açık HTTP/HTTPS servisi tespit edilmedi; saldırı yüzeyi analizi atlandı.')
        } else {
            $AdvisorNotes.Add('[i] No open HTTP/HTTPS service was detected at the WebSec level; the attack-surface analysis was skipped.')
        }
    } else {
        if ($Script:LanguageCode -eq 'tr') {
            $webSecSummaryText = "$($webPortsProbed.Count) web servisi incelendi; $dangerCount kritik ve $warnCount uyarı bulgusu."
        } else {
            $webSecSummaryText = "$($webPortsProbed.Count) web service(s) analyzed; $dangerCount critical and $warnCount warning finding(s)."
        }
    }

    $solutionText = @{}
    if ($Script:LanguageCode -eq 'tr') {
        $solutionText['TRACE Method'] = 'TRACE metodu etkin; XST riski. Nginx: discardante_http_trace off; Apache: TraceEnable Off; IIS: <verbs> ile TRACE engelle.'
        $solutionText['PUT'] = 'PUT metodu açık; yetkisiz içerik değişikliği riski. Yalnızca gerekli metodlara (GET/HEAD/POST/OPTIONS) izin verin.'
        $solutionText['DELETE'] = 'DELETE metodu açık; yetkisiz kaynak silme riski. Yalnızca gerekli metodlara izin verin.'
        $solutionText['PATCH'] = 'PATCH metodu açık; gerekli değilse kısıtlanmalıdır.'
        $solutionText['Directory Listing'] = 'Klasör listeleme etkin; içerik ve sürüm ifşası riski. Nginx: autoindex off; Apache: Options -Indexes; IIS: directoryBrowsing disabled.'
        $solutionText['Server Banner'] = 'Sunucu banner bilgisi ifşa ediliyor. Nginx: server_tokens off; Apache: ServerSignature Off; IIS: removeServerHeader enabled.'
        $solutionText['X-Powered-By'] = 'Teknoloji bileşenleri ifşa ediliyor. Nginx: proxy_hide_header X-Powered-By; Apache: Header unset X-Powered-By; IIS: removeServerHeader enabled.'
        $solutionText['Cookie Flags'] = 'Çerezlerde Secure/HttpOnly/SameSite eksik. Nginx: add_cookie_flag; PHP: session.cookie_secure=On, session.cookie_httponly=On; IIS: httpOnlyCookies enabled.'
        $solutionText['HTTP to HTTPS'] = 'HTTP/80 trafiği HTTPS''e yönlendirmiyor. Nginx: return 301 https://...; Apache: Redirect permanent / https://...; IIS: https binding gerekli.'
        $solutionText['Security Header'] = 'Güvenlik başlığı eksik. HSTS: Nginx add_header Strict-Transport-Security; CSP: add_header Content-Security-Policy; X-Frame-Options: add_header X-Frame-Options DENY; X-Content-Type-Options: add_header X-Content-Type-Options nosniff.'
        $solutionText['HTTP Flood'] = 'Rate limiting/WAF eksik. Nginx: limit_req_zone + limit_req; Apache: mod_ratelimit; Cloudflare/AWS WAF hız sınırlama.'
        $solutionText['Slowloris'] = 'Sunucu yavaş isteklere açık. Nginx: client_header_timeout 5s, client_body_timeout 5s; Apache: Timeout 5; IIS: headerWaitTimeout kısa tutulmalı.'
        $solutionText['SQL Injection'] = 'SQL enjeksiyon açığı. Hazırlanmış sorgular (prepared statements) kullanın; veritabanı hata mesajlarını gizleyin; parameterized query kullanın.'
        $solutionText['XSS'] = 'XSS açığı. Çıktı kodlaması (output encoding) uygulayın; CSP ekleyin; HttpOnly çerez işaretleyin.'
        $solutionText['HTTP Host Header'] = 'Host başlığı doğrulaması eksik. Sunucu yalnızca bilinen hostname''leri kabul etmeli; rastgele Host başlıkları reddedilmeli.'
        $solutionText['CRLF Injection'] = 'CRLF enjeksiyon açığı. İstek parametrelerinde CR/LF karakterlerini nötrleştirin; HTTP başlık değerlerinde satır sonu karakterlerine izin vermeyin.'
        $solutionText['CSRF'] = 'CSRF token eksik. POST formlara CSRF token ekleyin; çerezleri SameSite=Lax/Strict ile işaretleyin; Origin/Referer doğrulaması yapın.'
        $solutionText['Man-in-the-Middle'] = 'HTTPS + HSTS gerekli. Nginx: return 301 https://...; HSTS: add_header Strict-Transport-Security max-age=31536000; Apache: Redirect permanent / https://...'
        $solutionText['Open Redirect'] = 'Açık yönlendirme. URL parametrelerinde harici adreslere izin vermeyin; yönlendirmeleri aynı etki alanıyla sınırlayın; kullanıcı girdisini doğrulayın.'
        $solutionText['CORS'] = 'CORS yapılandırması açık. Access-Control-Allow-Origin yalnızca güvenilen domain''lere ayarlayın; Allow-Credentials ile joker kullanmayın.'
        $solutionText['Sensitive File Exposure'] = 'Hassas dosyalar açık. Nginx: location ~ /\. { deny all; }; Apache: Require all denied via FilesMatch; dosyaları web kökünden taşıyın.'
        $solutionText['Path Traversal'] = 'Yol gezinme açığı. Girdi normalizasyonu uygulayın; kök dizin kısıtlamaları kullanın; kullanıcı girdisiyle dosya yolu oluşturmayın.'
        $solutionText['Mixed Content'] = 'HTTPS sayfası http:// kaynağı kullanıyor. Tüm kaynakları HTTPS ile sunun;mixed-content içerikleri güncelleyin.'
        $solutionText['Subresource Integrity'] = 'Harici script''lerde integrity eksik. CDN kaynaklarına integrity özetleri ekleyin; integrity ve crossorigin attribute''larını kullanın.'
        $solutionText['robots.txt'] = 'robots.txt''de Sitemap eksik veya çok geniş izin verilmiş. Sitemap ekleyin; hassas dizinleri Disallow ile kısıtlayın.'
        $solutionText['Client Access Policy'] = 'Cross-domain policy dosyası açık. clientaccesspolicy.xml / crossdomain.xml dosyalarını kısıtlayın veya kaldırın.'
        $solutionText['security.txt'] = 'security.txt eksik veya hatalı. /.well-known/security.txt dosyası oluşturun; Contact: mailto: ekleyin.'
        $solutionText['Sensitive Files'] = 'Hassas dosyalar (backup, .env, debug) açık. Nginx: location ~ (\.env|\.bak|\.sql) { deny all; }; web kökünden kaldırın.'
        $solutionText['Information Disclosure'] = 'Bilgi ifşası. Debug başlıklarını (X-Debug, X-Powered-By) kaldırın; hata sayfalarında stack trace göstermeyin.'
        $solutionText['Cleartext Credentials'] = 'Şifre açık metin olarak gönderiliyor. Tüm form action''ları HTTPS ile işaretleyin; HTTP''yi HTTPS''e yönlendirin.'
        $solutionText['Commented Code'] = 'Yorum satırlarında hassas kod/debug bilgisi var. Üretim ortamında yorum satırlarını ve debug bilgilerini kaldırın.'
        $solutionText['Login Interface'] = 'Giriş arayüzü tespit edildi. Admin sayfalarını kısıtlayın; erişim kontrolü uygulayın; brute-force koruması ekleyin.'
        $solutionText['Outdated JS Libraries'] = 'Eski JS kütüphaneleri tespit edildi. Kütüphaneleri güncelleyin; bilinen güvenlik açıklarını kontrol edin.'
        $solutionText['Admin Pages'] = 'Yönetici sayfaları açık. Erişimi kısıtlayın; IP bazlı erişim kontrolü uygulayın; VPN/whitelist kullanın.'
        $solutionText['Server Misconfiguration'] = 'Sunucu yapılandırma sorunu. TRACE engelleyin; eksik güvenlik başlıklarını ekleyin; verbose hata sayfalarını devre dışı bırakın.'
    } else {
        $solutionText['TRACE Method'] = 'TRACE method enabled; XST risk. Nginx: discardante_http_trace off; Apache: TraceEnable Off; IIS: block TRACE via <verbs>.'
        $solutionText['PUT'] = 'PUT method allowed; unauthorized content change risk. Allow only GET/HEAD/POST/OPTIONS.'
        $solutionText['DELETE'] = 'DELETE method allowed; unauthorized resource deletion risk. Allow only required methods.'
        $solutionText['PATCH'] = 'PATCH method allowed; restrict unless required.'
        $solutionText['Directory Listing'] = 'Directory listing enabled; content/version exposure. Nginx: autoindex off; Apache: Options -Indexes; IIS: directoryBrowsing disabled.'
        $solutionText['Server Banner'] = 'Server banner disclosed; enlarges attack surface. Nginx: server_tokens off; Apache: ServerSignature Off; IIS: removeServerHeader enabled.'
        $solutionText['X-Powered-By'] = 'Technology components disclosed. Nginx: proxy_hide_header X-Powered-By; Apache: Header unset X-Powered-By; IIS: removeServerHeader.'
        $solutionText['Cookie Flags'] = 'Cookies missing Secure/HttpOnly/SameSite flags. Nginx: add_cookie_flag; PHP: session.cookie_secure=On, session.cookie_httponly=On; IIS: httpOnlyCookies enabled.'
        $solutionText['HTTP to HTTPS'] = 'HTTP/80 does not redirect to HTTPS. Nginx: return 301 https://...; Apache: Redirect permanent / https://...; IIS: add HTTPS binding.'
        $solutionText['Security Header'] = 'Security header missing. HSTS: add_header Strict-Transport-Security; CSP: add_header Content-Security-Policy; X-Frame-Options: add_header X-Frame-Options DENY; X-Content-Type-Options: add_header X-Content-Type-Options nosniff.'
        $solutionText['HTTP Flood'] = 'No rate limiting/WAF. Nginx: limit_req_zone + limit_req; Apache: mod_ratelimit; deploy Cloudflare/AWS WAF rate limiting.'
        $solutionText['Slowloris'] = 'Server vulnerable to slow requests. Nginx: client_header_timeout 5s, client_body_timeout 5s; Apache: Timeout 5; IIS: short headerWaitTimeout.'
        $solutionText['SQL Injection'] = 'SQL injection vulnerability. Use prepared statements (parameterized queries); hide database errors from users; validate input.'
        $solutionText['XSS'] = 'XSS vulnerability. Apply output encoding; add Content-Security-Policy header; mark cookies HttpOnly.'
        $solutionText['HTTP Host Header'] = 'Host header validation missing. Server should accept only known hostnames; reject arbitrary Host headers with 400/403.'
        $solutionText['CRLF Injection'] = 'CRLF injection flaw. Neutralize CR/LF characters in request parameters; forbid line terminators in HTTP header values.'
        $solutionText['CSRF'] = 'CSRF token missing. Add CSRF tokens to POST forms; mark cookies SameSite=Lax/Strict; validate Origin/Referer.'
        $solutionText['Man-in-the-Middle'] = 'HTTPS + HSTS required. Nginx: return 301 https://...; add_header Strict-Transport-Security max-age=31536000; Apache: Redirect permanent / https://...'
        $solutionText['Open Redirect'] = 'Open-redirect risk. Do not redirect to external URLs in parameters; restrict redirects to same-domain targets; validate user input.'
        $solutionText['CORS'] = 'CORS misconfigured. Set Access-Control-Allow-Origin only for trusted domains; never combine Allow-Credentials with a wildcard.'
        $solutionText['Sensitive File Exposure'] = 'Sensitive files exposed. Nginx: location ~ /\. { deny all; }; Apache: Require denied via FilesMatch; move files out of web root.'
        $solutionText['Path Traversal'] = 'Path-traversal flaw. Apply input normalization; use root-directory restrictions; never build file paths from user input.'
        $solutionText['Mixed Content'] = 'HTTPS page references http:// resources. Serve all resources over HTTPS; update mixed-content references.'
        $solutionText['Subresource Integrity'] = 'External scripts lack SRI. Add integrity hashes with the integrity and crossorigin attributes.'
        $solutionText['robots.txt'] = 'robots.txt missing Sitemap or overly permissive. Add Sitemap directive; restrict sensitive directories with Disallow.'
        $solutionText['Client Access Policy'] = 'Cross-domain policy file exposed. Restrict or remove clientaccesspolicy.xml / crossdomain.xml.'
        $solutionText['security.txt'] = 'security.txt missing or incomplete. Create /.well-known/security.txt; include Contact: mailto:.'
        $solutionText['Sensitive Files'] = 'Sensitive files (backups, .env, debug) exposed. Nginx: location ~ (\.env|\.bak|\.sql) { deny all; }; remove from web root.'
        $solutionText['Information Disclosure'] = 'Information disclosed via headers/errors. Remove debug headers (X-Debug, X-Powered-By); disable verbose error pages.'
        $solutionText['Cleartext Credentials'] = 'Credentials submitted in clear text. Mark all form actions as HTTPS; redirect HTTP to HTTPS.'
        $solutionText['Commented Code'] = 'Sensitive code/comments found in source. Remove comment blocks and debug info from production.'
        $solutionText['Login Interface'] = 'Login interface detected. Restrict admin pages; apply access control; add brute-force protection.'
        $solutionText['Outdated JS Libraries'] = 'Outdated JavaScript libraries detected. Update libraries; check for known CVEs.'
        $solutionText['Admin Pages'] = 'Admin pages exposed. Restrict access; apply IP-based access control; use VPN/whitelist.'
        $solutionText['Server Misconfiguration'] = 'Server misconfiguration. Disable TRACE; add missing security headers; disable verbose error pages.'
    }
    $headerSolutionMap = @{
        'Strict-Transport-Security' = 'Security Header'
        'Content-Security-Policy' = 'Security Header'
        'X-Content-Type-Options' = 'Security Header'
        'X-Frame-Options' = 'Security Header'
        'Referrer-Policy' = 'Security Header'
        'Permissions-Policy' = 'Security Header'
    }
    foreach ($row in $webSecRows) {
        if ($row.Status -notin @('Danger','Warn','Fail')) { continue }
        $solutionKey = if ($headerSolutionMap.ContainsKey([string]$row.Check)) { $headerSolutionMap[[string]$row.Check] } else { [string]$row.Check }
        if (-not $solutionText.ContainsKey($solutionKey)) { continue }
        $noteKey = "$($row.Port)|$solutionKey"
        if ($webSecAdvised.ContainsKey($noteKey)) { continue }
        $webSecAdvised[$noteKey] = $true
        $severityPrefix = if ($row.Status -in @('Danger','Fail')) { '[!]' } else { '[i]' }
        $webSecAdvices.Add("$severityPrefix Port $($row.Port): $($solutionText[$solutionKey])")
    }
}

Write-LogHeader '7. KÖK NEDEN VE ÇAPRAZ KORELASYON'
$analysis = New-Object Text.StringBuilder

$networkQualityAvailable = (
    $null -ne $destinationPingMetrics -and
    $destinationPingMetrics.Successful -gt 0
)
$allHttpRequestsFailed = (
    $appMetricsAvailable -and
    $null -ne $jmeterErrRateVal -and
    $jmeterErrRateVal -ge 100
)
$appErrorsHigh = (
    $appMetricsAvailable -and
    $null -ne $jmeterErrRateVal -and
    $jmeterErrRateVal -gt 5
)
$appSlow = (
    $appMetricsAvailable -and
    $null -ne $jmeterP95Val -and
    $jmeterP95Val -gt 1000
)
$targetLossHigh = (
    $networkQualityAvailable -and
    $destinationPingMetrics.LossPercent -gt 2
)
$targetJitterModerate = (
    $networkQualityAvailable -and
    $destinationPingMetrics.MeanJitter -ge 10 -and
    $destinationPingMetrics.MeanJitter -lt 20
)
$targetJitterHigh = (
    $networkQualityAvailable -and
    $destinationPingMetrics.MeanJitter -ge 20
)

$tailLatencyProblem = (
    $appMetricsAvailable -and
    $null -ne $jmeterTailRatio -and
    $jmeterTailRatio -ge 3
)
$wideSpread = (
    $appMetricsAvailable -and
    $null -ne $jmeterSpreadVal -and
    $jmeterSpreadVal -gt 500
)
$capacitySaturation = (
    $appMetricsAvailable -and
    $null -ne $jmeterP50Val -and
    $jmeterP50Val -gt 200 -and
    $null -ne $jmeterP99Val -and
    $jmeterP99Val -gt 1000
)
$lowSampleQuality = (
    $appMetricsAvailable -and
    $jmeterSamplesCount -gt 0 -and
    $jmeterSamplesCount -lt 200
)

if ($Script:LanguageCode -eq 'tr') {
    [void]$analysis.AppendLine('<b>[Sistem Mimarisi ve Performans Değerlendirmesi]</b><br>')

    if ($allHttpRequestsFailed) {
        [void]$analysis.AppendLine("<b>UYGULAMA TESTİ TAMAMEN BAŞARISIZ</b><br>HTTP isteklerinin tamamı başarısız oldu. Başarılı örnek olmadığı için p95 hesaplanmadı. Hata dağılımı: $($ReportData.JMeter_Error_Distribution). Hedef servis, protokol, TLS, WAF ve uygulama yanıtı kontrol edilmelidir.")
    }
    elseif ($tailLatencyProblem) {
        $spreadMs = if ($null -ne $jmeterSpreadVal) { "$jmeterSpreadVal ms" } else { 'N/A' }
        [void]$analysis.AppendLine("<b>KUYRUK LATENCY PROBLEMI (Kuyruk Oranı ${tailRatio}x)</b><br>p50: $jmeterP50Val ms, p99: $jmeterP99Val ms, yayılım: $spreadMs. Kullanıcıların çoğunluğu hızlı yanıt alırken, %5'lik kesim çok daha yavaş. Backend servislerde kuyruk, lock contention veya GC duraklamaları araştırılmalıdır. p95 tercih edin, p99 tek başına yanıltıcı olabilir.")
    }
    elseif ($wideSpread) {
        $tailLabel = if ($null -ne $jmeterTailRatio) { " (Kuyruk Oranı: ${tailRatio}x)" } else { '' }
        [void]$analysis.AppendLine("<b>GENİŞ GECİKME YAYILIMI${tailLabel}</b><br>p50: $jmeterP50Val ms, p99: $jmeterP99Val ms, yayılım: $jmeterSpreadVal ms. Yanıt süreleri tutarsız; uygulama katmanında dalgalanma var. Hotspot analizi, thread contention veya depolama gecikmesi kaynakları incelenmelidir.")
    }
    elseif ($capacitySaturation) {
        $ttfbLabel = if ($null -ne $jmeterP50Val) { " TTFB p50: $($displayP50Header) ms." } else { '' }
        [void]$analysis.AppendLine("<b>KAPASİTE DOYUMU</b><br>p50 ($jmeterP50Val ms) ve p99 ($jmeterP99Val ms) ikisi de yüksek. Sunucu, CPU, RAM, bağlantı havuzu veya thread kapasitesi doymuş durumda.${ttfbLabel} Ölçekleme veya kaynak artırımı gereklidir.")
    }
    elseif ($appErrorsHigh) {
        [void]$analysis.AppendLine("<b>YÜKSEK UYGULAMA HATA ORANI</b><br>HTTP hata oranı %$jmeterErrRateVal. HTTP p95: $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}). Hata dağılımı: $($ReportData.JMeter_Error_Distribution).")
    }
    elseif ((-not $networkQualityAvailable) -and (-not $appMetricsAvailable)) {
        [void]$analysis.AppendLine('<b>SONUÇ: YETERSİZ ÖLÇÜM</b><br>Hedef ICMP kalite metrikleri ve HTTP yük metrikleri alınamadığından kesin korelasyon yapılamadı.')
    }
    elseif ($targetLossHigh -and $appSlow) {
        [void]$analysis.AppendLine("<b>OLASI AĞ KALİTESİ SORUNU</b><br>Hedef paket yanıt kaybı %$($destinationPingMetrics.LossPercent), hedef jitter ±$($destinationPingMetrics.MeanJitter) ms ve HTTP p95 $jmeterP95Val ms. Paket kaybı ile uygulama gecikmesi aynı ölçümde görüldü.")
    }
    elseif ($targetJitterHigh -and $appSlow) {
        [void]$analysis.AppendLine("<b>AĞ VE UYGULAMA GECİKMESİ KORELASYONU</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, hedef RTT p95 $($destinationPingMetrics.P95) ms ve HTTP p95 $jmeterP95Val ms. Ağ değişkenliği uygulama yanıt dağılımını etkiliyor olabilir.")
    }
    elseif ($networkQualityAvailable -and (-not $targetJitterModerate) -and (-not $targetJitterHigh) -and (-not $targetLossHigh) -and $appSlow) {
        [void]$analysis.AppendLine("<b>OLASI SUNUCU VEYA UYGULAMA DARBOĞAZI</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms ve kayıp %$($destinationPingMetrics.LossPercent) iken HTTP p95 $jmeterP95Val ms. Uygulama, bağımlı servisler, veritabanı ve sunucu kaynakları incelenmelidir.")
    }
    elseif (($targetJitterModerate -or $targetJitterHigh) -and (-not $appSlow)) {
        [void]$analysis.AppendLine("<b>AĞ DEĞİŞKENLİĞİ VAR, UYGULAMA ETKİLENMEMİŞ</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms olmasına rağmen HTTP p95 $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}) ve hata oranı %$(if($null-ne$jmeterErrRateVal){$jmeterErrRateVal}else{'N/A'}).")
    }
    elseif ($networkQualityAvailable -and $appMetricsAvailable) {
        [void]$analysis.AppendLine("<b>ÖLÇÜLEN DEĞERLER NORMAL</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, hedef RTT p95 $($destinationPingMetrics.P95) ms, HTTP p95 $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}) ve hata oranı %$(if($null-ne$jmeterErrRateVal){$jmeterErrRateVal}else{'N/A'}).")
    }
    elseif ($networkQualityAvailable) {
        [void]$analysis.AppendLine("<b>AĞ KALİTESİ ÖLÇÜLDÜ</b><br>Hedef jitter ±$($destinationPingMetrics.MeanJitter) ms, RTT p95 $($destinationPingMetrics.P95) ms ve kayıp %$($destinationPingMetrics.LossPercent). $(if($loadTestSkipped){$loadTestSkipReason}else{'Uygulama yük testi yapılmadı.'})")
    }
    else {
        [void]$analysis.AppendLine("<b>UYGULAMA ÖLÇÜLDÜ, AĞ METRİĞİ SINIRLI</b><br>HTTP p95 $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}) ve hata oranı %$(if($null-ne$jmeterErrRateVal){$jmeterErrRateVal}else{'N/A'}); hedef ICMP kalite metriği alınamadı.")
    }

    if ($null -ne $maxJitterVal -and $networkQualityAvailable -and $maxJitterVal -gt 20 -and $destinationPingMetrics.MeanJitter -lt 10) {
        [void]$analysis.AppendLine('<br><b>ARA HOP ICMP VARYASYONU</b><br>Bazı ara hoplarda yüksek ICMP yanıt değişkenliği görülmesine rağmen son hedef jitter değeri düşüktür. Ara hop değişkenliği uçtan uca trafik bozulması olarak doğrulanmamıştır.')
    }

    if ($lowSampleQuality) {
        [void]$analysis.AppendLine("<br><b>⚠ DÜŞÜK ÖRNEK KALİTESİ</b><br>Sadece $jmeterSamplesCount örnek toplandı. p99 güvenilirliği için en az 200 örnek gereklidir. p95 değeri tercih edilmelidir. Test süresini artırın veya eşzamanlı istek sayısını yükseltin.")
    }
}
else {
    [void]$analysis.AppendLine('<b>[System Architecture and Performance Assessment]</b><br>')

    if ($allHttpRequestsFailed) {
        [void]$analysis.AppendLine("<b>APPLICATION TEST COMPLETELY FAILED</b><br>All HTTP requests failed. p95 was not calculated because there were no successful samples. Error distribution: $($ReportData.JMeter_Error_Distribution). Verify the target service, protocol, TLS, WAF, and application response.")
    }
    elseif ($tailLatencyProblem) {
        $spreadMs = if ($null -ne $jmeterSpreadVal) { "$jmeterSpreadVal ms" } else { 'N/A' }
        [void]$analysis.AppendLine("<b>TAIL LATENCY PROBLEM (Tail Ratio ${tailRatio}x)</b><br>p50: $jmeterP50Val ms, p99: $jmeterP99Val ms, spread: $spreadMs. Most users get fast responses, but the worst 5% are significantly slower. Investigate backend service queuing, lock contention, or GC pauses. Prefer p95 over p99; p99 alone can be misleading.")
    }
    elseif ($wideSpread) {
        $tailLabel = if ($null -ne $jmeterTailRatio) { " (Tail Ratio: ${tailRatio}x)" } else { '' }
        [void]$analysis.AppendLine("<b>WIDE LATENCY SPREAD${tailLabel}</b><br>p50: $jmeterP50Val ms, p99: $jmeterP99Val ms, spread: $jmeterSpreadVal ms. Response times are inconsistent; there is application-layer variance. Investigate hotspot analysis, thread contention, or storage latency sources.")
    }
    elseif ($capacitySaturation) {
        $ttfbLabel = if ($null -ne $jmeterP50Val) { " TTFB p50: $($displayP50Header) ms." } else { '' }
        [void]$analysis.AppendLine("<b>CAPACITY SATURATION</b><br>p50 ($jmeterP50Val ms) and p99 ($jmeterP99Val ms) are both high. Server CPU, RAM, connection pool, or thread capacity is saturated.${ttfbLabel} Scaling or resource increase is required.")
    }
    elseif ($appErrorsHigh) {
        [void]$analysis.AppendLine("<b>HIGH APPLICATION ERROR RATE</b><br>HTTP error rate is $jmeterErrRateVal%. HTTP p95: $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}). Error distribution: $($ReportData.JMeter_Error_Distribution).")
    }
    elseif ((-not $networkQualityAvailable) -and (-not $appMetricsAvailable)) {
        [void]$analysis.AppendLine('<b>RESULT: INSUFFICIENT MEASUREMENT</b><br>Destination ICMP quality metrics and HTTP load metrics were unavailable, so no definitive correlation could be made.')
    }
    elseif ($targetLossHigh -and $appSlow) {
        [void]$analysis.AppendLine("<b>POSSIBLE NETWORK QUALITY ISSUE</b><br>Destination response loss is $($destinationPingMetrics.LossPercent)%, destination jitter is ±$($destinationPingMetrics.MeanJitter) ms, and HTTP p95 is $jmeterP95Val ms. Packet loss and application latency were observed in the same measurement.")
    }
    elseif ($targetJitterHigh -and $appSlow) {
        [void]$analysis.AppendLine("<b>NETWORK AND APPLICATION LATENCY CORRELATION</b><br>Destination jitter is ±$($destinationPingMetrics.MeanJitter) ms, destination RTT p95 is $($destinationPingMetrics.P95) ms, and HTTP p95 is $jmeterP95Val ms. Network variation may be affecting the application response-time distribution.")
    }
    elseif ($networkQualityAvailable -and (-not $targetJitterModerate) -and (-not $targetJitterHigh) -and (-not $targetLossHigh) -and $appSlow) {
        [void]$analysis.AppendLine("<b>POSSIBLE SERVER OR APPLICATION BOTTLENECK</b><br>Destination jitter is ±$($destinationPingMetrics.MeanJitter) ms and loss is $($destinationPingMetrics.LossPercent)%, while HTTP p95 is $jmeterP95Val ms. Investigate the application, dependent services, database, and server resources.")
    }
    elseif (($targetJitterModerate -or $targetJitterHigh) -and (-not $appSlow)) {
        [void]$analysis.AppendLine("<b>NETWORK VARIATION DETECTED, APPLICATION UNAFFECTED</b><br>Destination jitter is ±$($destinationPingMetrics.MeanJitter) ms, while HTTP p95 is $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}) and the error rate is $(if($null-ne$jmeterErrRateVal){"$jmeterErrRateVal%"}else{'N/A'}).")
    }
    elseif ($networkQualityAvailable -and $appMetricsAvailable) {
        [void]$analysis.AppendLine("<b>MEASURED VALUES ARE NORMAL</b><br>Destination jitter is ±$($destinationPingMetrics.MeanJitter) ms, destination RTT p95 is $($destinationPingMetrics.P95) ms, HTTP p95 is $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}), and the error rate is $(if($null-ne$jmeterErrRateVal){"$jmeterErrRateVal%"}else{'N/A'}).")
    }
    elseif ($networkQualityAvailable) {
        [void]$analysis.AppendLine("<b>NETWORK QUALITY MEASURED</b><br>Destination jitter is ±$($destinationPingMetrics.MeanJitter) ms, RTT p95 is $($destinationPingMetrics.P95) ms, and loss is $($destinationPingMetrics.LossPercent)%. $(if($loadTestSkipped){$loadTestSkipReason}else{'Application load testing was not performed.'})")
    }
    else {
        [void]$analysis.AppendLine("<b>APPLICATION MEASURED, NETWORK METRICS LIMITED</b><br>HTTP p95 is $(if($null-ne$jmeterP95Val){"$jmeterP95Val ms"}else{'N/A'}), and the error rate is $(if($null-ne$jmeterErrRateVal){"$jmeterErrRateVal%"}else{'N/A'}); destination ICMP quality metrics were unavailable.")
    }

    if ($null -ne $maxJitterVal -and $networkQualityAvailable -and $maxJitterVal -gt 20 -and $destinationPingMetrics.MeanJitter -lt 10) {
        [void]$analysis.AppendLine('<br><b>INTERMEDIATE-HOP ICMP VARIATION</b><br>Some intermediate hops showed high ICMP response variation, while destination jitter remained low. The intermediate-hop variation was not confirmed as end-to-end traffic degradation.')
    }

    if ($lowSampleQuality) {
        [void]$analysis.AppendLine("<br><b>⚠ LOW SAMPLE QUALITY</b><br>Only $jmeterSamplesCount samples collected. p99 reliability requires at least 200 samples. Prefer p95. Increase test duration or concurrent request count.")
    }
}

Write-Host (($analysis.ToString() -replace '<br>',"`n") -replace '<[^>]+>','') -ForegroundColor Yellow

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
        Env_ComputerName='İstemci Bilgisayar Adı'; Env_OS='İşletim Sistemi'; Env_CPU='CPU Bilgisi ve Kullanımı'; Env_CPU_Source='CPU Kullanım Veri Kaynağı';
        Env_Memory='Sistem Belleği (RAM)'; Env_Disk='Disk Kullanımı'; Env_LocalIP='Aktif Ağ Adaptörü ve Yerel IP';
        Local_DNS_IP='Yerel DNS IPv4 Sonucu'; Public_DNS_IP='Google Public DNS IPv4 Sonucu';
        Cloudflare_DNS_IP='Cloudflare DNS IPv4 Sonucu'; DNS_Query_Time='Yerel DNS Sorgu Süresi';
        DNS_Name_Servers='Yetkili DNS Sunucuları'; Reverse_DNS='Reverse DNS (PTR) Kaydı';
        CDN_Status='CDN / Reverse Proxy Durumu'; ICMP_Status='ICMP Ping Durumu';
        Unloaded_Avg_RTT='Boştaki Ortalama Gecikme (RTT)'; Path_MTU='Path MTU Tahmini';
        Port_Matrix='TCP Port Erişilebilirlik Matrisi'; UDP_Port_Matrix='UDP Servis Doğrulama Matrisi'; Verified_UDP_Service_Count='Doğrulanan UDP Servis Sayısı'; Unresponsive_UDP_Service_Count='Yanıt Vermeyen UDP Servis Sayısı'; Target_Port_Status='Seçilen Portun Durumu';
        Open_Port_Count='Açık Port Sayısı'; Tested_Port_Count='Test Edilen Port Sayısı'; Verified_Service_Count='Doğrulanan Servis Sayısı'; Unverified_TCP_Count='Doğrulanamayan TCP Bağlantısı'; Closed_Filtered_Count='Kapalı / Filtreli Port Sayısı';
        Reachability_Status='Genel Erişilebilirlik Durumu'; JMeter_Threads='Eşzamanlı Sanal Kullanıcı';
        JMeter_Total_Requests='Toplam HTTP İsteği'; JMeter_Throughput_RPS='HTTP İşlem Hızı (RPS)';
        JMeter_Avg_Latency='Ortalama HTTP Yanıt Süresi'; JMeter_p90_Latency='p90 HTTP Yanıt Süresi';
        JMeter_p95_Latency='p95 HTTP Yanıt Süresi'; JMeter_Error_Rate='HTTP Hata Oranı';
        Ext_JMeter_File='Harici JMeter Sonuç Dosyası'; Ext_JMeter_p95='Harici JMeter p95';
        SSL_Subject='SSL Sertifika Konusu'; SSL_Issuer='SSL Sertifika Yayıncısı';
        SSL_Days_Left='SSL Kalan Geçerlilik Süresi'; HTTP_Code='HTTP Yanıt Kodu';
        HTTP_Total_Time='Toplam HTTP Yanıt Süresi'; ICMP_Sent='Gönderilen ICMP Paketi'; ICMP_Received='Yanıtlanan ICMP Paketi'; ICMP_Loss='Hedef ICMP Yanıt Kaybı';
        Unloaded_Min_RTT='Hedef Minimum RTT'; Unloaded_Median_RTT='Hedef Medyan RTT'; Unloaded_p95_RTT='Hedef p95 RTT'; Unloaded_Max_RTT='Hedef Maksimum RTT'; Destination_RTT_StdDev='Hedef RTT Standart Sapması'; Destination_Mean_Jitter='Hedef Ortalama Jitter'; Destination_Peak_Jitter='Hedef Peak Jitter'; Destination_Smoothed_Variation='Hedef Yumuşatılmış RTT Değişimi';
        HTTPS_Certificate_Status='HTTPS Sertifika Durumu'; HTTPS_Certificate_NotBefore='HTTPS Sertifika Başlangıcı'; HTTPS_Certificate_NotAfter='HTTPS Sertifika Bitişi'; Effective_Load_Test_URL='Etkin Yük Testi URL''si'; Load_Test_Status='HTTP Yük Testi Durumu'; JMeter_Engine='HTTP Yük Test Motoru'; JMeter_Method='HTTP Metodu'; JMeter_Peak_Concurrency='Ölçülen En Yüksek Eşzamanlı İstek'; JMeter_RampUp='Ramp-up Süresi'; JMeter_Warmup_Requests='Warm-up İstek Sayısı'; JMeter_Successful_Requests='Başarılı HTTP İsteği'; JMeter_Failed_Requests='Başarısız HTTP İsteği'; JMeter_Test_Duration='Toplam Yük Testi Süresi'; JMeter_Avg_Header_Time='Ortalama Header / TTFB Süresi'; JMeter_p95_Header_Time='p95 Header / TTFB Süresi';         JMeter_Avg_Download_Time='Ortalama Response İndirme Süresi'; JMeter_Avg_Elapsed='Ortalama Toplam HTTP Süresi'; JMeter_Elapsed_StdDev='HTTP Süre Standart Sapması'; JMeter_p50_Elapsed='p50 Toplam HTTP Süresi'; JMeter_p75_Elapsed='p75 Toplam HTTP Süresi'; JMeter_p90_Elapsed='p90 Toplam HTTP Süresi'; JMeter_p95_Elapsed='p95 Toplam HTTP Süresi'; JMeter_p99_Elapsed='p99 Toplam HTTP Süresi'; JMeter_TTFB_p50='p50 Header / TTFB Süresi'; JMeter_TTFB_p90='p90 Header / TTFB Süresi'; JMeter_TTFB_p99='p99 Header / TTFB Süresi'; JMeter_TTFB_Spread='TTFB Yayılımı'; JMeter_Tail_Ratio='Kuyruk Oranı (p99/p50)'; JMeter_Spread_ms='Gecikme Yayılımı (p99-p50)'; JMeter_Min_Elapsed='En Düşük HTTP Süresi'; JMeter_Max_Elapsed='En Yüksek HTTP Süresi'; JMeter_Status_Distribution='HTTP Durum Kodu Dağılımı'; JMeter_Error_Distribution='HTTP Hata Tipi Dağılımı'; JMeter_Total_Data='Toplam Alınan Response Verisi'; JMeter_Average_Response_Size='Ortalama Response Boyutu'; JMeter_Download_Throughput='Response Veri Aktarım Hızı';
        TLS_Supported_Versions='Desteklenen TLS Sürümleri'; TLS_Negotiated_Protocol='Müzakere Edilen TLS Sürümü'; TLS_Negotiated_Cipher='Müzakere Edilen Şifreleme'; HTTP_Version_ALPN='HTTP Protokolü (ALPN)'; HTTP2_Status='HTTP/2 Durumu'; HTTP3_QUIC_Status='HTTP/3 (QUIC) Durumu'; Security_Header_Score='Güvenlik Başlığı Puanı'; Security_Headers='Güvenlik Başlığı Denetimi';
        GeoIP_Target_ASN='Hedef ASN / Ağ Sağlayıcı'; GeoIP_Target_Location='Hedef Coğrafi Konum'; GeoIP_Target_ISP='Hedef İSS / Organizasyon'; GeoIP_Hop_ASN='Yol Üzerindeki Ağlar (ASN)';
        DNSSEC_Status='DNSSEC Durumu'; DNS_DoT_Status='DNS-over-TLS (853) Durumu'; DNS_DoH_Status='DNS-over-HTTPS Durumu'; DNS_Resolver_Consistency='Çözümleyici Tutarlılığı (UDP/DoT/DoH)'; DNS_MX_Records='MX Kayıtları'; DNS_SPF_Record='SPF Kaydı'; DNS_DMARC_Record='DMARC Kaydı'; DNS_DKIM_Record='DKIM Kaydı'; DNS_CAA_Records='CAA Kayıtları'; DNS_Exposure_Summary='DNS Sızıntı Özeti';
        HTTPS_Cert_SAN='HTTPS Sertifika SAN Alanları'; HTTPS_Cert_SAN_Match='SAN Hostname Eşleşmesi'; HTTPS_Cert_Chain='Sertifika Zinciri Geçerliliği'; HTTPS_Cert_Chain_Status='Sertifika Zinciri Durumları'; HTTPS_Cert_Revocation='İptal (Revocation) Durumu'; HTTPS_Cert_Signature='Sertifika İmza Algoritması'; HTTPS_Cert_Valid='Sertifika Geçerlilik Penceresi';
        Wifi_Ssid='Wi-Fi Ağ Adı (SSID)'; Wifi_Signal_Percent='Wi-Fi Sinyal Gücü'; Wifi_Channel='Wi-Fi Kanalı'; Wifi_Radio_Type='Wi-Fi Radyo Tipi'; Wifi_Rx_Mbps='Wi-Fi Alış (RX) Hızı'; Wifi_Tx_Mbps='Wi-Fi Gönderim (TX) Hızı';
        Adapter_Status='Ağ Adaptörü Durumu'; Adapter_Link_Speed='Adaptör Bağlantı Hızı'; Adapter_Media='Adaptör Medya Tipi'; Adapter_Packet_Errors='Adaptör Paket Hataları';
        Port_List='Taranan Portlar'
    }
    $systemMetricGroups = @(
        @{ Title='Script Bilgisi'; Keys=@('Script_Version','Language','System_UICulture','Yes_No_Format','Timestamp') },
        @{ Title='Hedef'; Keys=@('Target','Port','ScanLevel') },
        @{ Title='Sistem Kaynakları'; Keys=@('Env_User','Env_ComputerName','Env_OS','Env_CPU','Env_CPU_Source','Env_Memory','Env_Disk','Env_LocalIP') },
        @{ Title='Wi-Fi'; Keys=@('Wifi_Ssid','Wifi_Signal_Percent','Wifi_Channel','Wifi_Radio_Type','Wifi_Rx_Mbps','Wifi_Tx_Mbps') },
        @{ Title='Ağ Adaptörü'; Keys=@('Adapter_Status','Adapter_Link_Speed','Adapter_Media','Adapter_Packet_Errors') }
    )
    $networkMetricGroups = @(
        @{ Title='DNS'; Keys=@('Local_DNS_IP','Public_DNS_IP','Cloudflare_DNS_IP','DNS_Query_Time','DNS_Name_Servers','Reverse_DNS','CDN_Status','DNSSEC_Status','DNS_DoT_Status','DNS_DoH_Status','DNS_Resolver_Consistency') },
        @{ Title='ICMP / Ping'; Keys=@('ICMP_Status','Unloaded_Avg_RTT','Path_MTU','ICMP_Sent','ICMP_Received','ICMP_Loss') },
        @{ Title='TCP / UDP Portları'; Keys=@('Open_Port_Count','Tested_Port_Count','Verified_Service_Count','Unverified_TCP_Count','Closed_Filtered_Count','Port_Matrix','UDP_Port_Matrix','Verified_UDP_Service_Count','Unresponsive_UDP_Service_Count','Target_Port_Status','Port_List','Reachability_Status') },
        @{ Title='Hedef Jitter Metrikleri'; Keys=@('Unloaded_Min_RTT','Unloaded_Median_RTT','Unloaded_p95_RTT','Unloaded_Max_RTT','Destination_RTT_StdDev','Destination_Mean_Jitter','Destination_Peak_Jitter','Destination_Smoothed_Variation') },
        @{ Title='GeoIP / ASN'; Keys=@('GeoIP_Target_ASN','GeoIP_Target_Location','GeoIP_Target_ISP','GeoIP_Hop_ASN') }
    )
    $systemMetricKeys = @()
    foreach ($g in $systemMetricGroups) { $systemMetricKeys += $g.Keys }
    $networkMetricKeys = @()
    foreach ($g in $networkMetricGroups) { $networkMetricKeys += $g.Keys }
    $applicationMetricGroups = @(
        @{ Title='Yük Testi Yapılandırması'; Keys=@('Effective_Load_Test_URL','Load_Test_Status','JMeter_Engine','JMeter_Method','JMeter_Peak_Concurrency','JMeter_RampUp','JMeter_Warmup_Requests','JMeter_Threads') },
        @{ Title='Yük Testi Sonuçları'; Keys=@('JMeter_Total_Requests','JMeter_Successful_Requests','JMeter_Failed_Requests','JMeter_Test_Duration','JMeter_Error_Rate','JMeter_Throughput_RPS') },
        @{ Title='HTTP Zamanlaması - TTFB'; Keys=@('JMeter_Avg_Header_Time','JMeter_p95_Header_Time','JMeter_TTFB_p50','JMeter_TTFB_p90','JMeter_TTFB_p99','JMeter_TTFB_Spread') },
        @{ Title='HTTP Zamanlaması - Elapsed'; Keys=@('JMeter_Avg_Elapsed','JMeter_Avg_Download_Time','JMeter_Elapsed_StdDev','JMeter_p50_Elapsed','JMeter_p75_Elapsed','JMeter_p90_Elapsed','JMeter_p95_Elapsed','JMeter_p99_Elapsed','JMeter_Tail_Ratio','JMeter_Spread_ms','JMeter_Min_Elapsed','JMeter_Max_Elapsed') },
        @{ Title='HTTP Veri ve Durum'; Keys=@('JMeter_Status_Distribution','JMeter_Error_Distribution','JMeter_Total_Data','JMeter_Average_Response_Size','JMeter_Download_Throughput') },
        @{ Title='HTTP Yanıtı'; Keys=@('HTTP_Code','HTTP_Total_Time') },
        @{ Title='SSL / TLS'; Keys=@('SSL_Subject','SSL_Issuer','SSL_Days_Left','HTTPS_Certificate_Status','HTTPS_Certificate_NotBefore','HTTPS_Certificate_NotAfter','HTTPS_Cert_SAN','HTTPS_Cert_SAN_Match','HTTPS_Cert_Chain','HTTPS_Cert_Chain_Status','HTTPS_Cert_Revocation','HTTPS_Cert_Signature','HTTPS_Cert_Valid','TLS_Supported_Versions','TLS_Negotiated_Protocol','TLS_Negotiated_Cipher') },
        @{ Title='HTTP Protokolü'; Keys=@('HTTP_Version_ALPN','HTTP2_Status','HTTP3_QUIC_Status') },
        @{ Title='Güvenlik Başlıkları'; Keys=@('Security_Header_Score','Security_Headers') },
        @{ Title='Dış JMeter'; Keys=@('Ext_JMeter_File','Ext_JMeter_p95') }
    )
    $applicationMetricKeys = @()
    foreach ($g in $applicationMetricGroups) { $applicationMetricKeys += $g.Keys }
    $dnsExposureKeys = @('DNS_MX_Records','DNS_SPF_Record','DNS_DMARC_Record','DNS_DKIM_Record','DNS_CAA_Records','DNS_Exposure_Summary')
    $appGroupRows = [ordered]@{}
    foreach ($g in $applicationMetricGroups) { $appGroupRows[$g.Title] = New-Object Text.StringBuilder }
    $sysGroupRows = [ordered]@{}
    foreach ($g in $systemMetricGroups) { $sysGroupRows[$g.Title] = New-Object Text.StringBuilder }
    $netGroupRows = [ordered]@{}
    foreach ($g in $networkMetricGroups) { $netGroupRows[$g.Title] = New-Object Text.StringBuilder }
    foreach ($x in $ReportData.GetEnumerator()) {
        if ($x.Key -in $dnsExposureKeys) { continue }
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
        if ($x.Key -in @('Port_Matrix','UDP_Port_Matrix','Security_Headers')) {
            $value = ConvertTo-LocalizedReportValue $rawValue
        } else {
            $localizedValue = ConvertTo-LocalizedReportValue $rawValue
            $value = ConvertTo-HtmlSafe $localizedValue
        }

        $wideClass = if ($x.Key -in @('Port_Matrix','UDP_Port_Matrix','Security_Headers')) { ' metric-item-wide' } else { '' }
        $itemHtml = "<div class='metric-item$wideClass'><div class='metric-label'>$(ConvertTo-HtmlSafe $title)</div><div class='metric-value'>$value</div></div>`n"
        if ($systemMetricKeys -contains $x.Key) {
            foreach ($g in $systemMetricGroups) {
                if ($g.Keys -contains $x.Key) {
                    [void]$sysGroupRows[$g.Title].Append($itemHtml)
                    break
                }
            }
        } elseif ($applicationMetricKeys -contains $x.Key) {
            foreach ($g in $applicationMetricGroups) {
                if ($g.Keys -contains $x.Key) {
                    [void]$appGroupRows[$g.Title].Append($itemHtml)
                    break
                }
            }
        } elseif ($networkMetricKeys -contains $x.Key) {
            foreach ($g in $networkMetricGroups) {
                if ($g.Keys -contains $x.Key) {
                    [void]$netGroupRows[$g.Title].Append($itemHtml)
                    break
                }
            }
        } else {
            # Fallback: items not in any group go to first network group
            if ($networkMetricGroups.Count -gt 0) {
                [void]$netGroupRows[$networkMetricGroups[0].Title].Append($itemHtml)
            }
        }
    }
    $generalSystemTitle = ConvertTo-LocalizedText 'Genel Sistem Metrikleri'
    $networkMetricsTitle = ConvertTo-LocalizedText 'Ağ Metrikleri'
    $applicationMetricsTitle = ConvertTo-LocalizedText 'Uygulama Metrikleri'
    $sysGroupsHtml = ''
    foreach ($g in $systemMetricGroups) {
        $groupTitle = ConvertTo-LocalizedText $g.Title
        $groupContent = $sysGroupRows[$g.Title].ToString()
        if (-not [string]::IsNullOrWhiteSpace($groupContent)) {
            $sysGroupsHtml += "<div class='metric-group-sub'>$groupTitle</div><div class='metric-grid'>$groupContent</div>"
        }
    }
    $netGroupsHtml = ''
    foreach ($g in $networkMetricGroups) {
        $groupTitle = ConvertTo-LocalizedText $g.Title
        $groupContent = $netGroupRows[$g.Title].ToString()
        if (-not [string]::IsNullOrWhiteSpace($groupContent)) {
            $netGroupsHtml += "<div class='metric-group-sub'>$groupTitle</div><div class='metric-grid'>$groupContent</div>"
        }
    }
    $appGroupsHtml = ''
    foreach ($g in $applicationMetricGroups) {
        $groupTitle = ConvertTo-LocalizedText $g.Title
        $groupContent = $appGroupRows[$g.Title].ToString()
        if (-not [string]::IsNullOrWhiteSpace($groupContent)) {
            $appGroupsHtml += "<div class='metric-group-sub'>$groupTitle</div><div class='metric-grid'>$groupContent</div>"
        }
    }
    $metricsGridHtml = "<div class='metric-group-title'>$generalSystemTitle</div>$sysGroupsHtml<div class='metric-group-title'>$networkMetricsTitle</div>$netGroupsHtml<div class='metric-group-title'>$applicationMetricsTitle</div>$appGroupsHtml"
    $dnsExposureSection = ''
    if ($ReportData.Contains('DNS_Exposure_Details')) {
        $dnsExposureTitle = ConvertTo-LocalizedText 'DNS Sızıntı Özeti'
        $emailSecTitle = ConvertTo-LocalizedText 'E-posta Güvenliği'
        $caSecTitle = ConvertTo-LocalizedText 'Sertifika Otoritesi'
        $foundLabel = ConvertTo-LocalizedText 'Bulunan Kayıtlar'
        $missingLabel = ConvertTo-LocalizedText 'Eksik Kayıtlar'
        $foundStateLabel = ConvertTo-LocalizedText 'Bulundu'
        $missingStateLabel = ConvertTo-LocalizedText 'Eksik'
        $riskInfoLabel = ConvertTo-LocalizedText 'Bilgi'
        $riskWarnLabel = ConvertTo-LocalizedText 'Uyarı'
        $riskDangerLabel = ConvertTo-LocalizedText 'Tehlike'
        $details = $ReportData.DNS_Exposure_Details
        $foundList = @($ReportData.DNS_Exposure_Found)
        $missingList = @($ReportData.DNS_Exposure_Missing)
        $totalChecks = 5
        $foundCount = $foundList.Count
        $missingCount = $missingList.Count
        $foundPct = if ($totalChecks -gt 0) { [Math]::Round(($foundCount / $totalChecks) * 100) } else { 0 }
        $barColor = if ($foundPct -ge 80) { '#107c10' } elseif ($foundPct -ge 40) { '#f7630c' } else { '#d13438' }
        # Progress bar
        $dnsExposureSection = "<section class='websec-section'><h3>$dnsExposureTitle</h3>"
        $dnsExposureSection += "<div style='margin:12px 0 18px 0'><div style='display:flex;justify-content:space-between;margin-bottom:6px;font-size:13px;color:#475467'><span>${foundLabel}: $foundCount / $totalChecks</span><span>$foundPct%</span></div><div style='height:10px;background:#edf2f7;border-radius:5px;overflow:hidden'><div style='height:100%;width:$foundPct%;background:$barColor;border-radius:5px'></div></div>"
        $foundSummary = if ($foundCount -gt 0) { [string]::Join(', ', @($foundList | ForEach-Object { ConvertTo-LocalizedText $_ })) } else { '—' }
        $missingSummary = if ($missingCount -gt 0) { [string]::Join(', ', @($missingList | ForEach-Object { ConvertTo-LocalizedText $_ })) } else { '—' }
        $dnsExposureSection += "<div style='margin-top:10px;font-size:12px;color:#475467'><strong style='color:#107c10'>${foundLabel}:</strong> $foundSummary &nbsp;&nbsp;|&nbsp;&nbsp; <strong style='color:#d13438'>${missingLabel}:</strong> $missingSummary</div></div>"
        # Email security group
        $emailTypes = @('MX','MX-External','SPF','SPF-Policy','DMARC','DMARC-Policy','DKIM')
        $emailRows = New-Object Text.StringBuilder
        foreach ($d in $details) {
            if ($d.Type -notin $emailTypes) { continue }
            $riskClass = switch ($d.Risk) { 'Danger' { 'badge-closed' } 'Warn' { 'badge-warning' } default { 'badge-open' } }
            $riskText = switch ($d.Risk) { 'Danger' { $riskDangerLabel } 'Warn' { $riskWarnLabel } default { $riskInfoLabel } }
            $recordLabel = switch ($d.Type) {
                'MX' { ConvertTo-LocalizedText 'MX Kayıtları' }
                'MX-External' { ConvertTo-LocalizedText 'Harici MX Sağlayıcıları' }
                'SPF' { ConvertTo-LocalizedText 'SPF Kaydı' }
                'SPF-Policy' { ConvertTo-LocalizedText 'SPF Politika Analizi' }
                'DMARC' { ConvertTo-LocalizedText 'DMARC Kaydı' }
                'DMARC-Policy' { ConvertTo-LocalizedText 'DMARC Politika Analizi' }
                'DKIM' { ConvertTo-LocalizedText 'DKIM Kaydı' }
            }
            [void]$emailRows.Append("<tr><td>$(ConvertTo-HtmlSafe $recordLabel)</td><td><span class='badge $riskClass'>$(ConvertTo-HtmlSafe $riskText)</span></td><td style='font-size:12px;word-break:break-word'>$(ConvertTo-HtmlSafe (ConvertTo-LocalizedReportValue $d.Detail))</td></tr>`n")
        }
        if ($emailRows.Length -gt 0) {
            $dnsExposureSection += "<div class='metric-group-sub'>$emailSecTitle</div><table><thead><tr><th>$(ConvertTo-LocalizedText 'Denetim')</th><th>$(ConvertTo-LocalizedText 'Durum')</th><th>$(ConvertTo-LocalizedText 'Detay')</th></tr></thead><tbody>$($emailRows.ToString())</tbody></table>"
        }
        # Certificate authority group
        $caTypes = @('CAA')
        $caRows = New-Object Text.StringBuilder
        foreach ($d in $details) {
            if ($d.Type -notin $caTypes) { continue }
            $riskClass = switch ($d.Risk) { 'Danger' { 'badge-closed' } 'Warn' { 'badge-warning' } default { 'badge-open' } }
            $riskText = switch ($d.Risk) { 'Danger' { $riskDangerLabel } 'Warn' { $riskWarnLabel } default { $riskInfoLabel } }
            $recordLabel = ConvertTo-LocalizedText 'CAA Kayıtları'
            [void]$caRows.Append("<tr><td>$(ConvertTo-HtmlSafe $recordLabel)</td><td><span class='badge $riskClass'>$(ConvertTo-HtmlSafe $riskText)</span></td><td style='font-size:12px;word-break:break-word'>$(ConvertTo-HtmlSafe (ConvertTo-LocalizedReportValue $d.Detail))</td></tr>`n")
        }
        if ($caRows.Length -gt 0) {
            $dnsExposureSection += "<div class='metric-group-sub'>$caSecTitle</div><table><thead><tr><th>$(ConvertTo-LocalizedText 'Denetim')</th><th>$(ConvertTo-LocalizedText 'Durum')</th><th>$(ConvertTo-LocalizedText 'Detay')</th></tr></thead><tbody>$($caRows.ToString())</tbody></table>"
        }
        $dnsExposureSection += "</section>"
    }
    $metricsGridHtml += $dnsExposureSection
    $route = New-Object Text.StringBuilder
    foreach ($r in $RouteReportRows) {
        [void]$route.Append(@"
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
"@)
    }
    $routeSection = ''
    if ($route.Length -gt 0) {
        $routeTitle = ConvertTo-LocalizedText 'Hop Katmanlı Rota, Gecikme ve Jitter Analizi'
        $avgHeader = ConvertTo-LocalizedText 'Ort'
        $medianHeader = ConvertTo-LocalizedText 'Medyan'
        $lossHeader = ConvertTo-LocalizedText 'Kayıp'
        $statusHeader = ConvertTo-LocalizedText 'Durum'
        $routeSection = "<h3>$routeTitle</h3><table><thead><tr><th>Hop</th><th>IP</th><th>Min</th><th>Max</th><th>$avgHeader</th><th>$medianHeader</th><th>p95</th><th>Jitter</th><th>Peak</th><th>StdDev</th><th>$lossHeader</th><th>$statusHeader</th></tr></thead><tbody>$($route.ToString())</tbody></table>"
    }
    $webSecSection = ''
    if ($ScanLevel -eq 'WebSec' -and $webSecRows.Count -gt 0) {
        $webSecSectionTitle = if ($Script:LanguageCode -eq 'tr') { 'Web Saldırı Yüzeyi Analizi ve Çözüm Önerileri' } else { 'Web Attack-Surface Analysis and Solution Advice' }
        $portHeader = ConvertTo-LocalizedText 'Port'
        $checkHeader = ConvertTo-LocalizedText 'Denetim'
        $webSecStatusHeader = ConvertTo-LocalizedText 'Durum'
        $detailHeader = ConvertTo-LocalizedText 'Detay'
        $solutionHeader = ConvertTo-LocalizedText 'Çözüm'
        $webSecTableRows = New-Object Text.StringBuilder
        foreach ($row in $webSecRows) {
            $rowCssClass = switch ($row.Status) {
                'Pass'   { 'success' }
                'Warn'   { 'warning' }
                'Danger' { 'danger' }
                'Fail'   { 'failed' }
                default  { '' }
            }
            $rowBadgeClass = switch ($row.Status) {
                'Pass'   { 'badge-open' }
                'Warn'   { 'badge-warning' }
                'Danger' { 'badge-closed' }
                'Fail'   { 'badge-closed' }
                default  { 'badge-drop' }
            }
            $rowSolutionKey = if ($headerSolutionMap.ContainsKey([string]$row.Check)) { $headerSolutionMap[[string]$row.Check] } else { [string]$row.Check }
            $rowSolutionText = ''
            if ($row.Status -ne 'Pass' -and $solutionText.ContainsKey($rowSolutionKey)) { $rowSolutionText = $solutionText[$rowSolutionKey] }
            $solutionCellHtml = if ($rowSolutionText) { ConvertTo-HtmlSafe $rowSolutionText } else { '—' }
            [void]$webSecTableRows.Append("<tr class='$rowCssClass'><td>$($row.Port)</td><td>$(ConvertTo-HtmlSafe ([string]$row.Check))</td><td><span class='badge $rowBadgeClass'>$(ConvertTo-HtmlSafe ([string]$row.Status))</span></td><td>$(ConvertTo-HtmlSafe ([string]$row.Detail))</td><td>$solutionCellHtml</td></tr>`n")
        }
        $webSecSummaryHtml = ConvertTo-HtmlSafe $webSecSummaryText
        $webSecSection = "<section class='websec-section'><h3>$webSecSectionTitle</h3><div class='websec-summary'>$webSecSummaryHtml</div><table><thead><tr><th>$portHeader</th><th>$checkHeader</th><th>$webSecStatusHeader</th><th>$detailHeader</th><th>$solutionHeader</th></tr></thead><tbody>$($webSecTableRows.ToString())</tbody></table></section>"
    }
    $notes = New-Object Text.StringBuilder
    foreach ($n in $AdvisorNotes) {
        [void]$notes.Append("<div class='advisor-item'>$(ConvertTo-HtmlSafe (ConvertTo-LocalizedReportValue $n))</div>")
    }
    $advisorSectionHtml = ''
    if ($notes.Length -gt 0) {
        $advisorTitle = ConvertTo-LocalizedText 'Önerilen Aksiyonlar ve Sistem Uyarıları'
        $advisorSectionHtml = "<div class='advisor'><h3>$advisorTitle</h3>$($notes.ToString())</div>"
    }
    $localizedAnalysis = ConvertTo-LocalizedReportValue ($analysis.ToString())
    $htmlLanguage = if ($Script:LanguageCode -eq 'tr') { 'tr' } else { 'en' }
    $htmlTitle = if ($Script:LanguageCode -eq 'tr') { 'NetDiag Raporu' } else { 'NetDiag Report' }
    $infographicTitle = ConvertTo-LocalizedText 'Performans Bilgi Grafikleri'
    $networkSummaryTitle = ConvertTo-LocalizedText 'Ağ Kalitesi Özeti'
    $httpSummaryTitle = ConvertTo-LocalizedText 'HTTP Yük Testi Özeti'
    $httpPercentileTitle = ConvertTo-LocalizedText 'HTTP Gecikme Yüzdelikleri'
    $hopJitterTitle = ConvertTo-LocalizedText 'Hop Bazlı Jitter Dağılımı'
    $hopLatencyTitle = ConvertTo-LocalizedText 'Hop Bazlı Ortalama Gecikme'
    $rttScaleTitle = ConvertTo-LocalizedText 'Ağ RTT Dağılımı'
    $httpStatusTitle = ConvertTo-LocalizedText 'HTTP Durum Kodu Dağılımı'
    $httpErrorTitle = ConvertTo-LocalizedText 'HTTP Hata Tipi Dağılımı'
    $httpTimingTitle = ConvertTo-LocalizedText 'HTTP Zamanlama Dağılımı'
    $securityGaugeTitle = ConvertTo-LocalizedText 'Güvenlik Başlığı Puanı'
    $certGaugeTitle = ConvertTo-LocalizedText 'Sertifika Geçerlilik Süresi'
    $notEnoughDataText = ConvertTo-LocalizedText 'Grafik oluşturmak için yeterli veri yok.'

    $infographicHtml = New-Object Text.StringBuilder
    [void]$infographicHtml.Append("<section class='infographic-section'><h3>$infographicTitle</h3>")

    # Network KPI cards
    if ($networkQualityAvailable) {
        $networkCards = @(
            @{ Label=(ConvertTo-LocalizedText 'Ortalama RTT'); Value="$($destinationPingMetrics.Average) ms"; Color='#0078d4' },
            @{ Label=(ConvertTo-LocalizedText 'Hedef p95 RTT'); Value="$($destinationPingMetrics.P95) ms"; Color='#5c2d91' },
            @{ Label=(ConvertTo-LocalizedText 'Ortalama Jitter'); Value="$($destinationPingMetrics.MeanJitter) ms"; Color='#f7630c' },
            @{ Label=(ConvertTo-LocalizedText 'Yanıt Kaybı'); Value="$($destinationPingMetrics.LossPercent)%"; Color='#d13438' }
        )
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$networkSummaryTitle</div><div class='dashboard-grid'>")
        foreach ($card in $networkCards) {
            [void]$infographicHtml.Append("<div class='kpi-card'><div class='kpi-label'>$(ConvertTo-HtmlSafe $card.Label)</div><div class='kpi-value'>$(ConvertTo-HtmlSafe $card.Value)</div><div class='kpi-accent' style='background:$($card.Color)'></div></div>")
        }
        [void]$infographicHtml.Append('</div></div>')

        # Network RTT distribution scale meter
        $rttMinVal = [double]$destinationPingMetrics.Min
        $rttAvgVal = [double]$destinationPingMetrics.Average
        $rttP95Val = [double]$destinationPingMetrics.P95
        $rttSpan = $rttP95Val - $rttMinVal
        if ($rttSpan -lt 1) { $rttSpan = 1 }
        $rttAvgPos = [Math]::Round((($rttAvgVal - $rttMinVal) / $rttSpan) * 100,1)
        $rttP95Pos = [Math]::Round((($rttP95Val - $rttMinVal) / $rttSpan) * 100,1)
        if ($rttAvgPos -lt 0) { $rttAvgPos = 0 }; if ($rttAvgPos -gt 100) { $rttAvgPos = 100 }
        if ($rttP95Pos -lt 0) { $rttP95Pos = 0 }; if ($rttP95Pos -gt 100) { $rttP95Pos = 100 }
        $zoneGoodEnd = [Math]::Round((([Math]::Max(0,50 - $rttMinVal)) / $rttSpan) * 100,1)
        $zoneFairEnd = [Math]::Round((([Math]::Max(0,150 - $rttMinVal)) / $rttSpan) * 100,1)
        if ($zoneGoodEnd -lt 0) { $zoneGoodEnd = 0 }; if ($zoneGoodEnd -gt 100) { $zoneGoodEnd = 100 }
        if ($zoneFairEnd -lt $zoneGoodEnd) { $zoneFairEnd = $zoneGoodEnd }; if ($zoneFairEnd -gt 100) { $zoneFairEnd = 100 }
        $avgRttLabel = ConvertTo-LocalizedText 'Ortalama RTT'
        $p95RttLabel = ConvertTo-LocalizedText 'Hedef p95 RTT'
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$rttScaleTitle</div><div class='scale-track'><div class='scale-zones'><div class='scale-zone scale-good' style='width:$zoneGoodEnd%'></div><div class='scale-zone scale-fair' style='left:$zoneGoodEnd%;width:$([Math]::Round($zoneFairEnd - $zoneGoodEnd,1))%'></div><div class='scale-zone scale-poor' style='left:$zoneFairEnd%;width:$([Math]::Round(100 - $zoneFairEnd,1))%'></div></div><div class='scale-marker scale-marker-avg' style='left:$rttAvgPos%'><span>$(ConvertTo-HtmlSafe $avgRttLabel) $([Math]::Round($rttAvgVal,1)) ms</span></div><div class='scale-marker scale-marker-p95' style='left:$rttP95Pos%'><span>$(ConvertTo-HtmlSafe $p95RttLabel) $([Math]::Round($rttP95Val,1)) ms</span></div></div><div class='scale-labels'><span>$(ConvertTo-LocalizedText 'En Düşük') $([Math]::Round($rttMinVal,1)) ms</span><span>$(ConvertTo-LocalizedText 'En Yüksek') $([Math]::Round($rttP95Val,1)) ms</span></div></div>")
    }

    # HTTP KPI cards and success/failure donut
    if ($appMetricsAvailable -and $ReportData.Contains('JMeter_Total_Requests')) {
        $httpP95Display = if ($null -ne $jmeterP95Val) { "$jmeterP95Val ms" } else { 'N/A' }
        $httpP50Display = if ($null -ne $jmeterP50Val) { "$jmeterP50Val ms" } else { 'N/A' }
        $httpP99Display = if ($null -ne $jmeterP99Val) { "$jmeterP99Val ms" } else { 'N/A' }
        $throughputDisplay = if ($ReportData.JMeter_Throughput_RPS) { [string]$ReportData.JMeter_Throughput_RPS } else { 'N/A' }
        $errorRateDisplay = if ($null -ne $jmeterErrRateVal) { "$jmeterErrRateVal%" } else { 'N/A' }
        $peakDisplay = if ($ReportData.JMeter_Peak_Concurrency) { [string]$ReportData.JMeter_Peak_Concurrency } else { 'N/A' }
        $tailDisplay = if ($null -ne $tailRatio) { "${tailRatio}x" } else { 'N/A' }
        $tailColor = if ($null -ne $tailRatio -and $tailRatio -lt 2) { '#107c10' } elseif ($null -ne $tailRatio -and $tailRatio -lt 3) { '#ffaa44' } else { '#d13438' }
        $httpCards = @(
            @{ Label=(ConvertTo-LocalizedText 'İşlem Hızı'); Value=$throughputDisplay; Color='#107c10' },
            @{ Label=(ConvertTo-LocalizedText 'HTTP p95'); Value=$httpP95Display; Color='#5c2d91' },
            @{ Label=(ConvertTo-LocalizedText 'Hata Oranı'); Value=$errorRateDisplay; Color='#d13438' },
            @{ Label=(ConvertTo-LocalizedText 'Peak Eşzamanlılık'); Value=$peakDisplay; Color='#00b7c3' },
            @{ Label=(ConvertTo-LocalizedText 'p50 Gecikmesi'); Value=$httpP50Display; Color='#2b88d8' },
            @{ Label=(ConvertTo-LocalizedText 'p99 Gecikmesi'); Value=$httpP99Display; Color='#7719aa' }
        )
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$httpSummaryTitle</div><div class='dashboard-grid'>")
        foreach ($card in $httpCards) {
            [void]$infographicHtml.Append("<div class='kpi-card'><div class='kpi-label'>$(ConvertTo-HtmlSafe $card.Label)</div><div class='kpi-value'>$(ConvertTo-HtmlSafe $card.Value)</div><div class='kpi-accent' style='background:$($card.Color)'></div></div>")
        }
        [void]$infographicHtml.Append('</div>')

        $totalRequestCount = [double]$ReportData.JMeter_Total_Requests
        $successfulRequestCount = [double]$ReportData.JMeter_Successful_Requests
        $failedRequestCount = [double]$ReportData.JMeter_Failed_Requests
        $successPercent = if ($totalRequestCount -gt 0) { [Math]::Round(($successfulRequestCount / $totalRequestCount) * 100,1) } else { 0 }
        $failedPercent = [Math]::Round(100 - $successPercent,1)
        [void]$infographicHtml.Append("<div class='donut-wrap'><div class='donut' style='background:conic-gradient(#107c10 0% $successPercent%,#d13438 $successPercent% 100%)'><div class='donut-center'>$successPercent%<br><span style='font-size:11px;font-weight:500'>$(ConvertTo-LocalizedText 'Başarılı İstekler')</span></div></div><div><div class='legend-item'><span class='legend-dot legend-success'></span>$(ConvertTo-LocalizedText 'Başarılı İstekler'): $successfulRequestCount ($successPercent%)</div><div class='legend-item'><span class='legend-dot legend-failed'></span>$(ConvertTo-LocalizedText 'Başarısız İstekler'): $failedRequestCount ($failedPercent%)</div></div></div></div>")

        # Latency spread panel: p50 -> p95 -> p99 horizontal bar with health indicator
        if ($null -ne $jmeterP50Val -and $null -ne $jmeterP99Val -and $jmeterP99Val -gt 0) {
            $spreadTitle = ConvertTo-LocalizedText 'Gecikme Yayılım Analizi'
            $p50Pct = if ($jmeterP99Val -gt 0) { [Math]::Round(($jmeterP50Val / $jmeterP99Val) * 100,1) } else { 50 }
            $p95Pct = if ($jmeterP99Val -gt 0) { [Math]::Round(([double]$jmeterP95Val / $jmeterP99Val) * 100,1) } else { 95 }
            $p95ValForSpread = [double]$jmeterP95Val
            $tailHealth = if ($tailRatio -lt 2) { 'kuyruk-saglikli' } elseif ($tailRatio -lt 3) { 'kuyruk-orta' } else { 'kuyruk-kritik' }
            $tailHealthText = if ($tailRatio -lt 2) { ConvertTo-LocalizedText 'Kuyruk Sağlıklı (<2x)' } elseif ($tailRatio -lt 3) { ConvertTo-LocalizedText 'Kuyruk Orta (2-3x)' } else { ConvertTo-LocalizedText 'Kuyruk Kritik (>3x)' }
            $tailHealthColor = if ($tailRatio -lt 2) { '#107c10' } elseif ($tailRatio -lt 3) { '#ffaa44' } else { '#d13438' }
            $sampleBadge = if ($jmeterSamplesCount -ge 200) { "<span style='color:#107c10;font-weight:600;margin-left:6px'>($jmeterSamplesCount)</span>" } else { "<span style='color:#d13438;font-weight:600;margin-left:6px'>($jmeterSamplesCount)</span>" }
            [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$(ConvertTo-HtmlSafe $spreadTitle) $sampleBadge</div><div class='bar-row'><div class='bar-label'>p50</div><div class='bar-track'><div class='bar-fill bar-fill-good' style='width:$p50Pct%'></div></div><div class='bar-value'>$jmeterP50Val ms</div></div><div class='bar-row'><div class='bar-label'>p95</div><div class='bar-track'><div class='bar-fill bar-fill-fair' style='width:$p95Pct%'></div></div><div class='bar-value'>$p95ValForSpread ms</div></div><div class='bar-row'><div class='bar-label'>p99</div><div class='bar-track'><div class='bar-fill bar-fill-poor' style='width:100%'></div></div><div class='bar-value'>$jmeterP99Val ms</div></div><div style='margin-top:8px;text-align:center'><span class='badge badge-$tailHealth' style='display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;background:$tailHealthColor;color:#fff'>$(ConvertTo-HtmlSafe $tailHealthText) ($tailDisplay)</span></div></div>")
        }

        # HTTP percentile horizontal bars
        $percentileItems = @(
            @{ Label='p50'; Value=$p50 },
            @{ Label='p75'; Value=$p75 },
            @{ Label='p90'; Value=$p90 },
            @{ Label='p95'; Value=$p95 },
            @{ Label='p99'; Value=$p99 }
        ) | Where-Object { $null -ne $_.Value }
        if ($percentileItems.Count -gt 0) {
            $maxPercentileValue = ($percentileItems | ForEach-Object { [double]$_.Value } | Measure-Object -Maximum).Maximum
            [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$httpPercentileTitle</div>")
            foreach ($item in $percentileItems) {
                $barWidth = if ($maxPercentileValue -gt 0) { [Math]::Round(([double]$item.Value / $maxPercentileValue) * 100,1) } else { 0 }
                $barSeverityClass = if ([double]$item.Value -lt 200) { 'bar-fill-good' } elseif ([double]$item.Value -le 1000) { 'bar-fill-fair' } else { 'bar-fill-poor' }
                [void]$infographicHtml.Append("<div class='bar-row'><div class='bar-label'>$($item.Label)</div><div class='bar-track'><div class='bar-fill $barSeverityClass' style='width:$barWidth%'></div></div><div class='bar-value'>$($item.Value) ms</div></div>")
            }
            [void]$infographicHtml.Append('</div>')
        }

        # HTTP status code distribution (stacked bar)
        $statusSegments = New-Object 'System.Collections.Generic.List[object]'
        if ($ReportData.JMeter_Status_Distribution) {
            foreach ($statusMatch in [regex]::Matches([string]$ReportData.JMeter_Status_Distribution,'HTTP\s+(\d{3}):\s*(\d+)')) {
                $statusCode = $statusMatch.Groups[1].Value
                $statusCount = [int]$statusMatch.Groups[2].Value
                $statusColor = if ($statusCode -match '^2') { '#107c10' } elseif ($statusCode -match '^3') { '#0078d4' } elseif ($statusCode -match '^4') { '#f7630c' } else { '#d13438' }
                $statusSegments.Add(@{ Code=$statusCode; Count=$statusCount; Color=$statusColor }) | Out-Null
            }
        }
        if ($statusSegments.Count -gt 0 -and $totalRequestCount -gt 0) {
            $statusHtml = "<div class='chart-panel'><div class='chart-title'>$httpStatusTitle</div><div class='stack-bar'>"
            $statusLegend = "<div class='legend-list'>"
            foreach ($statusItem in ($statusSegments | Sort-Object { [int]$_.Code })) {
                $segPct = [Math]::Round(($statusItem.Count / $totalRequestCount) * 100,1)
                $statusHtml += "<div class='stack-seg' style='background:$($statusItem.Color);width:$segPct%' title='HTTP $($statusItem.Code): $($statusItem.Count)'></div>"
                $statusLegend += "<div class='legend-item'><span class='legend-dot' style='background:$($statusItem.Color)'></span>HTTP $($statusItem.Code): $($statusItem.Count) ($segPct%)</div>"
            }
            $statusHtml += '</div>'
            $statusLegend += '</div>'
            [void]$infographicHtml.Append($statusHtml + $statusLegend + '</div>')
        }

        # HTTP error type distribution (stacked bar)
        $errorSegments = New-Object 'System.Collections.Generic.List[object]'
        if ($ReportData.JMeter_Error_Distribution -and $failedRequestCount -gt 0) {
            foreach ($errMatch in [regex]::Matches([string]$ReportData.JMeter_Error_Distribution,'([^:]+):\s*(\d+)')) {
                $errName = $errMatch.Groups[1].Value.Trim()
                $errCount = [int]$errMatch.Groups[2].Value
                $errColor = '#8a2be2'
                if ($errName -match 'Timeout') { $errColor = '#d13438' }
                elseif ($errName -match 'HttpStatus|HTTP') { $errColor = '#f7630c' }
                elseif ($errName -match 'Assert') { $errColor = '#c50f1f' }
                $errorSegments.Add(@{ Name=$errName; Count=$errCount; Color=$errColor }) | Out-Null
            }
        }
        if ($errorSegments.Count -gt 0) {
            $errorHtml = "<div class='chart-panel'><div class='chart-title'>$httpErrorTitle</div><div class='stack-bar'>"
            $errorLegend = "<div class='legend-list'>"
            foreach ($errItem in ($errorSegments | Sort-Object { $_.Count } -Descending)) {
                $errPct = [Math]::Round(($errItem.Count / [double]$failedRequestCount) * 100,1)
                $errorHtml += "<div class='stack-seg' style='background:$($errItem.Color);width:$errPct%' title='$(ConvertTo-HtmlSafe $errItem.Name): $($errItem.Count)'></div>"
                $errorLegend += "<div class='legend-item'><span class='legend-dot' style='background:$($errItem.Color)'></span>$(ConvertTo-HtmlSafe $errItem.Name): $($errItem.Count) ($errPct%)</div>"
            }
            $errorHtml += '</div>'
            $errorLegend += '</div>'
            [void]$infographicHtml.Append($errorHtml + $errorLegend + '</div>')
        }

        # HTTP timing breakdown: header (TTFB) vs download + optimization analysis
        $avgHeaderMs = 0.0; $avgDownloadMs = 0.0
        $headerTimeMatch = [regex]::Match([string]$ReportData.JMeter_Avg_Header_Time,'[0-9]+(?:[\.,][0-9]+)?')
        if ($headerTimeMatch.Success) {
            [double]::TryParse(($headerTimeMatch.Value -replace ',','.'),[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$avgHeaderMs) | Out-Null
        }
        $downloadTimeMatch = [regex]::Match([string]$ReportData.JMeter_Avg_Download_Time,'[0-9]+(?:[\.,][0-9]+)?')
        if ($downloadTimeMatch.Success) {
            [double]::TryParse(($downloadTimeMatch.Value -replace ',','.'),[Globalization.NumberStyles]::Any,[Globalization.CultureInfo]::InvariantCulture,[ref]$avgDownloadMs) | Out-Null
        }
        $totalTimingMs = $avgHeaderMs + $avgDownloadMs
        if ($totalTimingMs -gt 0) {
            $headerPct = [Math]::Round(($avgHeaderMs / $totalTimingMs) * 100,1)
            $downloadPct = [Math]::Round(($avgDownloadMs / $totalTimingMs) * 100,1)
            $timingHtml = "<div class='chart-panel'><div class='chart-title'>$httpTimingTitle</div><div class='stack-bar'><div class='stack-seg' style='background:#0078d4;width:$headerPct%'></div><div class='stack-seg' style='background:#00b7c3;width:$downloadPct%'></div></div><div class='legend-list'><div class='legend-item'><span class='legend-dot' style='background:#0078d4'></span>$(ConvertTo-LocalizedText 'Header / TTFB'): $([Math]::Round($avgHeaderMs,1)) ms ($headerPct%)</div><div class='legend-item'><span class='legend-dot' style='background:#00b7c3'></span>$(ConvertTo-LocalizedText 'İndirme'): $([Math]::Round($avgDownloadMs,1)) ms ($downloadPct%)</div></div>"

            # TTFB ratio analysis
            $ttfbRatioClass = if ($headerPct -gt 70) { 'badge-closed' } elseif ($headerPct -gt 50) { 'badge-warning' } else { 'badge-open' }
            $ttfbRatioLabel = if ($headerPct -gt 70) { ConvertTo-LocalizedText 'Kritik' } elseif ($headerPct -gt 50) { ConvertTo-LocalizedText 'Orta' } else { ConvertTo-LocalizedText 'İyi' }
            $timingHtml += "<div style='margin-top:12px;padding:10px 14px;background:#f8fafc;border:1px solid #e1e4e8;border-radius:8px'>"
            $timingHtml += "<div style='font-weight:700;font-size:13px;color:#005a9e;margin-bottom:8px'>$(ConvertTo-LocalizedText 'Zamanlama Analizi')</div>"
            $timingHtml += "<div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px'>"
            $timingHtml += "<div><span style='color:#5f6368;font-weight:600'>$(ConvertTo-LocalizedText 'TTFB Oranı'):</span> <span class='badge $ttfbRatioClass' style='font-size:11px'>$headerPct% - $ttfbRatioLabel</span></div>"
            $timingHtml += "<div><span style='color:#5f6368;font-weight:600'>$(ConvertTo-LocalizedText 'Yanıt Boyutu'):</span> $avgBytes Byte</div>"

            # Throughput efficiency
            if ($avgDownloadMs -gt 0 -and $avgBytes -gt 0) {
                $bytesPerMs = [Math]::Round($avgBytes / $avgDownloadMs, 1)
                $throughputLabel = if ($bytesPerMs -gt 50) { ConvertTo-LocalizedText 'İyi' } elseif ($bytesPerMs -gt 10) { ConvertTo-LocalizedText 'Orta' } else { ConvertTo-LocalizedText 'Kritik' }
                $throughputClass = if ($bytesPerMs -gt 50) { 'badge-open' } elseif ($bytesPerMs -gt 10) { 'badge-warning' } else { 'badge-closed' }
                $timingHtml += "<div><span style='color:#5f6368;font-weight:600'>$(ConvertTo-LocalizedText 'İndirme Verimliliği'):</span> <span class='badge $throughputClass' style='font-size:11px'>$bytesPerMs Byte/ms - $throughputLabel</span></div>"
            }

            # TTFB p99 spread indicator
            if ($null -ne $ttfbSpread -and $ttfbSpread -gt 0) {
                $ttfbSpreadClass = if ($ttfbSpread -gt 200) { 'badge-closed' } elseif ($ttfbSpread -gt 100) { 'badge-warning' } else { 'badge-open' }
                $ttfbSpreadLabel = if ($ttfbSpread -gt 200) { ConvertTo-LocalizedText 'Kritik' } elseif ($ttfbSpread -gt 100) { ConvertTo-LocalizedText 'Orta' } else { ConvertTo-LocalizedText 'İyi' }
                $timingHtml += "<div><span style='color:#5f6368;font-weight:600'>$(ConvertTo-LocalizedText 'TTFB Yayılımı'):</span> <span class='badge $ttfbSpreadClass' style='font-size:11px'>$ttfbSpread ms - $ttfbSpreadLabel</span></div>"
            }
            $timingHtml += "</div>"

            # Optimization suggestions
            $isTr = ($Script:LanguageCode -eq 'tr')
            $suggestions = @()
            if ($headerPct -gt 70) {
                $suggestions += if ($isTr) {
                    "Sunucu taraflı optimizasyon gerekli: TTFB toplam sürenin %$headerPct'i oluşturuyor. CDN, önbellekleme veya veritabanı sorgusu optimizasyonu düşünün."
                } else {
                    "Server-side optimization needed: TTFB accounts for $headerPct% of total time. Consider CDN, caching, or database query optimization."
                }
            } elseif ($headerPct -gt 50) {
                $suggestions += if ($isTr) {
                    "TTFB yüksek: Sunucu işlem süresi içerik aktarımından uzun. Backend optimizasyonu veya caching katmanı ekleyin."
                } else {
                    "High TTFB: Server processing time exceeds content transfer. Add backend optimization or caching layer."
                }
            }
            if ($downloadPct -gt 50) {
                $suggestions += if ($isTr) {
                    "İçerik optimizasyonu gerekli: Yanıt indirme süresi toplam sürenin %$downloadPct'sini oluşturuyor. gzip/brotli sıkıştırma, görüntü optimizasyonu veya CDN kullanın."
                } else {
                    "Content optimization needed: Download time accounts for $downloadPct% of total time. Use gzip/brotli compression, image optimization, or CDN."
                }
            }
            if ($avgBytes -gt 500000) {
                $kb = [Math]::Round($avgBytes/1024,1)
                $suggestions += if ($isTr) {
                    "Büyük yanıt boyutu: Ortalama $kb KB. Sıkıştırma, lazy loading veya varlık küçültme düşünün."
                } else {
                    "Large response size: Average $kb KB. Consider compression, lazy loading, or asset minification."
                }
            }
            if ($null -ne $ttfbSpread -and $ttfbSpread -gt 200) {
                $suggestions += if ($isTr) {
                    "TTFB değişkenliği yüksek: p50-p99 farkı $ttfbSpread ms. Backend servislerde kuyruk, lock contention veya GC duraklamaları araştırın."
                } else {
                    "High TTFB variability: p50-p99 spread is $ttfbSpread ms. Investigate backend queuing, lock contention, or GC pauses."
                }
            }
            if ($null -ne $tailRatio -and $tailRatio -ge 3) {
                $suggestions += if ($isTr) {
                    "Kuyruk latency sorunu: p99/p50 oranı ${tailRatio}x. Bağımlı servisler, bağlantı havuzu veya thread kapasitesi kontrol edin."
                } else {
                    "Tail latency problem: p99/p50 ratio is ${tailRatio}x. Check dependent services, connection pool, or thread capacity."
                }
            }
            if ($suggestions.Count -eq 0) {
                $suggestions += if ($isTr) {
                    "Zamanlama metrikleri sağlıklı görünüyor. Mevcut yapılandırmayı koruyun."
                } else {
                    "Timing metrics appear healthy. Maintain current configuration."
                }
            }
            $timingHtml += "<div style='margin-top:10px;padding:10px 14px;background:#fff8e1;border-left:3px solid #ffc107;border-radius:4px;font-size:12px'>"
            $timingHtml += "<div style='font-weight:700;color:#856404;margin-bottom:6px'>$(ConvertTo-LocalizedText 'Optimizasyon Önerileri')</div>"
            foreach ($s in $suggestions) {
                $timingHtml += "<div style='margin:4px 0;color:#5f6368'>• $(ConvertTo-HtmlSafe $s)</div>"
            }
            $timingHtml += "</div></div>"
            [void]$infographicHtml.Append($timingHtml)
        }
    }

    # Hop jitter distribution
    $jitterItems = @(
        $RouteReportRows |
            Where-Object { $_.Jitter -and $_.Jitter -ne 'N/A' } |
            ForEach-Object {
                $numericJitter = 0.0
                $match = [regex]::Match([string]$_.Jitter,'[0-9]+(?:[\.,][0-9]+)?')
                if ($match.Success) {
                    [double]::TryParse(
                        ($match.Value -replace ',','.'),
                        [Globalization.NumberStyles]::Any,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [ref]$numericJitter
                    ) | Out-Null
                }
                [pscustomobject]@{ Hop=$_.Hop; IP=$_.IP; Value=$numericJitter }
            }
    )
    if ($jitterItems.Count -gt 0) {
        $maxHopJitter = ($jitterItems | Measure-Object Value -Maximum).Maximum
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$hopJitterTitle</div>")
        foreach ($item in $jitterItems) {
            $barWidth = if ($maxHopJitter -gt 0) { [Math]::Round(($item.Value / $maxHopJitter) * 100,1) } else { 0 }
            $hopLabel = "Hop $($item.Hop) · $($item.IP)"
            [void]$infographicHtml.Append("<div class='bar-row'><div class='bar-label' title='$(ConvertTo-HtmlSafe $hopLabel)'>$(ConvertTo-HtmlSafe $hopLabel)</div><div class='bar-track'><div class='bar-fill bar-fill-jitter' style='width:$barWidth%'></div></div><div class='bar-value'>$($item.Value) ms</div></div>")
        }
        [void]$infographicHtml.Append('</div>')
    }

    # Hop average latency distribution
    $hopLatencyItems = @(
        $RouteReportRows |
            Where-Object { $_.Avg -and $_.Avg -ne 'N/A' } |
            ForEach-Object {
                $numericLatency = 0.0
                $match = [regex]::Match([string]$_.Avg,'[0-9]+(?:[\.,][0-9]+)?')
                if ($match.Success) {
                    [double]::TryParse(
                        ($match.Value -replace ',','.'),
                        [Globalization.NumberStyles]::Any,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [ref]$numericLatency
                    ) | Out-Null
                }
                [pscustomobject]@{ Hop=$_.Hop; IP=$_.IP; Value=$numericLatency }
            }
    )
    if ($hopLatencyItems.Count -gt 0) {
        $maxHopLatency = ($hopLatencyItems | Measure-Object Value -Maximum).Maximum
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$hopLatencyTitle</div>")
        foreach ($item in $hopLatencyItems) {
            $barWidth = if ($maxHopLatency -gt 0) { [Math]::Round(($item.Value / $maxHopLatency) * 100,1) } else { 0 }
            $hopLabel = "Hop $($item.Hop) · $($item.IP)"
            [void]$infographicHtml.Append("<div class='bar-row'><div class='bar-label' title='$(ConvertTo-HtmlSafe $hopLabel)'>$(ConvertTo-HtmlSafe $hopLabel)</div><div class='bar-track'><div class='bar-fill' style='width:$barWidth%'></div></div><div class='bar-value'>$($item.Value) ms</div></div>")
        }
        [void]$infographicHtml.Append('</div>')
    }

    # Security header score gauge
    $secScoreMatch = [regex]::Match([string]$ReportData.Security_Header_Score,'(\d+)/(\d+)')
    if ($secScoreMatch.Success) {
        $secPass = [int]$secScoreMatch.Groups[1].Value
        $secTotal = [int]$secScoreMatch.Groups[2].Value
        if ($secTotal -gt 0) {
            $secPct = [Math]::Round(($secPass / [double]$secTotal) * 100,1)
            $secColor = if ($secPct -ge 75) { '#107c10' } elseif ($secPct -gt 0) { '#f7630c' } else { '#d13438' }
            $secDetailHtml = ''
            if (-not [string]::IsNullOrWhiteSpace([string]$ReportData.Security_Headers)) {
                $secBadges = [regex]::Matches([string]$ReportData.Security_Headers, "<span class='badge\s+(badge-open|badge-warning|badge-closed)'>([^<]+)</span>")
                if ($secBadges.Count -gt 0) {
                    $secDetailHtml = '<div style="margin-top:12px;font-size:12px;color:#475467">'
                    foreach ($sb in $secBadges) {
                        $sbClass = $sb.Groups[1].Value
                        $sbText = [regex]::Replace($sb.Groups[2].Value, '<[^>]+>', '')
                        $sbIcon = if ($sbClass -eq 'badge-open') { '&#10003;' } elseif ($sbClass -eq 'badge-warning') { '&#9888;' } else { '&#10007;' }
                        $sbColor = if ($sbClass -eq 'badge-open') { '#107c10' } elseif ($sbClass -eq 'badge-warning') { '#f7630c' } else { '#d13438' }
                        $secDetailHtml += "<div style='margin:3px 0'><span style='color:$sbColor;font-weight:600'>$sbIcon</span> $(ConvertTo-HtmlSafe $sbText)</div>"
                    }
                    $secDetailHtml += '</div>'
                }
            }
            [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$securityGaugeTitle</div><div class='gauge-wrap'><div class='gauge' style='background:conic-gradient($secColor 0% $secPct%,#edf2f7 $secPct% 100%)'><div class='gauge-center'>$secPass/$secTotal<br><span style='font-size:11px;font-weight:500'>$secPct%</span></div></div><div class='legend-list'><div class='legend-item'><span class='legend-dot' style='background:$secColor'></span>$secPass/$secTotal $(ConvertTo-LocalizedText 'Pass')</div>$secDetailHtml</div></div></div>")
        }
    }

    # Certificate validity gauge
        $certNotBefore = $null; $certNotAfter = $null
        if ($ReportData.HTTPS_Certificate_NotBefore -and $ReportData.HTTPS_Certificate_NotAfter) {
            try { $certNotBefore = [datetime]::ParseExact([string]$ReportData.HTTPS_Certificate_NotBefore,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) } catch { $certNotBefore = $null }
            try { $certNotAfter = [datetime]::ParseExact([string]$ReportData.HTTPS_Certificate_NotAfter,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture) } catch { $certNotAfter = $null }
        }
    if ($null -ne $certNotBefore -and $null -ne $certNotAfter -and $certNotAfter -gt $certNotBefore) {
        $certTotalDays = [Math]::Max(1,($certNotAfter - $certNotBefore).TotalDays)
        $certRemainingDays = [Math]::Max(0,[Math]::Round(($certNotAfter - (Get-Date)).TotalDays))
        $certRemainingPct = [Math]::Round(([Math]::Max(0,($certNotAfter - (Get-Date)).TotalDays) / $certTotalDays) * 100,1)
        if ($certRemainingPct -gt 100) { $certRemainingPct = 100 }
        $certColor = if ($certRemainingPct -gt 30) { '#107c10' } elseif ($certRemainingPct -gt 10) { '#f7630c' } else { '#d13438' }
        $certIssuer = if (-not [string]::IsNullOrWhiteSpace([string]$ReportData.SSL_Issuer)) { [string]$ReportData.SSL_Issuer } else { 'N/A' }
        $certValidWindow = if (-not [string]::IsNullOrWhiteSpace([string]$ReportData.HTTPS_Cert_Valid)) { ConvertTo-LocalizedText ([string]$ReportData.HTTPS_Cert_Valid) } else { 'N/A' }
        $certSignature = if (-not [string]::IsNullOrWhiteSpace([string]$ReportData.HTTPS_Cert_Signature)) { [string]$ReportData.HTTPS_Cert_Signature } else { 'N/A' }
        $certNotBeforeStr = if ($null -ne $certNotBefore) { $certNotBefore.ToString('yyyy-MM-dd') } else { 'N/A' }
        $certNotAfterStr = if ($null -ne $certNotAfter) { $certNotAfter.ToString('yyyy-MM-dd') } else { 'N/A' }
        $certDetailHtml = "<div style='margin-top:12px;font-size:12px;color:#475467'>"
        $certDetailHtml += "<div><span style='font-weight:600'>$(ConvertTo-LocalizedText 'Yayıncı'):</span> $(ConvertTo-HtmlSafe $certIssuer)</div>"
        $certDetailHtml += "<div><span style='font-weight:600'>$(ConvertTo-LocalizedText 'Geçerlilik'):</span> $(ConvertTo-HtmlSafe $certNotBeforeStr) &rarr; $(ConvertTo-HtmlSafe $certNotAfterStr)</div>"
        $certDetailHtml += "<div><span style='font-weight:600'>$(ConvertTo-LocalizedText 'Durum'):</span> $(ConvertTo-HtmlSafe $certValidWindow)</div>"
        $certDetailHtml += "<div><span style='font-weight:600'>$(ConvertTo-LocalizedText 'İmza'):</span> $(ConvertTo-HtmlSafe $certSignature)</div>"
        $certDetailHtml += '</div>'
        [void]$infographicHtml.Append("<div class='chart-panel'><div class='chart-title'>$certGaugeTitle</div><div class='gauge-wrap'><div class='gauge' style='background:conic-gradient($certColor 0% $certRemainingPct%,#edf2f7 $certRemainingPct% 100%)'><div class='gauge-center'>$([Math]::Round($certRemainingDays,0))<br><span style='font-size:11px;font-weight:500'>$(ConvertTo-LocalizedText 'Gün')</span></div></div><div class='legend-list'><div class='legend-item'><span class='legend-dot' style='background:$certColor'></span>$certRemainingPct% $(ConvertTo-LocalizedText 'Sertifika Geçerlilik Süresi')</div>$certDetailHtml</div></div></div>")
    }

    if ((-not $networkQualityAvailable) -and (-not $appMetricsAvailable) -and $jitterItems.Count -eq 0) {
        [void]$infographicHtml.Append("<div class='chart-panel chart-note'>$notEnoughDataText</div>")
    }
    [void]$infographicHtml.Append('</section>')

    $footerGeneratedText = ConvertTo-LocalizedText 'Bu rapor NetDiag sürümü tarafından oluşturuldu.'
    $footerProjectText = ConvertTo-LocalizedText 'Açık kaynak kodu, güncellemeleri ve proje ayrıntılarını GitHub üzerinde görüntüleyin.'
    $footerLinkText = ConvertTo-LocalizedText 'NetDiag GitHub Projesi'
    $footerVersion = ConvertTo-HtmlSafe $CurrentCommit
    $footerProjectUrl = ConvertTo-HtmlSafe $GitHubProjectUrl

    $privacyTitle = ConvertTo-LocalizedText 'Gizlilik ve Veri İşleme Bilgilendirmesi'
    $privacyLead = ConvertTo-LocalizedText 'NetDiag geliştiricisine tanılama verisi gönderilmez'
    $privacyLocal = ConvertTo-LocalizedText 'NetDiag, tanılama sonuçlarını bir NetDiag sunucusuna, merkezi veri tabanına veya geliştiriciye göndermez.'
    $privacyReport = ConvertTo-LocalizedText 'Tanılama verileri yerel cihazda, çalıştırma sırasında işlenir; HTML raporu yalnızca kullanıcı seçerse yerel dosya olarak oluşturulur.'
    $privacyContents = ConvertTo-LocalizedText 'Rapor; kullanıcı adı, bilgisayar adı, yerel IP adresi, hedef adres, sistem envanteri ve ağ ölçümleri içerebilir. Raporun saklanması, paylaşılması ve erişim güvenliği kullanıcı veya raporu çalıştıran kuruluşun sorumluluğundadır.'
    $privacyConnections = ConvertTo-LocalizedText 'Güncelleme kontrolü GitHub ile, DNS karşılaştırmaları yapılandırılmış genel DNS çözücülerle ve tanılama testleri seçilen hedef sistemle ağ iletişimi kurabilir. Tanılama sonuçları bu hizmetlere analitik amaçla gönderilmez.'
    $privacyGeoIp = ConvertTo-LocalizedText 'GeoIP/ASN zenginleştirmesi, hedef ve yol üzerindeki IP adreslerinin konum ve ağ sahipliği bilgilerini almak için üçüncü taraf ip-api.com servisini kullanır; bu IP adresleri yalnızca bu amaçla gönderilir ve daha sonra kullanılmak üzere saklanmaz.'
    $privacyGeoIpHtml = if ($geoIpNotice) { "<p>$privacyGeoIp</p>" } else { '' }
    $privacyAnalytics = ConvertTo-LocalizedText 'NetDiag çerez, reklam kimliği veya kullanım analitiği kullanmaz; kalıcı bir kullanıcı profili oluşturmaz.'
    $privacyDisclaimer = ConvertTo-LocalizedText 'Bu bilgilendirme hukuki danışmanlık değildir. NetDiag bir kuruluş adına çalıştırılıyorsa rapor içeriği ve kullanım biçimi için GDPR, KVKK ve kurum politikaları kapsamındaki yükümlülükler ayrıca değerlendirilmelidir.'
    $gdprLinkText = ConvertTo-LocalizedText 'AB GDPR veri koruma ilkeleri'
    $kvkkLinkText = ConvertTo-LocalizedText 'KVKK aydınlatma yükümlülüğü'
    $gdprInformationUrlSafe = ConvertTo-HtmlSafe $GdprInformationUrl
    $kvkkInformationUrlSafe = ConvertTo-HtmlSafe $KvkkInformationUrl

    # Collapsed by default. It is available to readers without occupying normal report space.
    $privacyDisclosureHtml = @"
<details class='privacy-details'>
    <summary>$privacyTitle</summary>
    <div class='privacy-content'>
        <p><strong>$privacyLead</strong></p>
        <p>$privacyLocal</p>
        <p>$privacyReport</p>
        <p>$privacyContents</p>
        <p>$privacyConnections</p>
        $privacyGeoIpHtml
        <p>$privacyAnalytics</p>
        <p>$privacyDisclaimer</p>
        <div class='privacy-links'>
            <a href='$gdprInformationUrlSafe' target='_blank' rel='noopener noreferrer'>$gdprLinkText</a>
            <a href='$kvkkInformationUrlSafe' target='_blank' rel='noopener noreferrer'>$kvkkLinkText</a>
        </div>
    </div>
</details>
"@

    $footerHtml = @"
<footer class='report-footer'>
    <div><span class='footer-brand'>NetDiag $footerVersion</span> · $footerGeneratedText</div>
    <div>$footerProjectText</div>
    <div><a href='$footerProjectUrl' target='_blank' rel='noopener noreferrer'>$footerLinkText</a></div>
    $privacyDisclosureHtml
</footer>
"@
    $html=@"
<!doctype html><html lang='$htmlLanguage'><head><meta charset='utf-8'><title>$htmlTitle</title><style>body{font-family:Segoe UI,Arial;background:#f0f2f5;padding:25px;color:#333}.container{max-width:1200px;margin:auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 4px 20px #0001}h2{color:#005a9e;border-bottom:2px solid #005a9e;padding-bottom:10px}.subtitle{color:#5f6368;margin:-2px 0 18px 0;font-size:14px}table{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}th,td{padding:10px 14px;border:1px solid #e1e4e8;text-align:left}th{background:#0078d4;color:#fff}.analysis{background:#ebf8ff;border-left:5px solid #0078d4;padding:18px}.advisor{background:#fff8e1;border-left:5px solid #ffc107;padding:15px;margin-top:15px}.advisor-item{margin:6px 0}.websec-section{margin-top:28px}.websec-summary{margin:10px 0 14px 0;padding:12px 16px;background:#f8fafc;border:1px solid #e1e4e8;border-radius:8px;font-size:14px}.metric-group-title{margin-top:26px;font-size:15px;font-weight:700;color:#005a9e;border-bottom:1px solid #e1e4e8;padding-bottom:6px}.metric-group-sub{margin-top:20px;font-size:13px;font-weight:600;color:#005a9e;padding-bottom:4px;border-bottom:1px dashed #d0d7de}.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;margin-top:12px}.metric-item{background:#f8fafc;border:1px solid #e1e4e8;border-radius:8px;padding:10px 14px}.metric-item-wide{grid-column:1/-1}.metric-label{font-size:11px;font-weight:700;color:#5f6368;text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px}.metric-value{font-size:13px;color:#1a2733;word-break:break-word}.badge{padding:4px 9px;border-radius:4px;font-size:12px;font-weight:bold;display:inline-block}.badge-open{background:#d4edda;color:#155724}.badge-closed{background:#f8d7da;color:#721c24}.badge-drop{background:#e2e3e5;color:#383d41}.badge-warning{background:#fff3cd;color:#856404;border:1px solid #ffeeba}.success{background:#e6f4ea}.warning{background:#fef7e0}.danger{background:#fce8e6}.failed{background:#f1f3f4;color:#666}.report-footer{margin-top:28px;padding-top:18px;border-top:1px solid #dfe3e8;color:#5f6368;font-size:13px;line-height:1.6;text-align:center}.report-footer a{color:#0078d4;text-decoration:none;font-weight:600}.report-footer a:hover{text-decoration:underline}.footer-brand{color:#005a9e;font-weight:700}.infographic-section{margin-top:28px}.dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin:14px 0 20px}.kpi-card{background:linear-gradient(145deg,#ffffff,#f6f9fc);border:1px solid #dce6f0;border-radius:10px;padding:15px;box-shadow:0 2px 8px #0000000d}.kpi-label{font-size:12px;color:#667085;text-transform:uppercase;letter-spacing:.35px}.kpi-value{font-size:25px;font-weight:700;color:#12344d;margin-top:6px}.kpi-accent{height:4px;border-radius:4px;background:#0078d4;margin-top:12px}.chart-panel{background:#fff;border:1px solid #dce6f0;border-radius:10px;padding:16px;margin:14px 0;box-shadow:0 2px 8px #0000000d}.chart-title{font-size:16px;font-weight:700;color:#12344d;margin-bottom:14px}.bar-row{display:grid;grid-template-columns:minmax(92px,145px) 1fr minmax(68px,95px);gap:10px;align-items:center;margin:9px 0}.bar-label{font-size:12px;color:#475467;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bar-track{height:13px;background:#edf2f7;border-radius:7px;overflow:hidden}.bar-fill{height:100%;min-width:2px;border-radius:7px;background:linear-gradient(90deg,#0078d4,#35a7ff)}.bar-fill-jitter{background:linear-gradient(90deg,#ffb900,#f7630c)}.bar-value{font-size:12px;font-weight:600;color:#344054;text-align:right}.donut-wrap{display:flex;gap:22px;align-items:center;flex-wrap:wrap}.donut{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;position:relative}.donut:after{content:'';width:82px;height:82px;background:#fff;border-radius:50%;position:absolute}.donut-center{position:relative;z-index:1;text-align:center;font-weight:700;color:#12344d}.legend-item{display:flex;align-items:center;gap:8px;margin:8px 0;color:#475467;font-size:13px}.legend-dot{width:11px;height:11px;border-radius:50%;display:inline-block}.legend-success{background:#107c10}.legend-failed{background:#d13438}.scale-track{position:relative;height:22px;margin:30px 0 4px}.scale-zones{position:absolute;top:0;left:0;right:0;height:22px;border-radius:11px;overflow:hidden;background:#edf2f7}.scale-zone{position:absolute;top:0;bottom:0;height:100%}.scale-good{background:#107c10;opacity:.25}.scale-fair{background:#f7630c;opacity:.3}.scale-poor{background:#d13438;opacity:.32}.scale-marker{position:absolute;top:-22px;transform:translateX(-50%)}.scale-marker span{font-size:11px;font-weight:600;color:#344054;background:#fff;border:1px solid #dce6f0;border-radius:6px;padding:2px 6px;white-space:nowrap}.scale-marker:after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);width:2px;height:22px;background:#344054;opacity:.6}.scale-marker-avg:after{background:#0078d4;width:3px;opacity:.9}.scale-marker-p95:after{background:#d13438;width:3px;opacity:.9}.scale-labels{display:flex;justify-content:space-between;color:#667085;font-size:12px;margin-top:2px}.stack-bar{display:flex;height:26px;border-radius:7px;overflow:hidden;background:#edf2f7;margin:6px 0 12px}.stack-seg{height:100%;min-width:2px}.legend-list{margin-top:4px}.gauge-wrap{display:flex;gap:22px;align-items:center;flex-wrap:wrap}.gauge{width:132px;height:132px;border-radius:50%;display:grid;place-items:center;position:relative}.gauge:after{content:'';width:82px;height:82px;background:#fff;border-radius:50%;position:absolute}.gauge-center{position:relative;z-index:1;text-align:center;font-weight:700;color:#12344d}.bar-fill-good{background:linear-gradient(90deg,#107c10,#4ca84c)}.bar-fill-fair{background:linear-gradient(90deg,#f7630c,#ffb900)}.bar-fill-poor{background:linear-gradient(90deg,#d13438,#e2574c)}.chart-note{color:#667085;font-size:13px;font-style:italic}.privacy-details{margin:16px auto 0;max-width:920px;text-align:left;border:1px solid #dfe3e8;border-radius:8px;background:#f8fafc}.privacy-details summary{cursor:pointer;padding:10px 13px;color:#475467;font-weight:600;list-style-position:inside}.privacy-details[open] summary{border-bottom:1px solid #dfe3e8}.privacy-content{padding:12px 15px;color:#475467;font-size:12px;line-height:1.65}.privacy-content p{margin:7px 0}.privacy-content strong{color:#12344d}.privacy-links{margin-top:10px}.privacy-links a{margin-right:14px}</style></head><body><div class='container'><h2>$(ConvertTo-LocalizedText 'NetDiag Ağ, Sistem ve Uygulama Teşhis Raporu')</h2><div class='subtitle'>$(ConvertTo-LocalizedText 'Hedef'): $(ConvertTo-HtmlSafe $Target) | Port: $Port | $(ConvertTo-LocalizedText 'Tarama'): $(ConvertTo-HtmlSafe $ScanLevel)</div><div class='analysis'>$localizedAnalysis</div>$advisorSectionHtml<h3>$(ConvertTo-LocalizedText 'Genel Sistem, Ağ ve Uygulama Metrikleri')</h3>$metricsGridHtml$infographicHtml$routeSection$webSecSection$footerHtml</div></body></html>
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
