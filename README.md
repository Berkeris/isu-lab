# DNS Analyzer

**DNS Analyzer**, DNS sorgularını analiz etmek ve potansiyel güvenlik tehditlerini tespit etmek için geliştirilmiş bir araçtır. Proje, DNS kayıtlarının detaylı analizini sağlar ve IP adreslerinden DNS bilgilerini çözümler. Ayrıca VirusTotal API ile entegre çalışarak kötü niyetli domainleri tespit edebilir.

## Projenin Amacı ve Genel İşleyişi

Bu projenin amacı, DNS sorgularını analiz ederek ağ güvenliğini sağlamak ve DNS tabanlı tehditleri algılamaktır. Proje, aşağıdaki özelliklere sahiptir:
- DNS kayıtlarının detaylı analizi
- IP adreslerinden ters DNS çözümleme
- VirusTotal API kullanarak domain güvenliği kontrolü
- Sonuçların kullanıcı dostu bir formatta kaydedilmesi

## Takım Üyeleri

- Doğukan Kumbasar (2320191026)
- Ömer Berk Eriş (2320191017)

## Kullanılan Kütüphaneler ve Versiyonları

- **dnspython**: DNS sorguları için (>= 2.0)
- **requests**: HTTP istekleri için (>= 2.25)
- **ipaddress**: IP adres doğrulama için (Python dahili modülü)

## Gerekli Araçlar ve Kurulum Gereksinimleri

1. **Python**: 3.9 veya daha yeni bir sürüm
2. **Paket Yöneticisi**: pip
3. **Kütüphane Kurulumu**:
   ```bash
   pip install dnspython requests
   ```

## Zorunlu Çalışma Parametreleri

- **Domain Adı**: Analiz edilecek domain adı (örnek: `example.com`)
- **API Anahtarı**: VirusTotal API kullanımı için gerekli anahtar

## Opsiyonel Parametreler ve Kullanımları

- **Çıktı Türü**: Sonuçların kaydedileceği dosya formatı (`json` veya `txt`)
- **Çıktı Adı**: Kaydedilecek dosyanın adı (varsayılan: `sonuclar.json`)

## Kurulum ve Çalıştırma Talimatları

1. **Gerekli Kütüphaneleri Yükleyin**:
   ```bash
   pip install dnspython requests
   ```

2. **Projeyi Çalıştırın**:
   ```bash
   python dns_analyzer.py
   ```

3. **Menü Seçenekleri**:
   - **1**: DNS kayıtlarını sorgular
   - **2**: VirusTotal API ile domain güvenliğini kontrol eder
   - **3**: VirusTotal API anahtarı ekler
   - **4**: IP adresinden ters DNS çözümleme yapar
   - **5**: Programdan çıkar

4. **Sonuçları Kaydetme**:
   - Varsayılan olarak sonuçlar çalıştırma dizininde kaydedilir.
   - `json` veya `txt` formatında kayıt yapılabilir.
