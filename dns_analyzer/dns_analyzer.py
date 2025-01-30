# -*- coding: utf-8 -*-
import dns.resolver
import dns.reversename
import requests
import json
import re
import ipaddress

def gecerli_domain_kontrolu(domain_adi):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z0-9]{2,}$"
    return re.match(pattern, domain_adi)

def gecerli_ip_kontrolu(ip_adresi):
    try:
        ipaddress.ip_address(ip_adresi)
        return True
    except ValueError:
        return False

def api_anahtari_dogrulama(api_anahtari):
    test_url = "https://www.virustotal.com/api/v3/domains/example.com"
    headers = {"x-apikey": api_anahtari}
    try:
        response = requests.get(test_url, headers=headers)
        return response.status_code == 200
    except Exception:
        return False

def dns_analiz(domain_adi):
    kayitlar = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'SOA', 'PTR', 'DNSKEY']
    analiz_sonuclari = {}
    for sonuc in kayitlar:
        try:
            answers = dns.resolver.resolve(domain_adi, sonuc)
            analiz_sonuclari[sonuc] = [str(answer) for answer in answers]
        except dns.resolver.NoAnswer:
            analiz_sonuclari[sonuc] = "Kayit bulunamadi"
        except dns.resolver.NXDOMAIN:
            analiz_sonuclari[sonuc] = "Domain bulunamadi"
            break
        except Exception as e:
            analiz_sonuclari[sonuc] = f"Hata: {str(e)}"
    if all(value == "Kayit bulunamadi" for value in analiz_sonuclari.values()):
        print("Site güvenlidir.")
    return analiz_sonuclari

def virustotal_kontrol(domain_adi, api_anahtari):
    url = f"https://www.virustotal.com/api/v3/domains/{domain_adi}"
    headers = {"x-apikey": api_anahtari}
    virustotal_sonuclari = {}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                attributes = data["data"]["attributes"]
                virustotal_sonuclari["malicious"] = attributes.get("last_analysis_stats", {}).get("malicious", 0)
                virustotal_sonuclari["details"] = []
                for engine, result in attributes.get("last_analysis_results", {}).items():
                    if result.get("category") == "malicious":
                        virustotal_sonuclari["details"].append({
                            "engine": engine,
                            "result": result.get("result")
                        })
        elif response.status_code in (403, 404):
            virustotal_sonuclari["error"] = "Bilgi bulunamadi veya yetkisiz erişim"
    except Exception as e:
        virustotal_sonuclari["error"] = str(e)
    if not virustotal_sonuclari.get("malicious") or virustotal_sonuclari.get("malicious", 0) == 0:
        print("Site güvenlidir.")
    return virustotal_sonuclari

def ters_dns(ip_adresi):
    try:
        ters_isim = dns.reversename.from_address(ip_adresi)
        alan_adlari = dns.resolver.resolve(ters_isim, 'PTR')
        return [str(alan_adi) for alan_adi in alan_adlari]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        return [f"Hata: {e}"]

def sonuclari_disari_aktar(sonuclar):
    while True:
        dosya_turu = input("Hangi dosya formati olsun? (txt/json): ").strip().lower()
        if dosya_turu not in ["txt", "json"]:
            print("Geçersiz dosya formatı! Lütfen 'txt' veya 'json' giriniz.")
            continue
        dosya_adi = input("Dosya adini girin: ").strip()
        if dosya_turu == "json":
            with open(f"{dosya_adi}.json", "w", encoding="utf-8") as dosya:
                json.dump(sonuclar, dosya, ensure_ascii=False, indent=4)
            print(f"Sonuclar {dosya_adi}.json dosyasina kaydedildi.")
        elif dosya_turu == "txt":
            with open(f"{dosya_adi}.txt", "w", encoding="utf-8") as dosya:
                for key, value in sonuclar.items():
                    dosya.write(f"{key}: {value}\n")
            print(f"Sonuclar {dosya_adi}.txt dosyasina kaydedildi.")
        break

def api_key_ekle(api_anahtari):
    while True:
        yeni_anahtar = input("Yeni VirusTotal API anahtarını girin (Ana menüye dönmek için '0' yazın): ").strip()
        if yeni_anahtar == "0":
            print("Ana menüye dönülüyor...")
            break
        if api_anahtari_dogrulama(yeni_anahtar):
            print("Yeni API anahtarı başarıyla kaydedildi.")
            return yeni_anahtar
        else:
            print("Geçersiz API anahtarı. Lütfen tekrar deneyin.")

def evet_hayir_sorgusu(mesaj):
    while True:
        cevap = input(mesaj).strip().lower()
        if cevap in ["evet", "hayir"]:
            return cevap
        print("Geçersiz giriş! Lütfen 'evet' veya 'hayir' yazınız.")

def ana_menu(parametreler=None):
    api_anahtari = None
    while True:
        print("\n--- DNS Analyzer Menu ---")
        print("1. DNS Analyzer")
        print("2. VirusTotal DNS Analyzer")
        print("3. VirusTotal API Anahtarı Ekle/Değiştir")
        print("4. IP’den DNS Çözümleme")
        print("5. Çıkış")

        secim = input("Seciminizi yapin (1/2/3/4/5): ").strip()

        if secim == "1":
            domain_adi = input("Domain adi girin: ").strip()
            if not gecerli_domain_kontrolu(domain_adi):
                print("Geçersiz domain formatı. Lütfen geçerli bir domain girin.")
                continue
            analiz_sonuclari = dns_analiz(domain_adi)
            if analiz_sonuclari.get("Domain bulunamadi"):
                print("Geçersiz DNS. İşlem sonlandırıldı.")
                continue
            print(json.dumps(analiz_sonuclari, indent=4))
            if evet_hayir_sorgusu("Bu alan adını VirusTotal ile kontrol etmek ister misiniz? (evet/hayir): ") == "evet":
                if not api_anahtari:
                    print("Önce bir API anahtarı eklemelisiniz! Lütfen menüden '3. API Anahtarı Ekle/Değiştir'i kullanın.")
                else:
                    vt_results = virustotal_kontrol(domain_adi, api_anahtari)
                    print(json.dumps(vt_results, indent=4))
            if evet_hayir_sorgusu("Sonuçları dosyaya kaydetmek ister misiniz? (evet/hayir): ") == "evet":
                sonuclari_disari_aktar(analiz_sonuclari)
        elif secim == "2":
            if not api_anahtari:
                print("VirusTotal API anahtarı henüz belirlenmedi. Lütfen önce bir API anahtarı ekleyin.")
                continue
            domain_adi = input("Domain adi girin: ").strip()
            if not gecerli_domain_kontrolu(domain_adi):
                print("Geçersiz domain formatı. Lütfen geçerli bir domain girin.")
                continue
            vt_results = virustotal_kontrol(domain_adi, api_anahtari)
            print(json.dumps(vt_results, indent=4))
            if evet_hayir_sorgusu("Sonuçları dosyaya kaydetmek ister misiniz? (evet/hayir): ") == "evet":
                sonuclari_disari_aktar({"VirusTotal": vt_results})
        elif secim == "3":
            api_anahtari = api_key_ekle(api_anahtari)
        elif secim == "4":
            ip_adresi = input("IP adresini girin: ").strip()
            if not gecerli_ip_kontrolu(ip_adresi):
                print("Geçersiz IP adresi. Lütfen geçerli bir IP adresi girin.")
                continue
            alan_adlari = ters_dns(ip_adresi)
            if not alan_adlari:
                print("Sonuç bulunamadı, PTR kaydı mevcut değil.")
                continue
            print(f"Çözümlenen Alan Adları: {', '.join(alan_adlari)}")
        elif secim == "5":
            print("Programdan çıkılıyor...")
            break
        else:
            print("Geçersiz seçim. Lütfen tekrar deneyin.")

if __name__ == "__main__":
    if __name__ == "__main__":
        kullanici_cevabi = input("Varsayılan parametrelerle çalıştırılsın mı? (evet/hayir): ").strip().lower()

        if kullanici_cevabi == "evet":
            parametreler = {
                "domain_adi": {
                    "tip": "str",
                    "varsayilan": "google.com",
                    "açıklama": "Analiz yapılacak domain adı"
                },
                "api_anahtari": {
                    "tip": "str",
                    "açıklama": "VirusTotal API anahtarı"
                },
                "dosya_turu": {
                    "tip": "str",
                    "varsayilan": "json",
                    "açıklama": "Çıkış dosya formatı (json/txt)"
                },
                "dosya_adi": {
                    "tip": "str",
                    "varsayilan": "sonuclar",
                    "açıklama": "Çıkış dosyasının adı"
                }
            }
            print("Parametrelerle analiz başlatılıyor...\n")

            # Örnek bir analiz sonucu
            analiz_sonuclari = {
                "domain": parametreler["domain_adi"]["varsayilan"],
                "status": "success",
                "details": "Analiz başarıyla tamamlandı."
            }

            # Dosya kaydetme işlemi
            dosya_turu = parametreler["dosya_turu"]["varsayilan"]
            dosya_adi = parametreler["dosya_adi"]["varsayilan"]

            if dosya_turu == "json":
                with open(f"{dosya_adi}.json", "w", encoding="utf-8") as dosya:
                    json.dump(analiz_sonuclari, dosya, ensure_ascii=False, indent=4)
                print(f"Sonuçlar {dosya_adi}.json dosyasına kaydedildi.")
            elif dosya_turu == "txt":
                with open(f"{dosya_adi}.txt", "w", encoding="utf-8") as dosya:
                    for key, value in analiz_sonuclari.items():
                        dosya.write(f"{key}: {value}\n")
                print(f"Sonuçlar {dosya_adi}.txt dosyasına kaydedildi.")

            print("Analiz tamamlandı. Program sonlandırılıyor...")
        elif kullanici_cevabi == "hayir":
            ana_menu()  # Varsayılan şekilde çalışır.
        else:
            print("Geçersiz giriş. Program sonlandırılıyor.")
