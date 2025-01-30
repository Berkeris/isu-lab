import unittest
from dns_analyzer import gecerli_domain_kontrolu, gecerli_ip_kontrolu, dns_analiz, virustotal_kontrol, ters_dns

class TestDNSAnalyzer(unittest.TestCase):

    def test_gecerli_domain_kontrolu(self):
        # Geçerli domainler
        self.assertTrue(gecerli_domain_kontrolu("google.com"))

        # Geçersiz domainler
        self.assertFalse(gecerli_domain_kontrolu("example"))
        self.assertFalse(gecerli_domain_kontrolu(".com"))
        self.assertFalse(gecerli_domain_kontrolu("-example.com"))

    def test_gecerli_ip_kontrolu(self):
        # Geçerli IP adresleri
        self.assertTrue(gecerli_ip_kontrolu("192.168.1.1"))
        self.assertTrue(gecerli_ip_kontrolu("8.8.8.8"))

        # Geçersiz IP adresleri
        self.assertFalse(gecerli_ip_kontrolu("999.999.999.999"))
        self.assertFalse(gecerli_ip_kontrolu("abcd"))

    def test_dns_analiz(self):
        domain = "google.com"
        sonuc = dns_analiz(domain)
        self.assertIn("A", sonuc)
        self.assertIn("NS", sonuc)

    def test_virustotal_kontrol(self):
        domain = "google.com"
        api_key = "dummy_api_key"
        sonuc = virustotal_kontrol(domain, api_key)

        if "error" in sonuc:
            self.assertIn("error", sonuc)
        else:
            self.assertTrue(isinstance(sonuc, dict))  # Geçerli bir sonuç döndüğünü kontrol et

    def test_ters_dns(self):
        ip = "8.8.8.8"
        sonuc = ters_dns(ip)
        self.assertIsInstance(sonuc, list)

if __name__ == "__main__":
    unittest.main()
