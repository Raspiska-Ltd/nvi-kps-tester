# KPS Test

Türkiye **Kimlik Paylaşım Sistemi (KPS)** kimlik doğrulama servisini test etmek için komut satırı aracı.

Tam WS-Trust / WS-Security akışını uygular:

1. STS uç noktasından kullanıcı adı/şifre ile SAML token alır
2. Token içindeki proof key kullanılarak KPS sorgusunu HMAC-SHA1 ile imzalar
3. Doğrulama isteğini gönderir ve sonucu raporlar

## Gereksinimler

- Python 3.9+
- pip

## Kurulum

```bash
pip install -r requirements.txt
```

## Kullanım

```bash
python kps_test.py \
  --username <sts_kullanici_adi> \
  --password <sts_sifre> \
  --tc <tc_kimlik_no> \
  --name <ad> \
  --surname <soyad> \
  --birth <GG-AA-YYYY>
```

### Parametreler

| Parametre | Açıklama |
|---|---|
| `--username` | STS servis kullanıcı adı |
| `--password` | STS servis şifresi |
| `--tc` | TC Kimlik No (11 hane) |
| `--name` | Ad (büyük harf önerilir) |
| `--surname` | Soyad (büyük harf önerilir) |
| `--birth` | Doğum tarihi `GG-AA-YYYY` formatında |
| `--sts-url` | STS token servis adresini değiştir |
| `--kps-url` | KPS routing servis adresini değiştir |
| `--verbose` | Her request ve response'u ham olarak ekrana yazdır |

## Varsayılan Servis Adresleri

| Servis | Adres |
|---|---|
| STS (Token) | `https://kimlikdogrulama.nvi.gov.tr/services/issuer.svc/IWSTrust13` |
| KPS (Sorgulama) | `https://kpsv2.nvi.gov.tr/Services/RoutingService.svc` |

### Farklı Ortam veya Proxy Kullanımı

```bash
python kps_test.py \
  --sts-url http://kendi-sts-proxyniz/services/issuer.svc/IWSTrust13 \
  --kps-url http://kendi-kps-proxyniz/Services/RoutingService.svc \
  --username ... --password ... --tc ... --name ... --surname ... --birth ...
```

## Çıktı

Araç, hem STS hem de KPS çağrıları için request body ve response'u ekrana yazdırır. Böylece gönderilen ve alınan veriler kolayca incelenebilir.

Çıkış kodları:
- `0` — kimlik doğrulandı
- `1` — kimlik doğrulanamadı
- `2` — hata (ağ, ayrıştırma vb.)

## Notlar

- TC kimlik numarası `98` veya `99` ile başlayan yabancı uyruklu kişiler `YabanciKisiKutukleri` kaydı üzerinden doğrulanır.
- STS token her çalıştırmada yeniden alınır (çalıştırmalar arası önbellekleme yapılmaz).
- WCF sunucusunun keep-alive header'ından kaynaklanan hataları önlemek için her request'te `Connection: close` header'ı gönderilir.
