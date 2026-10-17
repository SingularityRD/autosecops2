# Check Point yanıt yürütücüsü (executor)

`core/integrations/checkpoint/executor.py` (W0.60) `block_ip` / `unblock_ip`
eylemlerini Check Point ağ geçidine **istek göndermeden** uygular: AutoSecOps
engelli IP listesini bir besleme olarak sunar, ağ geçidi bu beslemeyi kendi
aralığında çeker ve listeyi kullanan bir "drop" kuralı trafiği keser. Check Point
bu nesneleri (Generic Data Center, R81.20+ Network Feed) **policy install olmadan**
günceller; her engellemede kurulum gerekmez. Dışarıya çağrı olmadığından
internetsiz kurulumda da çalışır.

> Kayıt: `core/response/executors/wiring.py` (`EXECUTOR_SOURCES`). Her eylem onay
> kapısından ve müdahale politikasından geçer. **Deneysel:** Postgres'e karşı
> test edilir, canlı bir Check Point'te doğrulanmadı.

## Besleme

| Yol | Biçim |
|---|---|
| `GET /api/feeds/checkpoint/blocklist` | Generic Data Center JSON (`objects[0].ranges`; nesne kimliği sabit) |
| `GET /api/feeds/checkpoint/blocklist.txt` | Satır başına bir adres (Network Feed düz liste; başka güvenlik duvarlarının IP beslemesi) |

- Kimlik doğrulama: entegrasyonun `feed_token` sırrı; `Authorization: Bearer`,
  `X-Feed-Token` ya da yalnız URL alabilen istemciler için `?token=` (erişim
  logunda maskelenir). Yanlış belirteç 401; entegrasyon kapalıysa ya da belirteç
  yoksa 404.
- Süresi dolan adres beslemeden hemen düşer; süre dolumu taraması eylemi ayrıca
  geri alır.

## Check Point tarafında bir kez

1. SmartConsole → **Objects → New → More → Cloud → Data Center → Generic Data
   Center**: URL `https://<autosecops>/api/feeds/checkpoint/blocklist`, kimlik
   doğrulama olarak özel başlık `Authorization: Bearer <feed_token>` (sürüm
   desteklemiyorsa URL'ye `?token=<feed_token>`), yenileme aralığı (ör. 60 sn).
2. Nesnedeki **AutoSecOps block list** öğesini hem kaynak hem hedef olarak kullanan
   bir **Drop** kuralını izin kurallarının üstüne ekleyin; bir kez **Install
   Policy**.
3. Ağ geçidinin AutoSecOps backend'ine HTTPS ile erişebildiğinden emin olun
   (ingress / güvenlik duvarı kuralı). Backend'in sertifikasına ağ geçidinin
   güvenmesi gerekir.

## Eylemler ve kurallar

| `action_type` | Ne yapar | Geri alma |
|---|---|---|
| `block_ip` | IP'yi listeye ekler (TTL varsayılan 24 saat, en çok 30 gün) | Bu eylem eklediyse çıkarır; `noop` ise `noop` |
| `unblock_ip` | IP'yi listeden çıkarır | Yeniden ekler; önce `block_ip`'in tüm kuralları uygulanır |

Hedef kuralları Palo Alto yürütücüsüyle aynıdır (tek adres; özel/iç adresler yalnız
`allowed_internal_cidrs` içindeyse ve insan onayıyla; `protected_cidrs`).
`verify` listeyi doğrular; ağ geçidinin çekmesini göremez, ileti bunu söyler.
Liste en çok 50 000 adres tutar.

**Tek güvenlik duvarı:** Palo Alto, FortiGate ve Check Point üçü de `block_ip`
sunar; birden fazlası etkinse sıradaki ilk (Palo Alto, FortiGate, Check Point)
kalır, diğerleri çakışma olarak loglanır.
