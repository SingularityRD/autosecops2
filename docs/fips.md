# FIPS 140-3 modu

AutoSecOps, `FIPS_MODE=true` ile yalnızca FIPS 140-3 onaylı algoritmaları kullanan
bir modda çalışır. Bu belge modun ne yaptığını, FIPS etkin bir imajın nasıl
hazırlanacağını ve mevcut bir kurulumun nasıl geçirileceğini anlatır.

## Mod ne yapar

| Alan | Varsayılan (`FIPS_MODE=false`) | `FIPS_MODE=true` |
|---|---|---|
| Başlangıç | denetim yok | OpenSSL 3 FIPS sağlayıcısı hem `hashlib` hem `cryptography` için etkin değilse API, daemon ve worker `configuration error: FIPS_MODE=true but ...` yazıp 78 (`EX_CONFIG`) ile çıkar |
| Yeni parola hash'i | bcrypt | PBKDF2-HMAC-SHA256, 16 bayt tuz, 32 bayt çıktı, `PASSWORD_PBKDF2_ITERATIONS` (varsayılan 600 000) |
| Eski bcrypt hash'leri | doğrulanır | doğrulanır ve doğru parolayla ilk girişte PBKDF2'ye yeniden yazılır; `FIPS_LEGACY_BCRYPT_VERIFY=false` ile tamamen reddedilir |
| MFA kurtarma kodları | bcrypt | PBKDF2-HMAC-SHA256 (yeni üretilenler); eskiler çalışmaya devam eder |
| Denetim kontrol noktası imzası | Ed25519 | ECDSA P-256 + SHA-256 (`core/crypto/signing.py`) |
| JWT | HS256 | HS256 (HMAC-SHA256 onaylıdır) |
| MFA sırrı ve gizli anahtar deposu | Fernet (AES-128-CBC + HMAC-SHA256) | aynı (onaylı ilkeller) |
| TOTP | HMAC-SHA1 | aynı (HMAC-SHA1, SP 800-131A'ya göre onaylı) |
| MD5 / SHA-1 | yalnızca tanımlayıcı/bütünlük amaçlı, `usedforsecurity=False` ile | aynı; FIPS sağlayıcısı bu bayrakla çağrılara izin verir |

`PASSWORD_HASH_SCHEME=pbkdf2_sha256` FIPS modu olmadan da seçilebilir.
`FIPS_MODE=true` ile `PASSWORD_HASH_SCHEME=bcrypt` yapılandırma hatasıdır.

FIPS dışı ilkellerin envanteri `tests/unit/_ratchets/test_fips_primitive_inventory.py`
içindedir. Listeye girmeyen yeni bir kullanım (ör. `hashlib.md5()` bayraksız,
`import bcrypt`, ChaCha20, Ed25519) testi kırar; liste yalnızca küçülebilir.

## FIPS etkin imaj

Varsayılan imajlar (`python:<sürüm>-slim`) FIPS sağlayıcısı içermez ve pip'ten gelen
`cryptography` tekerleği kendi OpenSSL kopyasını gömer. Bu yüzden FIPS modu için
ayrı bir imaj gerekir. Gerekenler:

1. **Doğrulanmış bir OpenSSL 3 FIPS sağlayıcısı.** Seçenekler: RHEL 9 / UBI 9
   (`registry.access.redhat.com/ubi9/python-312`, sistem OpenSSL'i FIPS doğrulamalı),
   Ubuntu Pro FIPS imajları, ya da OpenSSL 3.0.x/3.1.2 kaynağından
   `enable-fips` ile derlenmiş ve `openssl fipsinstall` ile `fipsmodule.cnf`
   üretilmiş bir katman. Debian'ın paketlediği OpenSSL'in FIPS modülü doğrulanmış
   değildir; denetim için yeterli kabul edilmez.
2. **Python'un o OpenSSL'e bağlı olması.** UBI 9 Python'u sistem OpenSSL'ini kullanır.
   Kaynak derlemede `./configure --with-openssl=<önek>`.
3. **`cryptography`'nin aynı OpenSSL'e karşı derlenmesi.** Tekerlek değil kaynak
   kurulum: `pip install --no-binary cryptography cryptography==<requirements.lock'taki sürüm>`
   (Rust araç zinciri ve `openssl-devel` gerekir; `OPENSSL_DIR` FIPS OpenSSL önekini
   göstermeli). Aksi halde başlangıç denetimi `cryptography (OpenSSL ...)` için
   reddeder.
4. **OpenSSL yapılandırması.** `OPENSSL_CONF` dosyası `fips` sağlayıcısını etkinleştirip
   varsayılan özellikleri `fips=yes` yapmalı:

   ```ini
   openssl_conf = openssl_init
   .include /usr/local/ssl/fipsmodule.cnf
   [openssl_init]
   providers = provider_sect
   alg_section = algorithm_sect
   [provider_sect]
   fips = fips_sect
   base = base_sect
   [base_sect]
   activate = 1
   [algorithm_sect]
   default_properties = fips=yes
   ```

   RHEL/UBI'de bunu `update-crypto-policies --set FIPS` (veya FIPS çekirdekli bir
   düğüm) sağlar.
5. **Doğrulama.** İmaj içinde:

   ```bash
   python -c "from core.crypto.fips import fips_status; print(fips_status().as_dict())"
   ```

   `active: True` görülmeli. `kernel_fips` yalnızca bilgi amaçlıdır.

`bcrypt` paketi imajda kalır: göç sırasında eski hash'leri doğrulamak için
kullanılır, FIPS modunda yeni hash üretmez. Göç bitince
`FIPS_LEGACY_BCRYPT_VERIFY=false` yapılabilir.

## Helm

```yaml
backend:
  image:
    repository: <kayıt>/autosecops-backend-fips   # yukarıdaki gibi hazırlanmış imaj
daemon:
  image:
    repository: <kayıt>/autosecops-daemon-fips
# llmWorker backend imajını devralır.
config:
  FIPS_MODE: "true"
  PASSWORD_HASH_SCHEME: ""                    # boş = FIPS'te pbkdf2_sha256
```

Standart imajla `FIPS_MODE: "true"` verilirse her pod başlangıçta 78 ile çıkar
(CrashLoopBackOff); günlükte `configuration error: FIPS_MODE=true but the OpenSSL 3
FIPS provider is not active ...` satırı nedeni söyler.

## Mevcut kurulumu geçirme

1. FIPS imajına geçip `FIPS_MODE=true` ile başlatın. Mevcut kullanıcılar bcrypt
   hash'leriyle giriş yapabilir; her başarılı girişte hash PBKDF2'ye yeniden yazılır
   (parola değişim tarihi ve geçmişi değişmez).
2. Kalan bcrypt hash'lerini sayın:
   `SELECT count(*) FROM users WHERE password_hash LIKE '$2%';`
3. Sayı sıfırlandığında (veya kalan hesaplar için parola sıfırlaması yapıldığında)
   `FIPS_LEGACY_BCRYPT_VERIFY=false` ayarlayın.

Geri dönüş: `FIPS_MODE=false` ve `PASSWORD_HASH_SCHEME` boşken PBKDF2 hash'leri
doğrulanmaya devam eder ve girişte bcrypt'e yeniden yazılır. Bu özelliği içermeyen
eski bir sürüme dönmeden önce kullanıcıların bu şekilde bcrypt'e dönmesi ya da
parola sıfırlaması gerekir.

## Kapsam dışı

- TypeScript ajanı (Node) için ayrı bir FIPS denetimi yoktur; Node'u FIPS OpenSSL ile
  çalıştırmak için `node --enable-fips` ve aynı `OPENSSL_CONF` kullanılır.
- Medic servisinin imzalı paket güven kökü Ed25519 kullanır (ayrı imaj, ayrı
  sözleşme) ve envanterde taban listededir.
