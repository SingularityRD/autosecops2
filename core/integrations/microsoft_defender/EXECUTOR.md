# Microsoft Defender for Endpoint — İzolasyon Yürütücüsü (W2.5)

`executor.py`, AutoSecOps müdahale katmanının `Executor` protokolünü
(`core/response/executors/base.py`) Microsoft Defender for Endpoint (MDE) için
uygular. İki eylem tipi vardır ve ikisi de geri alınabilir:

| Eylem tipi | MDE çağrısı | Tersi |
|---|---|---|
| `isolate_host` | `POST /api/machines/{id}/isolate` (`IsolationType`: `Full` varsayılan, `Selective`) | `unisolate_host` |
| `unisolate_host` | `POST /api/machines/{id}/unisolate` | eski izolasyon tipiyle yeniden `isolate` |

Bu WP executor'ı **hiçbir registry'ye bağlamaz**. Kullanacak olan WP şunu yapar:

```python
from core.integrations.microsoft_defender.executor import build_executor
registry.register(build_executor({}))   # kimlik bilgileri entegrasyon yapılandırmasından
```

## Dosyalar

| Dosya | Görev |
|---|---|
| `client.py` | Paylaşılan MDE istemcisi: token alma, yeniden deneme/geri çekilme, hata ayrıştırma. Hem `tool.py` (MCP sunucusu) hem executor kullanır. |
| `executor.py` | `DefenderIsolationExecutor` ve `build_executor(config)` fabrikası. |
| `tool.py` | MCP araçları (`mde_get_alerts`, `mde_get_machine`, `mde_isolate`); artık `client.py` üzerinden çağırır, dışa dönük davranışı aynıdır. |

## Yaşam döngüsü

### validate (hedefe dokunmaz)

- Eylem tipi, `isolation_type` (yalnızca `isolate_host` için; `Full`/`Selective`)
  ve `comment` (metin) parametreleri kontrol edilir.
- Entegrasyon yapılandırılmamışsa (`tenant_id`, `client_id`, `client_secret`
  eksik) reddedilir.
- Hedef **tam olarak bir** MDE makinesine çözülmelidir:
  - 40 hex karakter → makine kimliği (`GET /machines/{id}`; 404 → ret).
  - IP adresi → `lastIpAddress eq '…'`.
  - FQDN → `computerDnsName eq '…'`; kısa ad → ilk DNS etiketinin tam
    eşleşmesi: `computerDnsName eq 'ws-01' or startswith(computerDnsName,'ws-01.')`,
    ardından istemci tarafında da tam ad / ilk etiket süzülür (`ws-01`,
    `ws-01.corp.example`'ı bulur ama `ws-010`'u bulmaz).
  - Arama tek sayfa (`$top=50`) okur. Yanıtta `@odata.nextLink` varsa veya
    sayfa doluysa tüm eşleşmeler görülmemiştir; "tam olarak bir" kanıtlanamaz ve
    hedef reddedilir (makine kimliğiyle verilmelidir). `nextLink` hiçbir zaman
    izlenmez (yanıttan gelen bir URL'ye token gönderilmez).
  - Başka biçimdeki hedef OData filtresine hiç girmez, reddedilir.
- Sıfır eşleşme, birden çok eşleşme (belirsiz; mesajda en fazla 10 makine
  kimliği listelenir) veya MDE'ye erişilememesi gerekçeli `deny` döner.
- `require_approval: true` ise izin verilen eylem yine de onay ister (executor
  onayı hiçbir zaman kaldıramaz).

### execute (idempotent)

1. Hedef yeniden çözülür ve `before_state` yakalanır: makine sağlığı
   (`health_status`, `onboarding_status`, `last_seen`, `last_ip_address`,
   `os_platform`) ve izolasyon durumu.
2. MDE makine varlığında izolasyon bayrağı **yoktur**; durum, makinenin
   başarısız/iptal/zaman aşımı olmayan **en son** Isolate/Unisolate makine
   eyleminden çıkarılır (`isolated`, `isolation_state` ∈ `isolated`,
   `isolating`, `not_isolated`, `unisolating`).
3. Makine zaten istenen durumdaysa veya o yönde bekleyen bir eylem varsa
   **`noop`** döner, POST yapılmaz (bekleyen eylem varsa `external_ref` ona işaret
   eder, böylece verify onu izler).
4. Aksi halde POST yapılır; `external_ref` = MDE makine eylemi kimliği,
   `after_state` = beklenen yeni durum.
5. POST hata ile biterse (ağ zaman aşımı, yeniden denemeler sonrası 5xx/429,
   herhangi bir 400 — `ActiveRequestAlreadyExists` dahil, ya da başka 4xx)
   sonuç belirsiz olabilir: MDE isteği kabul etmiş olabilir. Makine eylemleri
   **yeniden okunur**:
   - `before_state`'tekinden farklı, istenen yönde canlı bir eylem varsa sonuç
     `executed`, `external_ref` o eylemdir (verify onu izler; reverse/TTL geri
     alabilir).
   - Yeniden okuma böyle bir eylem olmadığını doğrularsa `failed`.
   - Yeniden okuma da başarısızsa: belirsiz hata (ağ, 429, 5xx) için
     `executed` + `after_state.outcome = "unknown"` ve `external_ref` yok
     (verify durumu yeniden okur; reverse kayıtlı makine kimliğiyle geri
     alabilir, böylece izole kalmış bir host sahipsiz kalmaz); kesin ret
     (diğer 4xx) için `failed`.

Yorum (`Comment`) verilmezse `AutoSecOps isolate (action <id>, requested by <kim>)`
yazılır; 1000 karakterle sınırlıdır.

### verify

- `failed` bir execute → `failed`.
- `external_ref` varsa `GET /machineactions/{id}` her `poll_interval_seconds`
  saniyede yoklanır: `Succeeded` → `verified`; `Failed`/`Cancelled`/`TimeOut` →
  `failed`; `verify_timeout_seconds` dolarsa (eylem hâlâ `Pending`/`InProgress`
  ya da API okunamıyor) → **`unknown`**. `unknown`, hiçbir şeyin yeniden
  denenmemesi veya geri alınmaması gerektiği anlamına gelir.
- Yerleşik bir `noop` için durumun hâlâ geçerli olduğu yeniden okunur.

### reverse

- Reverse eyleminin (`reverse_of` dolu) `validate`'i hedef dizgesini yeniden
  çözmez (yalnızca tip/parametre/yapılandırma kontrolü); yeniden adlandırılmış
  bir hostun geri alınması reddedilmez.
- `before_state`'teki **makine kimliği** kullanılır (hedef dizgesi değil); host
  yeniden adlandırılmış veya IP'si değişmiş olsa da doğru makine geri alınır.
- `noop` bir eylemin tersi `noop`'tur: biz dokunmadan önce izole olan bir host
  izole kalır.
- Makine zaten `before_state` durumundaysa `noop`.
- `before_state` yoksa `failed` (ne geri getirileceği bilinemez).

## Hata yönetimi ve yeniden deneme

| Durum | Davranış |
|---|---|
| 429, 500, 502, 503, 504, ağ hatası | `max_retries` (varsayılan 3) kez yeniden dener; bekleme `Retry-After` başlığı varsa ona göre, yoksa `backoff_base_seconds * 2^deneme`; en fazla 30 sn |
| 401 | Token düşürülür, bir kez yeni token ile tekrar denenir |
| Diğer 4xx (400, 403, 404 …) | Yeniden denenmez; `MDEApiError` (`status`, MDE `error.code`) |
| Token alımı başarısız | `TokenError`; mesajda yalnızca HTTP durumu ve AADSTS kodu |

**Gizli bilgiler:** istemci secret'ı ve erişim token'ı hiçbir log kaydına,
`ExecResult`/`VerifyResult`/`PolicyResult` içeriğine, istisna mesajına veya
`repr`'e girmez. Hata mesajları yalnızca yöntem, yol, HTTP durumu, MDE hata kodu
ve kısaltılmış (200 karakter) MDE mesajını içerir. Testler bunu doğrular
(`test_secrets_never_reach_logs_results_or_repr`).

## Yapılandırma (`build_executor(config)`)

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `tenant_id`, `client_id`, `client_secret` | entegrasyon yapılandırması | Verilmezse her token alımında `resolve(MICROSOFT_DEFENDER)` ile okunur (döndürülen secret yeniden kurulum gerektirmez). |
| `isolation_ttl` | `None` | Saniye; executor'ın `default_ttl`'i. `None`: izolasyon biri geri alana kadar sürer. |
| `default_isolation_type` | `Full` | `Full` veya `Selective`. |
| `verify_timeout_seconds` | 300 | Verify yoklamasının üst sınırı. |
| `poll_interval_seconds` | 10 | Yoklama aralığı. |
| `max_retries` | 3 | 429/5xx/ağ hatası için. |
| `backoff_base_seconds` | 1 | Üstel geri çekilme tabanı. |
| `require_approval` | `false` | `true` ise validate her zaman onay ister. |
| `api_base` | `https://api.securitycenter.microsoft.com/api` | Yalnızca resmi MDE uç noktaları kabul edilir (`client.ALLOWED_API_BASES`: global, `api-us/eu/uk/au.securitycenter.microsoft.com`, `api.security.microsoft.com` ve `us/eu/uk/au.api.security.microsoft.com`, hepsi `https://…/api`). Başka bir host `ValueError` ile reddedilir; böylece entegrasyon yapılandırmasını yazabilen biri bearer token'ı kendi sunucusuna yönlendiremez. Egemen bulutlar (GCC/High, DoD) farklı token kapsamı ister, desteklenmez. |

### Gerekli MDE uygulama izinleri (Application, yönetici onaylı)

- `Machine.Read.All` — hedef çözümleme, durum okuma
- `Machine.Isolate` — isolate / unisolate
- `Machine.ReadWrite.All` gerekmez. `Alert.Read.All` yalnızca MCP aracı
  `mde_get_alerts` ve ingestion için.

## Bilinen sınırlar

- Makine eylemi varlığı izolasyon tipini (`Full`/`Selective`) döndürmez;
  `before_state.isolation_type` yalnızca AutoSecOps'un kendi başlattığı eylem için
  biliniyor. Bilinmiyorsa unisolate'in tersi `default_isolation_type` ile izole eder.
- Durum, makine başına en yeni 50 Isolate/Unisolate eyleminden
  (`$orderby=creationDateTimeUtc desc`) çıkarılır.
- Portalda elle yapılmış ve henüz makine eylemi listesinde görünmeyen bir
  değişiklik, kısa bir süre için durum okumasını yanıltabilir; verify bunu
  eylem durumu üzerinden yakalar.

## Testler

```bash
source /tmp/claude-0/env.sh; unset DAEMON_AUTO_TRIAGE
DEMO_MODE=false MCP_AUTO_CONNECT_ON_STARTUP=false PYTHONPATH=. \
  python -m pytest tests/unit/integrations/test_defender_executor.py -q -p no:cacheprovider
```

Tüm HTTP çağrıları `respx` ile taklit edilir (MDE API ve Entra ID token uç
noktası); gerçek ağa çıkılmaz. Zaman (`sleep`/`clock`) sahte saatle ilerletilir.

## Canlı sandbox prosedürü (elle)

Bu prosedür **üretim kiracısında yapılmaz**. Gerçek bir makineyi ağdan
koparır; yalnızca test için ayrılmış bir cihazla çalışın.

### Ön koşullar

1. **Test kiracısı:** Microsoft 365 E5 / Defender for Endpoint P2 deneme
   kiracısı (ör. Microsoft 365 Developer Program veya Defender deneme lisansı).
   Kiracıda MDE etkin olmalı (`security.microsoft.com` → Ayarlar → Uç noktalar).
2. **Onboard edilmiş cihaz:** Kiracıya onboard edilmiş, kolayca yeniden
   kurulabilecek bir Windows 10/11 sanal makine (Ayarlar → Uç noktalar → Cihaz
   ekleme → yerel betik). Portalda *Cihaz envanteri*'nde `Onboarded` ve
   `Active` görünmeli. Cihaza ağ izolasyonu sırasında erişebilmek için
   hipervizör konsolu (RDP değil) hazır olmalı; Full izolasyon RDP'yi de keser.
3. **Uygulama kaydı:** Entra ID → Uygulama kayıtları → Yeni kayıt. *API
   izinleri* → *Kuruluşumun kullandığı API'ler* → `WindowsDefenderATP` →
   Application izinleri `Machine.Read.All`, `Machine.Isolate` → **Yönetici onayı
   ver**. *Sertifikalar ve gizli diziler* → yeni client secret.
4. AutoSecOps'ta `microsoft-defender` entegrasyonuna `tenant_id`, `client_id`,
   `client_secret` girilir (secret yalnızca secret deposunda tutulur; komut
   satırına veya log'a yazmayın).

### Adımlar

Worktree kökünde, secret'ı entegrasyon yapılandırmasından okuyarak:

```bash
source /tmp/claude-0/env.sh
PYTHONPATH=. python - <<'PY'
from core.integrations.microsoft_defender.executor import build_executor
from core.response.executors.base import TypedAction

ex = build_executor({"verify_timeout_seconds": 600, "poll_interval_seconds": 15})
host = "SANDBOX-VM-01"   # test cihazının adı veya MDE makine kimliği
iso = TypedAction(action_type="isolate_host", target=host, action_id="sandbox-1",
                  parameters={"comment": "AutoSecOps sandbox testi"})

print("validate:", ex.validate(iso))                 # allowed=True olmalı
res = ex.execute(iso)
print("execute:", res.status, res.external_ref)      # executed + makine eylemi kimliği
print("before:", res.before_state["isolation_state"])
print("verify:", ex.verify(iso, res))                # verified (birkaç dakika sürebilir)

again = ex.execute(iso)
print("tekrar:", again.status)                       # noop

undo = ex.reverse(iso, res)
print("reverse:", undo.status, undo.external_ref)    # executed (unisolate)
unis = TypedAction(action_type="unisolate_host", target=host, reverse_of="sandbox-1")
print("reverse verify:", ex.verify(unis, undo))      # verified
PY
```

### Beklenenler ve kontrol listesi

- [ ] `validate`: `allowed=True`. Var olmayan bir ad → `deny` ("no MDE machine
      matches"). İki cihaza aynı kısa adı vermek mümkünse → `deny` ("matches 2").
- [ ] `execute`: `executed`; portalda cihaz sayfasında *İşlem merkezi*nde
      "Isolate device" eylemi `Pending` → `Succeeded`; VM'de ağ kesilir
      (yalnızca Defender bulutuyla iletişim kalır).
- [ ] `verify`: `verified`. Cihaz kapalıysa eylem `Pending` kalır ve süre
      dolunca `unknown` döner — bu beklenen davranıştır.
- [ ] İkinci `execute`: `noop`, portalda yeni eylem açılmaz.
- [ ] `reverse`: `executed`; portalda "Release from isolation" eylemi
      `Succeeded`; VM ağı geri gelir.
- [ ] Log'larda (`docker logs` / uygulama logu) client secret ve `eyJ…` ile
      başlayan token **görünmez**: `grep -c "<secret'ın ilk 6 karakteri>"` → 0.
- [ ] Yanlış secret ile `validate` → `deny`, mesajda `credential rejected by Entra
      ID (HTTP 401, AADSTS…)`, secret yok.

### Temizlik

- Cihaz izole kaldıysa portaldan *Release from isolation* yapın veya
  `ex.execute(TypedAction(action_type="unisolate_host", target=host))`.
- Test bittiğinde client secret'ı Entra ID'de silin ve entegrasyon
  yapılandırmasından kaldırın.
