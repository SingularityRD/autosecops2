# Entra ID executor (AutoSecOps)

`core/integrations/azure_ad/executor.py`, AutoSecOps müdahale eylemlerini
Microsoft Graph v1.0 üzerinden Entra ID (Azure AD) kullanıcı hesaplarına
uygular. `core/response/executors/base.py` içindeki `Executor` protokolünü
gerçekler. Bu WP'de hiçbir yere kayıtlı değildir: `build_executor(config)` bir
örnek döndürür, `ExecutorRegistry`'ye bağlamayı ayrı bir WP yapar.

## Eylemler

| `action_type` | Graph çağrısı | Geri alınabilir | `verify` neye bakar |
|---|---|---|---|
| `disable_user` | `PATCH /users/{id}` `{"accountEnabled": false}` | evet (`enable`) | `accountEnabled == false` |
| `enable_user` | `PATCH /users/{id}` `{"accountEnabled": true}` | evet (`disable`) | `accountEnabled == true` |
| `revoke_sessions` | `POST /users/{id}/revokeSignInSessions` | **hayır** | `signInSessionsValidFromDateTime` ileri gitti mi |

- `revoke_sessions`, `reversible_types` içinde **değildir**. `reversibility="reversible"`
  ile gelirse hem executor hem registry reddeder; `validate` her zaman
  `requires_approval=True` döner (insan onayı şart). `reverse` bu eylem için
  `failed` döner.
- `default_ttl` varsayılan olarak `None`'dır (değişiklik kalıcıdır, biri geri
  alana kadar durur). `default_ttl_seconds` ile ayarlanabilir.

## Yaşam döngüsü

1. **validate**: hedefi değiştirmez, yalnızca okur.
   - Hedef bir UPN, e-posta adresi ya da object id (GUID) olmalıdır; diğer
     biçimler Graph'a hiç gidilmeden reddedilir.
   - UPN/e-posta `userPrincipalName eq '…' or mail eq '…'` filtresiyle aranır
     (`ConsistencyLevel: eventual`). Sonuç **tam olarak bir** kullanıcı değilse
     reddedilir (yok ya da belirsiz; ör. aynı adres hem üye hem misafir).
   - Korunan kimlik: `protected_users` (UPN, mail veya object id; büyük/küçük
     harf duyarsız), `protected_patterns` (UPN/mail üzerinde kabuk glob'u, ör.
     `svc-*@contoso.com`, `breakglass*@*`).
   - Korunan rol: kullanıcının `transitiveMemberOf/microsoft.graph.directoryRole`
     listesinde `protected_roles` içinden bir rol (template id veya görünen ad)
     varsa reddedilir. Varsayılan: Global Administrator, Privileged Role
     Administrator, Privileged Authentication Administrator. Açık bir liste
     verilirse varsayılanın **yerine geçer**.
   - Misafir (`userType=Guest`) yalnızca `parameters.user_type="Guest"` ile
     onaylanırsa işlenir; tür uyuşmazlığı reddedilir.
   - On-prem'den senkronize edilen hesapta (`onPremisesSyncEnabled=true`)
     disable/enable reddedilir (değişiklik AD'de yapılmalı); revoke izinlidir.
   - Graph'a ulaşılamazsa, belirteç alınamazsa ya da rol listesi okunamazsa
     **reddeder** (fail closed).
2. **execute**: kontrolleri yeniden yapar (onay ile çalıştırma arasında rol
   verilmiş olabilir), `before_state`'i yakalar. Hesap zaten istenen
   durumdaysa `noop` döner ve Graph'ı değiştirmez. Değişiklikten sonra kullanıcıyı
   yeniden okuyup `after_state` olarak kaydeder. `revoke_sessions` için
   idempotensi: aynı `idempotency_key` aynı süreçte ikinci kez gelirse `noop`;
   `parameters.requested_at` verilirse ve `signInSessionsValidFromDateTime` o
   andan sonraysa `noop` (kalıcı koruma).
3. **verify**: kullanıcıyı yeniden okur. Beklenen durum gözlenmezse `failed`,
   Graph okunamazsa `unknown` (yeniden deneme / geri alma tetiklemez).
4. **reverse**: yalnızca disable/enable için; `before_state.accountEnabled`
   değerini object id ile geri yükler. Koruma kontrolü yapmaz (bu bir geri
   yüklemedir). Orijinal eylem `noop` veya `failed` ise `noop` döner.

## Hatalar ve geri çekilme

- 429 ve 500/502/503/504 ile ağ hataları `max_retries` (varsayılan 3) kez
  yeniden denenir. `Retry-After` varsa ona uyulur (`max_backoff`, varsayılan
  30 sn ile sınırlı), yoksa `1, 2, 4, …` saniye beklenir.
- Diğer 4xx yeniden denenmez; `ExecResult(status="failed")` hatası HTTP durumu
  ve Graph hata kodunu içerir.
- 401 alınırsa belirteç bir kez yenilenir.

## Gizli bilgiler

- Erişim belirteci yalnızca bellekte ve yalnızca `Authorization` başlığında
  bulunur. Loglar, `GraphError` metni, `ExecResult` / `VerifyResult` ve
  `repr()` çıktıları belirteci veya client secret'ı içermez (testle
  doğrulanır: `test_no_token_logging`).
- Ağ hatalarında yalnızca istisna sınıfının adı yazılır, istek değil.

## Yapılandırma (`build_executor(config)`)

| Anahtar | Açıklama |
|---|---|
| `tenant_id`, `client_id`, `client_secret` | Uygulama kaydı (client credentials). Ya bunlar ya `token_provider`. |
| `token_provider` | Belirteç döndüren çağrılabilir (test / dış kasa için). |
| `protected_users` | Liste veya virgülle ayrılmış metin. Break-glass ve servis hesaplarını buraya yazın. |
| `protected_patterns` | Glob listesi (`svc-*@…`). |
| `protected_roles` | Rol template id / ad listesi; verilmezse varsayılan üç ayrıcalıklı rol. |
| `timeout`, `max_retries`, `max_backoff` | Graph istemcisi ayarları. |
| `default_ttl_seconds` | Boşsa kalıcı. |

Eksik kimlik bilgisi `ExecutorConfigError` verir; mesaj yalnızca eksik
anahtarların **adlarını** içerir.

## Gerekli Graph uygulama izinleri

- `User.Read.All` — kullanıcı çözümleme ve doğrulama
- `User.EnableDisableAccount.All` — `accountEnabled` değiştirme
- `User.RevokeSessions.All` — oturum iptali
- `RoleManagement.Read.Directory` (veya `Directory.Read.All`) — rol üyeliği

Not: ayrıcalıklı bir yöneticiyi devre dışı bırakmak Graph tarafında ayrıca
yetkili rol gerektirir; executor bunları zaten korunan rol olarak reddeder.
PIM ile yalnızca **uygun (eligible)** olan ve henüz etkinleştirilmemiş roller
`transitiveMemberOf` içinde görünmez; bu hesapları `protected_users` ile
listeleyin.

## Canlı tenant ile elle test prosedürü

Otomatik testler Graph'ı taklit eder (respx). Canlı doğrulama yalnızca bir
**test tenant'ında** ve aşağıdaki adımlarla yapılır:

1. Test tenant'ında yukarıdaki dört izni olan bir uygulama kaydı oluşturun,
   yönetici onayı verin. Bir deneme kullanıcısı (`exec-test@<tenant>`), bir
   break-glass taklidi ve bir Global Administrator hesabı hazırlayın.
2. Python kabuğunda:

   ```python
   from core.integrations.azure_ad.executor import build_executor
   from core.response.executors.base import TypedAction
   ex = build_executor({
       "tenant_id": "...", "client_id": "...", "client_secret": "...",
       "protected_users": ["breakglass@<tenant>"],
   })
   a = TypedAction(action_type="disable_user", target="exec-test@<tenant>")
   print(ex.validate(a))
   r = ex.execute(a); print(r)
   print(ex.verify(a, r))
   print(ex.reverse(a, r))
   ```

3. Beklenen: `validate` izin verir; `execute` → `executed`,
   `before_state.accountEnabled=True`, `after_state.accountEnabled=False`;
   `verify` → `verified` (Graph'ın nihai tutarlılığı nedeniyle birkaç saniye
   sonra tekrar denemek gerekebilir); `reverse` → hesap yeniden etkin.
4. `execute(a)`'yı hesap devre dışıyken iki kez çağırın: ikincisi `noop`.
5. `target` olarak break-glass hesabını ve Global Administrator'ı deneyin:
   `validate` reddetmeli, `execute` `failed` / `refused:` dönmeli; Entra
   portalında hesapların değişmediğini doğrulayın.
6. `revoke_sessions` (`reversibility="irreversible"`): `execute` → `executed`,
   `verify` → `verified`; portalda kullanıcının oturumlarının iptal edildiğini
   ve `reverse`'ün `failed` döndüğünü doğrulayın.
7. Uygulama kaydının client secret'ını silin veya döndürün; oluşan logları
   belirteç/secret için tarayın (`grep -c "eyJ"` sıfır olmalı).
