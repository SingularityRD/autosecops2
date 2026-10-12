# AutoSecOps — Veri saklama ve periyodik imha

> **Hukuki görüş değildir.** Bu belge AutoSecOps'un teknik saklama/imha
> yeteneklerini ve bunların KVKK kavramlarıyla nasıl eşleşebileceğini anlatır.
> Saklama sürelerinin belirlenmesi, imha politikasının onaylanması ve VERBİS
> kayıtları veri sorumlusunun (ve hukuk danışmanının) sorumluluğundadır.

Kod: `core/compliance/retention.py`, API: `core/compliance/retention_router.py`
(`/api/compliance/retention`), WP spesifikasyonu: `docs/wp/w3.5.md`.

## 1. Veri sınıfları

Her sınıf için `retention_policies` tablosunda (`tenant_id='default'`) bir
satır vardır: saklama süresi (`retain_days`) ve sınıf düzeyinde yasal saklama
(`legal_hold`). İmha yöntemi `system_config['retention.methods']` içinde tutulur.
**Politikası olmayan bir sınıf hiçbir zaman işlenmez.**

| Sınıf | Kapsam | Yaş ölçütü | Yöntemler | Not |
|---|---|---|---|---|
| `findings` | `findings` | `created_at` | delete / anonymise | Açık veya legal hold'daki vakaya bağlı bulgular atlanır |
| `raw_events` | `findings.entity_context.source_evidence` | bulgunun `created_at`'i | delete | Bulgu kalır, yalnızca gömülü ham kayıt çıkarılır |
| `cases` | `cases` (+ yorumlar, kanıt, ekler FK ile) | `updated_at` | delete / anonymise | Yalnızca `resolved`/`closed` vakalar; silme kanıt dosyalarını da siler |
| `case_evidence` | `case_evidence`, `case_attachments` | `created_at` | delete / anonymise | Anonimleştirme dosyayı siler; hash ve gözetim zinciri kalır |
| `chat_conversations` | `conversations`, `chat_messages` | son mesaj zamanı | delete / anonymise | |
| `llm_logs` | `llm_interaction_logs` | `created_at` | delete / anonymise | Anonimleştirme içerikleri siler, token/maliyet kalır |
| `agent_ledger` | `agent_events` (hash zincirli) | çalıştırmanın son olayı | — (arşiv) | **Otomatik imha edilmez**, bkz. §5 |
| `audit_logs` | `case_audit_logs`, `config_audit_log` | `timestamp` | delete / anonymise | İmha tutanağı kayıtları (`config_type='retention'`) hiç işlenmez |
| `uploads` | kanıt deposundaki öksüz dosyalar | dosya mtime | delete | Hiçbir kanıt/ek satırının göstermediği dosyalar |

**Anonimleştirme** kişisel veri taşıyabilecek serbest metin alanlarını
`[anonymised]` ile değiştirir veya boşaltır; istatistik için gereken
alanları (önem derecesi, zaman damgaları, token sayıları, dosya hash'leri)
korur. Anonimleştirilmiş bir satır bir sonraki çalıştırmada tekrar seçilmez.

## 2. Yasal saklama (legal hold)

- **Vaka düzeyi:** `PUT /legal-holds/cases/{case_id}` (gerekçe zorunlu). Vaka,
  bağlı bulguları, kanıt/ekleri, vakaya bağlı sohbetler, vakanın
  soruşturmalarına ait LLM kayıtları, vakanın denetim kayıtları ve
  `<case_id>/` altındaki yüklemeler her sınıfta imhadan dışlanır.
- **Sınıf düzeyi:** politikada `legal_hold=true` o sınıfı tamamen durdurur.
- Açık (çözülmemiş) bir vaka da kendisine bağlı bulgu ve kanıtları korur.
- Koyma ve kaldırma işlemleri `config_audit_log`'a (`legal_hold_set`,
  `legal_hold_release`) aktör ve gerekçeyle yazılır.

## 3. İmha işi

- Elle: `POST /api/compliance/retention/purge` — gövde varsayılanı
  `{"dry_run": true}`; gerçek imha için açıkça `false` verilmelidir.
- Zamanlanmış: daemon görevi `retention_purge`, yalnızca
  `RETENTION_PURGE_ENABLED=true` ise kaydedilir (varsayılan kapalı) ve
  `RETENTION_PURGE_DRY_RUN=true` (varsayılan) iken hiçbir şeyi değiştirmez.
  En sık saatte bir çalışır (`RETENTION_PURGE_INTERVAL`, varsayılan 86400 sn).
- Her sınıf `RETENTION_PURGE_BATCH_SIZE` (500) satırlık partilerle, her parti
  ayrı bir işlemde (transaction), en fazla `RETENTION_PURGE_MAX_BATCHES` (20)
  parti işlenir; kalanlar bir sonraki çalıştırmaya kalır (`more_remaining`).
  Satırlar `FOR UPDATE SKIP LOCKED` ile seçilir.
- Dosyalar ancak satırları commit edildikten sonra silinir; yalnızca kanıt
  deposu kökü içindeki yollar silinir.
- Aynı anda tek çalıştırma: Postgres advisory lock; ikincisi `409` alır.
- Kuru çalıştırma hiçbir şey yazmaz (denetim kaydı dahil); yalnızca işlenecek
  adetleri döndürür.
- Gerçek her çalıştırma tek bir `config_audit_log` satırı yazar:
  `config_type='retention'`, `action='purge'`, `changed_by=<kullanıcı|system>`,
  `new_value` = sınıf başına politika, yöntem, kesim tarihi, adet, durum.

## 4. Periyodik imha tutanağı

`GET /api/compliance/retention/reports?since=&until=&format=json|markdown`
(varsayılan son 180 gün). Tutanak denetim kayıtlarından üretilir ve şunları
içerir: yürürlükteki politikalar, dönem içinde sınıf başına silinen /
anonimleştirilen / silinen dosya sayıları, her çalıştırmanın ayrıntısı, legal
hold altındaki vakalar, politika/legal hold değişiklikleri, otomatik imhadan
hariç tutulanlar ve imza bloğu. Markdown çıktısı PDF'e dönüştürülmeye hazırdır
(ör. `pandoc tutanak.md -o tutanak.pdf`).

## 5. Hash zincirli tablolar: arşivle-sonra-kes

`agent_events` (ajan defteri) her ajan çalıştırması (`run_id`) için ayrı bir
hash zinciri tutar (`31_agent_ledger_hash_chain.sql`:
`event_hash = sha256(prev_hash || payload)`). Bir satırı sessizce silmek veya
değiştirmek zinciri bozar ve kanıt değerini yok eder. Bu yüzden:

1. İmha işi `agent_ledger` sınıfını **asla** işlemez; yalnızca süresi geçmiş
   çalıştırma sayısını (`archive_candidates`) raporlar. Uygulama rolü
   `vigil_app`'in bu tabloda zaten `UPDATE/DELETE/TRUNCATE` yetkisi yoktur.
2. **Arşiv:** `GET /api/compliance/retention/agent-ledger/archive?before=<tarih>&limit_runs=N`
   son olayı `before`'dan eski olan *tüm* çalıştırmaları döndürür; her zincir
   yeniden hesaplanarak doğrulanır (`chain_verified`, `first_break_seq`) ve
   manifest arşivin SHA-256 özetini taşır. Dışa aktarım `ledger_archive_export`
   olarak denetim kaydına yazılır (içerik değil, özet).
3. Arşiv dosyası WORM/değiştirilemez bir depoya konur; manifestteki
   `sha256` ayrıca kaydedilir.
4. **Kesme (elle, DB sahibi rolüyle):** yalnızca `all_verified=true` olan bir
   manifestin `run_ids` listesi için, tek bir işlemde:

   ```sql
   BEGIN;
   -- manifestteki run_id'ler; olay sayısı manifestle aynı olmalı
   SELECT count(*) FROM agent_events WHERE run_id = ANY(:run_ids);
   DELETE FROM agent_events WHERE run_id = ANY(:run_ids);
   COMMIT;
   ```

   Zincirler çalıştırma başınadır; bütün bir çalıştırmanın silinmesi kalan
   çalıştırmaların doğrulanabilirliğini etkilemez. Bir çalıştırma asla kısmen
   silinmez.
5. Kesme sonrasında, tutanağa eklenmek üzere arşiv manifestinin özeti ve
   silinen satır sayısı bir `config_audit_log` kaydı olarak elle girilir.

W1.10'un `audit_chain` / `audit_checkpoints` tabloları (varsa) bir veri sınıfı
değildir ve bu modül tarafından yalnızca okunabilir; imha kodu bu tablolara
hiçbir SQL yazımı içermez (spesifikasyondaki AC6 bunu grep ile denetler).

## 6. KVKK eşlemesi (bilgilendirme amaçlı)

| KVKK / Yönetmelik kavramı | AutoSecOps karşılığı |
|---|---|
| 6698 s. Kanun m.4/2-(d): ilgili mevzuatta öngörülen veya işlendikleri amaç için gerekli olan süre kadar muhafaza | Sınıf başına `retain_days` politikası |
| m.7: amaç ortadan kalkınca silme, yok etme veya anonim hale getirme | `delete` / `anonymise` yöntemleri |
| Kişisel Verilerin Silinmesi, Yok Edilmesi veya Anonim Hale Getirilmesi Hakkında Yönetmelik m.5: kişisel veri saklama ve imha politikası | Bu belge + `/policies` API'sinin çıktısı (politika metni veri sorumlusunca hazırlanır) |
| Yönetmelik m.11: periyodik imha (en fazla 6 aylık aralıklarla) | Zamanlanmış `retention_purge` görevi (varsayılan günlük) ve 180 günlük varsayılan tutanak dönemi |
| Yönetmelik m.7: tüm işlemlerin kayıt altına alınması, en az 3 yıl saklanması | Her imha/politika/legal hold değişikliği için `config_audit_log` kaydı; bu kayıtlar `audit_logs` imhasından muaftır |
| Anonimleştirme: verinin başka verilerle eşleştirilerek dahi kimliği belirli/belirlenebilir kişiyle ilişkilendirilemez hale gelmesi | `anonymise` serbest metin ve kimlik alanlarını kaldırır; yine de dolaylı tanımlayıcılar (ör. bulgu `entity_context` dışı alanlar, IP içeren başlıklar) için veri sorumlusu ek değerlendirme yapmalıdır |
| Hukuki yükümlülük / dava nedeniyle saklama (m.5/2-ç, m.5/2-e) | Vaka veya sınıf düzeyinde legal hold |

**Sınırlamalar:** Yedekler (DB dump, nesne deposu sürümleri), harici
sistemlere (SIEM, bilet sistemi, webhook alıcıları) gönderilen kopyalar ve
LLM sağlayıcısındaki kayıtlar bu iş tarafından imha edilmez; ayrı süreçlerle
ele alınmalıdır. Tüm işlemler tek kiracı (`default`) içindir.
