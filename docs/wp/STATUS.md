# AutoSecOps 2.0 — İş paketi durumu (12 Ekim 2026)


> Yeni oturumda devam etmek için önce `docs/wp/HANDOFF.md`, kalan düzeltmeler için `docs/wp/FIXES.md`.
Hedef: düzenlenmiş sektör GA, 30 Ekim 2026 (31 Ekim tampon). Plan: Claude Docs "AutoSecOps 2.0 Northstar uygulama planı".
Süreç: her iş paketi (WP) kendi dalında (`wp/<id>-<slug>`) yapılır → yalnızca spec + diff gören bağımsız doğrulayıcı → PASS olanlar `integration` dalına birleştirilir.
Tüm WP dalları `target` (SingularityRD/autosecops2) reposuna da gönderildi; hiçbir iş kaybolmadı.

## 1. Integration'a birleşenler (doğrulama PASS)

| WP | Konu | Not |
|---|---|---|
| W0.1, W0.3, W0.4, W0.5, W0.7 | Upstream sync/hard fork, CI, ajan fabrikası, sözleşmeler + init SQL 46–49, eval korpusu | Dalga 0 tamam |
| W0.4b | gates.sh düzeltmeleri | Düşük: `tracked_nm` silmeleri de sayıyor (`--diff-filter=d`) |
| W0.9 | Ortama sızan testler, korpus temizliği, API metinlerinde AutoSecOps | `storage_status.py:255,316` hâlâ "Vigil" diyor (takip işi) |
| W1.1 | Offline eval harness (evalkit) | |
| W1.6 | QA örnekleme + Scorecard | Öneri: çağıranın `seed` vermesini test dışı yok say; Disagree metni risk-ağırlıklı örnekler için yanlış |
| W1.7 | Araç etki sınıfları, yazma/yıkıcı araçlar onaysız çalışamaz | Düşük: onay argümana bağlı değil; isim sezgiseli `get_blockIp` gibi adları read_only sayıyor; chat'te `approve_action` açık |
| W1.8 | Giden webhook'lar, bildirim dağıtıcı, SLA | Orta: `url_safety` 100.64.0.0/10 (CGNAT, Alibaba metadata 100.100.100.200) geçiriyor → `not ip.is_global` ile engelle; dokümanda de-dup imzalı gövde `id` ile yapılmalı |
| W2.6 | Entra ID yürütücüsü | Orta: id-only rol stub'ı izin veriyor (reddetmeli). W2.4 kablolamasında id `azure-ad` olmalı ve client_secret secret store'dan çözülmeli |
| W2.8 | Vaka aksiyon zaman çizelgesi + Revert butonu | Düşük: 502 nesne `detail` gösterilmiyor |
| W3.8 | DORA/NIS2 bildirim saatleri, init SQL 50 | Orta: son olay(lar)ın silinmesi zincirde tespit edilmiyor (zincir başı çapası yok); sıra dışı anlar kabul ediliyor |

Birleştirme sonrası: `schema.d.ts` yeniden üretildi; `test_route_permissions.py` 37/37 geçti.

## 2. Yapıldı ama doğrulamada KALDI (dallarda commitli, birleşmedi)

| WP | Dal | Engelleyen bulgular (düzeltilecek) |
|---|---|---|
| W1.2 Triage JSON + provenance | wp/w1.2-triage-provenance | Provenance haritaları host/kullanıcı/etiket alanlarını SENSOR sayıyor (AWS `Resources.*`, Splunk `src/dest`, Elastic `host.*`); U+2028/2029/0085 prompt'ta yeni satır açıyor; `parse_triage_reply` derin iç içe/çok uzun sayıda istisna fırlatıyor; NUL karakteri JSONB'yi bozuyor |
| W1.5 Canary | wp/w1.5-canary | AC6 başarısız (tablo yokken `to_regclass` önbelleğe alınmıyor); canary'ler TEST-NET IP'lerle kolay tanınıyor; `/api/findings/{id}/intake` canary'de otonom soruşturma başlatabiliyor; W1.6 ile `core/quality/__init__.py` add/add çakışması; birleşince W1.6 örneklemesine canary filtresi eklenmeli |
| W1.9 OIDC SSO | wp/w1.9-oidc | **Yüksek:** Manager `link_by_verified_email` açıp kendi IdP'siyle Admin hesabına MFA'sız girebiliyor; SSO-only Admin break-glass seçilebiliyor; son sağlayıcı kapatılabiliyor; `schema.d.ts` çakışması |
| W1.10 Denetim zinciri (init SQL 51) | wp/w1.10-audit-chain | **Yüksek:** tetikleyici atlanarak yapılan değişiklik, aynı satıra sonraki normal yazımla gizleniyor (doğrulayıcı update/delete ön-görüntüsünü önceki zincir satırıyla karşılaştırmalı); anahtarsız doğrulama exit 0 veriyor |
| W2.1 Verdict run | wp/w2.1-verdict-run | **Yüksek:** reddedilen CONCLUDE bütçe bitince benign hüküm olarak kaydediliyor (yalnızca kabul edilen CONCLUDE kullanılmalı); `context` alanı gönderilmiyor |
| W2.2 Alert lanes (init SQL 56) | wp/w2.2-alert-lanes | **Yüksek:** bayrak kapalıyken bile payload'daki sahte `alert_lane` alanı triage'ı atlatıyor; tenant payload'dan geliyor; şiddeti olmayan uyarılar bastırılabiliyor |
| W2.4 Yürütücü kaydı + politika | wp/w2.4-executors-policy | **Yüksek:** çok büyük TTL `OverflowError` → aynı aksiyon her döngüde tekrar çalışıyor ve kuyruk tıkanıyor; korunan varlıklar sadece birebir dizeyle eşleşiyor (FQDN, `CORP\dc01`, CIDR, `0.0.0.0/0` geçiyor); model `parameters` hedefi değiştirebiliyor; `EXECUTOR_SOURCES` id'leri yanlış (`microsoft-defender`, `azure-ad` olmalı); reverse sırasında validate yeniden çözümleme yapmamalı; `revoke_sessions` ActionType değil; Cloudflare MCP araçları politikasız |
| W2.5 Defender yürütücüsü | wp/w2.5-defender-executor | **Yüksek:** kısa ad çözümlemesi `$top=50`'de kesiliyor (yanlış host izole edilebilir); izolasyon geçmişi sıralanmıyor; POST zaman aşımı durum okunmadan failed; config'teki `api_base` token sızdırabilir |
| W2.7 Palo Alto yürütücüsü | wp/w2.7-paloalto-executor | **Yüksek:** `verify` `reverse_of`'u yok sayıyor → her geri alma failed; unblock'un geri alınması blok kontrollerini atlıyor (yönetim IP'si engellenebilir); noop blok geri alması yeni blok ekliyor; IPv6 scope id kabul ediliyor |
| W3.3 Air-gap paketi | wp/w3.3-airgap | **Orta-Yüksek:** doğrulama ile kullanım arasında TOCTOU — paket önce özel `mktemp -d` dizinine kopyalanıp oradan doğrulanmalı/kurulmalı; FIFO/dizinler listelenmeden kabul; kural tar'larında symlink |
| W3.4 Sıfır egress | wp/w3.4-egress-zero | Tek engel önemsiz: `airgap.yml:14` yorumundaki "secrets" kelimesi AC5 grep'ini bozuyor. Düşük: tarayıcı kural boşlukları, `scripts/` taranmıyor, aksiyonlar SHA'ya sabitlenmemiş |
| W3.5 Saklama / KVKK | wp/w3.5-retention | **Yüksek:** yasal saklama (legal hold) altındaki veri 4 yoldan silinebiliyor (çalışma sırasında konan hold, sohbet LLM logları, cascade, açık vakalar); `ledger_archive_export` VARCHAR(20)'ye sığmıyor → arşiv uç noktası her seferinde çöküyor; `data_classes: []` "hepsi" anlamına geliyor |
| W3.6 Denetim dışa aktarımı (SIEM) | wp/w3.6-audit-export | **Yüksek:** redaksiyon birçok sır biçimini kaçırıyor (`password=`, PEM, `ghp_`, `xoxb-`, bağlantı dizeleri…); açık transaction'daki satır imleç geçtiği için kalıcı kayboluyor; CR/LF syslog'a kaçışsız gidiyor |

## 3. Hiç başlanmayanlar (plana göre)

- W1.3 / W1.4 (W1.2 içinde kısmen), W2.3, W3.1, W3.2, W3.7 (kanıt paketi — W3.8 şimdilik yerel paket kullanıyor) ve Dalga 4 (GA sertleştirme, pilot, dokümantasyon, sürüm) — ayrıntı için plan dokümanı.
- W1.10 ↔ W3.6 bağlantısı (W3.6 zinciri doğrudan tablodan okuyor).

## 4. Ortam notları

- `/root/vigil/.env` `DAEMON_AUTO_TRIAGE=true` ayarlıyor; gates için `GATES_ENV_SH=/root/wt/_briefs/gates_env.sh` kullanın (W0.9 birleştiği için ilgili testler artık wrapper'sız da geçiyor).
- 2 CPU'lu makinede 20 ajan aynı anda çalışınca vitest/pytest zaman aşımları ve OOM görüldü; doğrulayıcılar `GATES_TIMEOUT` artırarak yeniden koştu.
- Init SQL numaraları: 46–49 (W0.5), 50 (W3.8), 51 (W1.10), 56 (W2.2); 52–55, 57–67 ayrılmış ama kullanılmadı.
- Doğrulayıcı probe'ları ve logları: `/tmp/verify-<wp>/` (geçici makinede; oturum kapanınca silinir).

## 5. Önerilen sıradaki adım

1. FAIL alan 13 dal için düzeltme ajanları (bulgular yukarıda), ardından yeniden bağımsız doğrulama.
2. W2.4'ü önce düzelt/birleştir (W2.5/W2.7 ve W2.8 Revert ona bağlı), sonra W2.5, W2.7.
3. Birleştirme sırası çakışmaları: `core/compliance/__init__.py` (W3.5/W3.6), `core/quality/__init__.py` (W1.5), `schema.d.ts` her birleştirmeden sonra yeniden üretilmeli.
