# AutoSecOps 2.0 — İş paketi durumu (14 Ekim 2026, 12:40 TSİ)

> Yeni oturumda devam etmek için önce `docs/wp/HANDOFF.md` (kurulum + başlangıç komutu), sonra bu dosya.
Hedef: düzenlenmiş sektör GA, 30 Ekim 2026 (31 Ekim tampon). Plan: `docs/wp/NORTHSTAR_PLAN.md`.
Süreç: her iş paketi (WP) kendi dalında (`wp/<id>-<slug>`) → yalnızca spec + diff gören bağımsız doğrulayıcı → PASS → `integration`'a merge → tam test + gates → `integration` ve `main` push.

**`main` == `integration` == `dd671b86`** (remote `target` = SingularityRD/autosecops2). Bu commit'te gates `RESULT: PASS`; `tests/unit tests/security tests/airgap` + şema snapshot testi geçiyor (xdist altında `test_medic_permissions_db` ve `test_support_bundle` zaman aşımı flake'leri; tek başına geçiyorlar).

## 1. main'de (doğrulandı, birleşti) — 45 paketten ~37

W0.1–W0.7, W0.9, W0.10, W0.11 (güvenlik hotfix: detection-rules git/SSRF, Viewer yazma rotaları), W0.12 (kalıcı alım kuyruğu), W0.12b (spool sertleştirme), W0.13 commit-geçmişi incelemeleri (triyaj, data-infra-ci, response-integrations, auth-api — dördü de), W0.14 (tur-9 takipleri), W1.1, W1.2/W1.3, W1.5, W1.6, W1.7, W1.7b (modeller onay veremez; `/mcp` `approve_action`/`reject_action` kaldırıldı — CHANGELOG'da BREAKING notu var), W1.8, W1.9 (OIDC SSO), W1.10 (denetim zinciri + imzalı checkpoint), W2.1–W2.8, W3.1, W3.2, W3.3, W3.4, W3.5, W3.7, W3.8, W3.9, W3.11, W4.1/W4.2, W4.3, W4.5 (0.7.1 → 2.0 yükseltme yolu).

## 2. Dalda bekleyenler (hepsi remote'ta pushlu) — sıradaki iş

| WP | Dal @ uç | Durum | Sıradaki adım |
|---|---|---|---|
| W0.15 Redis kesintisinde çift triyaj | wp/w0.15-redis-restart-retriage @ 131790e7 | Doğrulama **PASS**, birleşmedi | **Önce düzelt (önerilen):** (1) ORTA — karar kaydı ile `ai_enrichment` yazımı arasında daemon ölürse backfill kararı yazıp `_evaluate_for_response`'u hiç çalıştırmıyor (yanıt en-az-bir'den en-çok-bir'e düştü; processor.py ~1018/1037, `_persist_settled` ~1241) → backfill yerleşik kararda da yanıt değerlendirmesini çalıştırmalı (idempotent). (2) ORTA — `alert_lane_decisions` hiç okunamazsa (56_*.sql yok) tüm backfill kalıcı durur (~1216-1223) → tablo yoksa eski davranışa düş + uyarı/alarm. (3) DÜŞÜK — en eski karar kazanıyor (decision_store.py:94); spool replay yolu (processor.py ~842) `_drop_settled` kontrolü yapmıyor. Merge çakışması: processor.py `__init__` alanları — iki tarafı da tut. |
| W0.16 Onay argüman sınırları | wp/w0.16-approval-args-bounds @ efc2312a | Düzeltildi, gates PASS, **doğrulama bekliyor** | `docs/wp/briefs/VERIFY_ROUND2.md` ile bağımsız doğrulayıcı. Açık risk: 64 KB üstü çağrı park edilmeyince run onaysız beklemede kalıyor (yalnızca faz satırında sebep). |
| W3.10 FIPS modu | wp/w3.10-fips @ 1a93ae96 | Tur 7 düzeltildi (merge çakışması, ratchet açıkları, CHANGELOG), gates PASS, **doğrulama bekliyor** | Doğrulayıcı. İnsan kabulü gerekli: FIPS_MODE'da denetim checkpoint'i ve kanıt paketi hâlâ yalnızca Ed25519 (bilinen boşluk, `docs/fips.md`); sıfırlama bağlantıları yükseltmede geçersizleşiyor. |
| W3.6 Denetim dışa aktarımı (SIEM) | wp/w3.6-audit-export @ aa828df7 | Doğrulama **FAIL** (tur 6) | Tur 7 düzeltici (kullanıcı son denemeyi durdurdu, yeniden başlatılmadı): önce `git merge integration` (users.py çakışması: iki import, `before = ...` ve 4'lü dönüş `old_email` tut; route matrix + `generate:api`). (a) ORTA — `format_cef` `max_details=1024` (audit_export.py ~2507/2521) checkpoint imza/açık anahtarını kesiyor → checkpoint alanları kesilmeyen ayrı CEF uzantıları, kesilirse yapısal bayrak. (b) ORTA — anahtar adına göre maskeleme boşlukları: `*_key`/`primaryKey`/`kek`/`dek`/`*_seed`/`recovery_code`/`jdbc_url`…, KKV anahtarları (`bank_account`, `vkn`, `tckn`, `health`, `religion`…). (c) DÜŞÜK-ORTA — olay başına toplam iş bütçesi (16 MB olay 210 sn). CHANGELOG'a CGNAT/`LLM_PROVIDER_ALLOWED_CIDRS` notu. |
| W4.6 Ürün dokümantasyonu | wp/w4.6-docs @ 7463d573 | Tur 7 düzeltildi (7a22e8b6'ya göre), doğrulanmadı | **En son birleşecek.** Birleşmeden önce `integration`'ı merge et, `tests/unit/docs/merged_wps.txt` ve belgelerdeki taban commit'i güncelle (W1.9, W0.12b, W0.13 auth-api, W0.14 ve sonra birleşenler), sonra doğrulayıcı. Kodda kalan: R29 geri yükleme mesajı (`core/backup/restore.py`). |
| W4.7 Sürüm aracı / notlar | wp/w4.7-release @ a020228c | Doğrulama FAIL — yalnızca notlar bayat | **En son birleşecek.** `git merge integration` → `render-notes --write` → commit; aksi halde `test_release_notes_*` main'i kırar. Her yeni WP merge'ünden sonra notlar yeniden üretilmeli (veya bu iki test yalnızca tag pipeline'ında koşmalı — karar ver). Düşük: W1.9 vurgu/yükseltme notu yok; W0.13 metninde "auth-api birleşmedi" sabit; git dışı çalışmada traceback. Asla `v2.0.0` tag'i oluşturma, ruleset uygulama. |

## 3. Başlanmadı / insan kararı

- **W1.4** (prompt-injection değerlendirme seti): saldırı metni yazımı güvenlik sınıflandırıcısına takıldı → insan yazmalı veya mevcut v1 240 vakalık set kullanılmalı.
- **W0.8**, **W4.4** (dış pentest): insan/dış iş. **W2.9**: isteğe bağlı.
- **Uzak dal silme**: birleşmiş `wp/*` dallarını remote'tan silmek kullanıcı onayı bekliyor (izin sınıflandırıcısı engelledi). Yerel temizlik yapıldı.
- **İnsan onayı**: main'e giren tüm Yüksek riskli WP'ler (özellikle W1.7b `/mcp` araç kaldırma, W0.13 auth-api ile Helm'de CSRF zorlaması `VIGIL_CSRF_REPORT_ONLY=false`, W0.12b spool disk biçimi, W4.5 DB yükseltme, W1.9 SSO/RBAC) için ürün sahibinin onayı alınmalı.

## 4. Birleşmiş ama takip gerektiren (engelleyici değil)

- W4.5: Helm yolunda `vigil_app` grant'leri testte kapsanmıyor (Orta); `?sslpassword=` argv'de; ürün sürümü hâlâ 0.7.1 (sürüm bump'ı W4.7 ile); postgres imajı digest'e sabitlenmemiş.
- W1.9: çok worker'lı kurulumda eski ortam değeri 409'a yol açabilir (güvenli tarafta); Manager SSO formunu görüp kaydederken 403 alıyor (UI'da gizlenmeli); IdP grup değişikliği son SSO-Admin'i düşürebilir (belgelendi).
- W0.12b: başlık bozuk + taşınamayan segment hâlâ spool'u kapatıyor (spool.py:333); `.done` eklemesi `O_NOFOLLOW`'suz; sayısal `external_id` lookup hatası → dead/.
- W0.13 auth-api: `test_service_account_reset_confirm_is_refused` düzeltme olmadan da geçiyor (güçlendirilmeli); `scripts/reset-setup.sh` CSRF zorlamalı Helm'de kırılıyor.
- W0.11/W0.14: `.git` dosyası ile başka repoya yönlenme → W0.16'da kapatıldı (doğrulanınca).
- Katalog (Claude Design artifact'ı, özel): https://claude.ai/artifact/1WrkQHpuahMWgiZTnREMWY — iletişim yer tutucuları ([E-POSTA ADRESİ], [TELEFON], [WEB ADRESİ]) ve "2.0 GA" rozetleri (SSO, otonomi katmanları, imzalı zincir, kanıt paketi, yerel model artık main'de) güncellenmeli.

## 5. Önerilen sıra

1. W0.16 ve W3.10 doğrulayıcıları (paralel) + W0.15 tur-2 düzeltici + W3.6 tur-7 düzeltici.
2. PASS olanları birleştir: W0.16 → W3.10 → W0.15 → W3.6. Her merge sonrası: `python -m tests.security.route_matrix --write`, `cd clients/web && npm run generate:api`, gerekirse `python scripts/generate_schema_snapshot.py`, `tests/airgap` (yeni dış çağrıları `egress_inventory.json`'da sınıflandır), tam test + gates, push.
3. En son W4.6 ve W4.7'yi `integration` ile güncelle (merged_wps.txt, taban commit, `render-notes --write`), doğrula, birleştir.
4. Sürüm: sürüm bump'ı ve GA kontrol listesi (W4.7 spec'i), insan onayları, W1.4 kararı.

## 6. Ortam notları

- Makine yeniden başlarsa: `pg_ctlcluster 16 main start; redis-server --daemonize yes`.
- `gates_env.sh` (`docs/wp/briefs/`) `.env`'deki `DAEMON_AUTO_TRIAGE`'ı kaldırır, `DEMO_MODE=false`, `MCP_AUTO_CONNECT_ON_STARTUP=false`.
- Tam test: `source /root/wt/_briefs/gates_env.sh; PYTHONPATH=<wt> python -m pytest tests/unit tests/security tests/airgap tests/integration/test_schema_snapshot.py -q -p no:cacheprovider -n 4 --no-cov`.
- Init SQL main'de: 46–51, 55, 56, 58, 61 (values.yaml sırası ve Helm kopyaları eşit tutulmalı).
- **Asla `git stash` kullanma** (worktree'ler ortak stash listesi paylaşıyor; bir kez iki ajanın işi karıştı). `pkill -f` kullanma. Sır pushlama. Force-push yok.
- Doğrulayıcı probe/logları `/tmp/verify-*` altında (geçici makine).
