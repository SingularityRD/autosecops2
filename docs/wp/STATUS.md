# AutoSecOps 2.0 — İş paketi durumu (14 Ekim 2026, akşam)

> Yeni oturumda devam etmek için önce `docs/wp/HANDOFF.md` (kurulum + başlangıç komutu), sonra bu dosya.
Hedef: düzenlenmiş sektör GA, 30 Ekim 2026 (31 Ekim tampon). Plan: `docs/wp/NORTHSTAR_PLAN.md`.
Süreç: her iş paketi (WP) kendi dalında (`wp/<id>-<slug>`) → yalnızca spec + diff gören bağımsız doğrulayıcı → PASS → `integration`'a merge → tam test + gates → `integration` ve `main` push.

**`main` == `integration` == `a72f686a`** (remote `target` = SingularityRD/autosecops2). Ürün sürümü **2.0.0** (`release_tool.py check-versions`); sürüm notları `docs/release/2.0.0.md` (54 dahil, 4 hariç: W0.8, W1.4, W2.9, W4.4). **`v2.0.0` etiketi yok.**

## 1. main'de (doğrulandı, birleşti)

Önceki turlar: W0.1–W0.7, W0.9–W0.14, W0.12b, W0.13 (dört inceleme), W1.1, W1.2/W1.3, W1.5–W1.10, W1.7b, W2.1–W2.8, W3.1–W3.5, W3.7–W3.9, W3.11, W4.1/W4.2, W4.3, W4.5.

14 Ekim (bu oturum), sırayla:

| WP | Sonuç | Not |
|---|---|---|
| W0.17 integration test düzeltmeleri | PASS (Normal) | approval-actions fixture, detection-rules route-matrix stand-in'leri, DB koruması (`tests/_db_guard.py`) |
| W0.16 onay argüman sınırları | PASS (Normal) | 64 KB üstü → 413 |
| W3.10 FIPS modu | PASS, tur 8 (Yüksek) | Bilinen boşluk: denetim checkpoint'i ve kanıt paketi yalnızca Ed25519 |
| W0.15 Redis kesintisinde çift triyaj | PASS, tur 2 (Yüksek) | backfill yanıtı çalıştırır; tablo yoksa eski davranış + alarm |
| W3.6 denetim dışa aktarımı (SIEM) | PASS, tur 12 (Yüksek) | Tek ortak key/value bulucu; serbest metin PII maskelemesi en-iyi-çaba (belgeli) |
| W4.6 ürün dokümantasyonu | PASS, tur 10 (Normal) | Taban `main` @ `b8795def`; metrik adları koda karşı test ediliyor |
| W0.18 GA takipleri | PASS (Yüksek: run durumu) | SQLSTATE-yalnız tablo tespiti, FIPS doküman girişi, 413'te run `failed`/`refused`, medic testi (root), liteparse exit-134, R29 geri yükleme mesajı |
| W0.20 doküman listesi kontrolü | PASS (Normal) | `merged_wps.txt` HEAD yerine belgelenen tabana karşı |
| W4.7 sürüm aracı / notlar / 2.0.0 | PASS, tur 9 (Yüksek) | SBOM, cosign anahtarsız imza, `allow_late` (birim testi toleranslı, etiket hattı katı) |

## 2. Dalda / sürmekte

| WP | Durum | Sıradaki adım |
|---|---|---|
| W0.19 GitHub CI yeşil | Sürüyor (`wp/w0.19-ci-green`) | `main`'de CI/CD Pipeline 165c5f1f'den beri kırmızı: Unit Tests – Backend (DB-backed) ve Security Scan – Python (Bandit) kesin; Backend/Integration teyit edilecek. Bu yüzden "Build/Scan Docker Images" hiç koşmadı. Doğrula → birleştir → notları yeniden üret (`render-notes --data docs/release/2.0.0.json --write`). |
| W1.4 prompt-injection seti | Spec taslağı `wp/w1.4-injection-set` | İnsan kararı (aşağı §3). |

## 3. GA kontrol listesi (sahibiyle)

| # | Madde | Sahip | Durum |
|---|---|---|---|
| 1 | `main`'de GitHub CI tamamen yeşil, imaj build + Trivy taraması koşmuş | Ajan (W0.19) | sürüyor |
| 2 | İnternetsiz kurulum temiz VM'de < 30 dk (Kapı C) | Ajan + insan (gerçek VM) | yapılmadı; bu makinede Docker var, `kind` ile simülasyon mümkün |
| 3 | Yük ve kaos SLO'ları son `main` üzerinde | Ajan | W4.1 birleşik; son taban üzerinde yeniden koşulmadı |
| 4 | Yüksek riskli WP'lerin ürün sahibi onayı: W1.7b (`/mcp` approve/reject kaldırıldı), W1.9 SSO, W4.5 DB yükseltme, W0.13 auth-api (CSRF), W0.12b spool, W0.15, W3.10, W3.6, W0.18, W4.7 | Ürün sahibi | kullanıcı 14 Ekim'de merge/push'u onayladı; ürün onayı ayrıca kaydedilmeli |
| 5 | Dış pentest (26 Ekim başlangıç) ön bulguları | İnsan | rezervasyon teyit edilmeli |
| 6 | W1.4: insan yazımı saldırı seti mi, mevcut v1 240 vaka mı | İnsan | karar bekliyor |
| 7 | Etiket koruması ruleset'leri (`scripts/release/rulesets/`) | Repo yöneticisi | uygulanmadı |
| 8 | `v2.0.0-rc.1` / `v2.0.0` etiketi ve sürüm iş akışının ilk gerçek koşusu | İnsan kararı | yapılmadı (yasak, onay gerekir) |
| 9 | Türkçe sürüm notlarının anadil okuması | İnsan | bekliyor |
| 10 | Doküman tabanını (`main` @ `b8795def`) GA öncesi son `main`'e taşı | Ajan | W0.20 bunu zorlamıyor (DÜŞÜK) |
| 11 | Katalog artifact'ı: iletişim yer tutucuları, "2.0 GA" rozetleri | İnsan/ajan | bekliyor |

## 4. Birleşmiş ama takip gerektiren (engelleyici değil)

- W0.18: run bitirmede kontrol-yazma yarışı (cancel arada gelirse `cancelled` → `failed`, sayaç iki kez); aynı desen cancel ve `/terminal`'de zaten var (ORTA). TS ajanı 413'ü yalnızca logluyor; sonra `/terminal` `abandoned` ile bitişi `cancelled`'a çevirebilir (DÜŞÜK). `/checkpoints` 413 run durumunu değiştirmiyor. `refused` için CHECK kısıtı yok.
- W4.7 notları: 64 KB maddesi yalnızca faz yolu için geçerli ("faz yolunda" denmeli); "yalnızca SQLSTATE" Postgres için (SQLite'ta metin yedeği). Sonraki notlar yenilemesinde düzelt.
- W3.6: belgelenmemiş serbest-metin biçimleri (ayırıcısız `diagnosis HIV`, tırnaklı alt simge varyantları dışındakiler) en-iyi-çaba; `d["password"]: str` aşırı maskeleme.
- W3.10: imzalar FIPS'te Ed25519 (ECDSA bağlantısı ayrı WP).
- W0.16: hedef anahtar adları uzunluk sınırsız; tek surrogate 500 (önceden vardı).
- W4.5, W1.9, W0.12b, W0.13 auth-api takipleri: önceki sürümdeki listeler geçerli (Helm `vigil_app` grant testi, `?sslpassword=` argv, SSO formu 403, spool başlık bozulması, `reset-setup.sh` CSRF).
- Bazı birim testleri `deeptempo_soc`'a satır yazıyor (`intake_triggers` `human_ask`), ayrı WP.

## 5. Uzak dal temizliği

Kullanıcı 14 Ekim'de birleşmiş `wp/*` dallarının silinmesini onayladı; bu oturumun git proxy'si silme push'larını 403 ile reddetti. 51 dal (tamamı `main`'in atası) elle silinmeli; açık işler (W1.4, W0.19) silinmez. Komut ve SHA listesi oturum notlarında; her dalın ucu `main` geçmişinde olduğundan kayıp yok.

## 6. Ortam notları

- Yeni makinede Postgres boş gelir: init SQL (`infra/database/init/*.sql`) → `scripts/init_schema.py` → init SQL tekrar → `scripts/seed_reference_data.py` (HANDOFF §1'e eklenmeli). Konteyner yeniden başlarsa `service postgresql start; service redis-server start`.
- `pytest-xdist` kurulu değil; tam test seri ~10 dk. Paralel ajanlar varken DB testleri (`test_medic_permissions_db`, `test_approval_action_lifecycle_db`, `test_finding_mitre_predictions_db`) çakışmadan düşebilir; tek başına geçer.
- Docker daemon elle başlatılabilir (`dockerd &`).
- **Asla `git stash`**, `pkill -f`, sır pushlama, force-push. Etiket/ruleset kullanıcı onayı ister.
