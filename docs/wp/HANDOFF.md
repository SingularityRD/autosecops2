# Devir teslim — yeni bir oturumda kaldığı yerden devam

Bu dosya, kota biterse veya oturum kapanırsa başka bir Claude oturumunun hiçbir bilgi kaybetmeden devam etmesi için yazıldı.
Her şeyin tek doğru kaynağı GitHub'daki `SingularityRD/autosecops2` reposudur. Makine geçicidir; yerel dosyalara güvenme.

## Durumun özeti (14 Ekim 2026)
- `main` == `integration` == `dd671b86`: doğrulanmış ~37/45 iş paketi (liste: `docs/wp/STATUS.md` §1).
- Bekleyen dallar, durumları ve sıradaki adımlar: `docs/wp/STATUS.md` §2 (W0.15, W0.16, W3.10, W3.6, W4.6, W4.7). Hepsi remote'ta pushlu.
- Plan: `docs/wp/NORTHSTAR_PLAN.md`. Hedef: düzenlenmiş sektör GA 30 Ekim 2026.
- Brief'ler: `docs/wp/briefs/ROUND3.md` (uygulayıcı/düzeltici kuralları), `VERIFY_ROUND2.md` (doğrulayıcı), `REVIEW.md` (commit-geçmişi incelemesi), `gates_env.sh`; kurallar `docs/wp/VERIFIER.md`, şablon `docs/wp/TEMPLATE.md`. `docs/wp/FIXES.md` eskidir (12 Ekim); güncel bulgular STATUS.md §2'de.

## 1. Ortamı kur (yeni makinede)
```bash
git clone https://github.com/SingularityRD/autosecops2 /root/vigil && cd /root/vigil
git remote rename origin target            # brief'ler remote adını 'target' varsayar
git fetch target '+refs/heads/*:refs/remotes/target/*'
git checkout -b integration target/integration
for b in $(git branch -r | grep 'target/wp/' | sed 's#target/##'); do git branch -f "$b" "target/$b"; done
./setup_dev.sh                              # venv (/root/vigil/venv), bağımlılıklar; Postgres + Redis gerekir
cp env.example .env                         # gerekli değerleri doldur; JWT_SECRET_KEY'i rastgele üret, ASLA commitleme
mkdir -p /root/wt/_briefs && cp docs/wp/briefs/* /root/wt/_briefs/
git worktree add /root/wt/integ integration
```
- Ajan (TS) testleri için: `AGENT_TEST_DATABASE_URL=postgres://test:test@localhost:5432/agent_test`.
- Testler: `source /root/wt/_briefs/gates_env.sh` sonra `PYTHONPATH=<worktree> python -m pytest ...`. Gates: `GATES_ENV_SH=/root/wt/_briefs/gates_env.sh scripts/wp/gates.sh --base integration` (yük altında `GATES_TIMEOUT=5400`).
- Her WP için ayrı worktree: `git worktree add /root/wt/<id> <dal>` (örn. `/root/wt/w24 wp/w2.4-executors-policy`).

## 2. Kurallar
- `pkill -f` kullanma. Sır (secret) commitleme/pushlama. Log dosyalarına benzersiz adlar ver (ajanlar ortak dizini paylaşıyor).
- Commit trailer'ları: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` ve çalışan oturumun `Claude-Session:` satırı.
- Her iş: uygulayıcı ajan → yalnızca spec + diff gören AYRI doğrulayıcı → PASS ise integration'a merge → push.
- Her merge'den sonra: `python -m tests.security.route_matrix --write`, `cd clients/web && npm run generate:api`, gerekirse `python scripts/generate_schema_snapshot.py`; `tests/airgap` yeni dış çağrı bulursa `tests/airgap/egress_inventory.json`'da sınıflandır.
- `git stash` KULLANMA (worktree'ler stash listesini paylaşır).
- Aynı anda en fazla 20 ajan; 2 CPU'lu makinede 15–20 iyi, test zaman aşımları normal.
- Ajan çalışırken kullanıcı mesaj gönderirse parti kesilebilir; kesilen işler worktree'de commitsiz kalır — yeni ajana "worktree'deki yarım işi incele ve devam et" de.

## 3. Yeni oturuma yapıştırılacak başlangıç komutu
> SingularityRD/autosecops2 reposunu ekle, `integration` dalındaki `docs/wp/HANDOFF.md`'yi oku ve §1 kurulumunu yap (`cp docs/wp/briefs/* /root/wt/_briefs/`). Sonra `docs/wp/STATUS.md` §2 ve §5'teki sırayla devam et: W0.16 ve W3.10 için `docs/wp/briefs/VERIFY_ROUND2.md` ile bağımsız doğrulayıcı; W0.15 (yanıt değerlendirmesi kaybı + tablo yoksa backfill durması) ve W3.6 (CEF kesmesi, anahtar-adı maskeleme boşlukları, olay başına iş bütçesi) için düzeltici — her düzeltici önce `git merge integration`, `docs/wp/briefs/ROUND3.md` kurallarına uyar. PASS olanları integration'a birleştir, üretilen dosyaları yenile (route matrix, schema.d.ts, şema snapshot, egress envanteri), tam test + gates, `integration` ve `main`'e pushla. En son W4.6 (merged_wps.txt + taban commit) ve W4.7 (`render-notes --write`) güncellenip birleşsin. Her tur sonunda `docs/wp/STATUS.md`'yi güncelle, commitle, pushla. Subagent'larla paralel çalış (2 CPU'da 6–8 makul). `git stash` ve `pkill -f` yasak; sır pushlama; force-push yok; v2.0.0 tag'i ve ruleset yok; uzak dal silmek kullanıcı onayı ister.

## 4. İlerlemeyi kayıpsız tutmak için (her oturum uygulamalı)
- Her ajan işini commitleyip dalını HEMEN pushlasın (yerel commit makineyle birlikte kaybolabilir).
- Her doğrulama raporunun özünü `docs/wp/FIXES.md`'ye (FAIL) veya `STATUS.md`'ye (PASS) ekle ve pushla — rapor sadece sohbette kalmasın.
- Tur bitince `STATUS.md`'yi güncelle: "son güncelleme" tarihi, birleşenler, kalanlar, sıradaki adım.
