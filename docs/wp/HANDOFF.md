# Devir teslim — yeni bir oturumda kaldığı yerden devam

Bu dosya, kota biterse veya oturum kapanırsa başka bir Claude oturumunun hiçbir bilgi kaybetmeden devam etmesi için yazıldı.
Her şeyin tek doğru kaynağı GitHub'daki `SingularityRD/autosecops2` reposudur. Makine geçicidir; yerel dosyalara güvenme.

## Durumun özeti
- `integration` dalı: doğrulamadan geçmiş tüm işler (bkz. `docs/wp/STATUS.md` §1).
- `wp/*` dalları: her iş paketi kendi dalında, hepsi remote'ta. Doğrulamada kalan 13 dal ve bulguları: `docs/wp/FIXES.md`.
- `main`: henüz integration'ı almadı (integration'da tam test koşusu yapılmadan main'e alınmayacak).
- Plan: `docs/wp/NORTHSTAR_PLAN.md` (Claude Docs'taki "AutoSecOps 2.0 Northstar uygulama planı"nın kopyası). Hedef: düzenlenmiş sektör GA 30 Ekim 2026.
- Görev tanımları (brief'ler): `docs/wp/briefs/<id>_impl.txt`, doğrulayıcı brief'leri `<id>_verify.txt`, genel doğrulayıcı: `VERIFY_ROUND2.md`, kurallar: `docs/wp/VERIFIER.md`, şablon: `docs/wp/TEMPLATE.md`.

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
- Her merge'den sonra `schema.d.ts` çakışırsa `cd clients/web && npm run generate:api`.
- Aynı anda en fazla 20 ajan; 2 CPU'lu makinede 15–20 iyi, test zaman aşımları normal.
- Ajan çalışırken kullanıcı mesaj gönderirse parti kesilebilir; kesilen işler worktree'de commitsiz kalır — yeni ajana "worktree'deki yarım işi incele ve devam et" de.

## 3. Yeni oturuma yapıştırılacak başlangıç komutu
> SingularityRD/autosecops2 reposunu ekle ve `integration` dalındaki `docs/wp/HANDOFF.md` dosyasını oku, §1'deki kurulumu yap. Sonra `docs/wp/FIXES.md`'deki 13 kalan iş paketini subagent'larla düzelt (her biri kendi `wp/*` dalında, önce `git merge integration`), W2.4'ü öncelikli al. Her düzeltmeden sonra `docs/wp/briefs/VERIFY_ROUND2.md` ile ayrı bir doğrulayıcı koştur; PASS olanları integration'a merge et ve pushla. Sonra `docs/wp/STATUS.md` §3'teki başlanmamış paketlere (W2.3, W3.1, W3.2, W3.7, Dalga 4) plan dokümanına göre brief yazıp aynı döngüyle devam et. Her turun sonunda `docs/wp/STATUS.md`'yi güncelle, commitle, pushla. Her şeye izin var; 15–20 subagent paralel kullan.

## 4. İlerlemeyi kayıpsız tutmak için (her oturum uygulamalı)
- Her ajan işini commitleyip dalını HEMEN pushlasın (yerel commit makineyle birlikte kaybolabilir).
- Her doğrulama raporunun özünü `docs/wp/FIXES.md`'ye (FAIL) veya `STATUS.md`'ye (PASS) ekle ve pushla — rapor sadece sohbette kalmasın.
- Tur bitince `STATUS.md`'yi güncelle: "son güncelleme" tarihi, birleşenler, kalanlar, sıradaki adım.
