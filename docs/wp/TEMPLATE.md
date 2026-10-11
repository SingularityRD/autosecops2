# WP {{ID}} — {{TITLE}}

<!--
Bu dosya bir iş paketinin (work package, WP) sözleşmesidir. Uygulayıcı (implementer)
yalnızca burada yazanı yapar; doğrulayıcı (verifier) yalnızca bu dosyayı ve diff'i
görür (bkz. docs/wp/VERIFIER.md). Bu yüzden her şey bu dosyada yazılı olmalı:
"konuşmada söylemiştim" doğrulayıcıya ulaşmaz.

Anahtarlar (ID, Goal, ...) İngilizce kalır; araçlar ve doğrulayıcı istemi onları
arar. Açıklamalar Türkçe yazılır. Doldurduktan sonra yorum (HTML comment) yönergelerini silin.
Oluşturma: scripts/wp/new.sh <id> <slug>
-->

| Key | Value |
|---|---|
| ID | {{ID}} |
| Branch | `{{BRANCH}}` |
| Base | `target/main` @ `{{BASE_SHA}}` |
| Worktree | `{{WORKTREE}}` |
| Risk | Normal <!-- Normal \| Yüksek --> |
| Owner | <!-- uygulayıcı ajan / kişi --> |
| Depends-on | <!-- önce birleşmesi gereken WP ID'leri, yoksa "—" --> |

## Goal

<!-- Tek paragraf: bu WP bittiğinde kullanıcı / operatör ne görür, ne değişir?
Ölçülebilir yazın. "X'i iyileştir" değil, "X artık Y durumunda Z döndürür". -->

## Non-goals

<!-- Bilerek yapılmayacak olanlar. Kapsam kaymasını (scope creep) doğrulayıcı buna
göre ölçer. -->

-

## Allowed files

<!-- Değiştirilmesine / eklenmesine izin verilen yollar (glob olabilir). Diff'te
burada eşleşmeyen her dosya doğrulayıcı için FAIL sebebidir. Bu spec dosyasının
kendisi (docs/wp/{{ID}}.md) her zaman izinlidir. -->

- `docs/wp/{{ID}}.md`
-

## Forbidden files

<!-- Dokunulmaması gerekenler; "Allowed" ile çakışırsa bu liste kazanır. Aşağıdaki
varsayılanları yalnızca gerekçe yazarak kaldırın. -->

- `infra/database/init/**` (şema değişikliği → Risk: Yüksek ve ayrı WP)
- `.github/workflows/**`
- `requirements*.txt`, `requirements.lock`, `**/package-lock.json` (bağımlılık değişikliği)
- `tests/unit/_ratchets/**` (ratchet gevşetmek yasak; sıkılaştırmak ayrı WP)
- Diğer WP'lerin spec dosyaları (`docs/wp/*.md`, bu dosya hariç)

## Contracts

<!-- Bu WP'nin bozmaması gereken ve/veya yeni sunduğu arayüzler: HTTP yolları ve
şemaları, CLI bayrakları, ortam değişkenleri, DB kolonları, olay/kuyruk adları,
dosya biçimleri. Her biri için: önce → sonra, ve kimin tükettiği. Değişmiyorsa
"değişmez" yazın; doğrulayıcı diff'te sessiz bir sözleşme değişikliği arar. -->

| Contract | Before | After | Consumers |
|---|---|---|---|
| | | | |

## Acceptance criteria

<!-- Her kriter, çalıştırılabilir bir komut ve beklenen sonuçtur. Doğrulayıcı
bunları birebir yeniden çalıştırır. Komutlar worktree kökünden, etkileşimsiz
çalışmalı; sabit /root/vigil yolu yerine göreli yol kullanın.
"Manuel kontrol" yalnızca komutla ifade edilemiyorsa ve neye bakılacağı kesin
yazılmışsa kabul edilir. -->

| # | Criterion | Command | Expected |
|---|---|---|---|
| AC1 | Kapı kontrolleri geçer | `scripts/wp/gates.sh` | çıkış kodu 0, `RESULT: PASS` |
| AC2 | | | |

## Evidence

<!-- Uygulayıcı, bitirdiğinde buraya kanıtı ekler: her AC için komutun son
satırları (kısaltılmış çıktı), commit SHA'ları. Doğrulayıcı bu bölüme güvenmez,
komutları yeniden çalıştırır; bu bölüm yalnızca karşılaştırma içindir. -->

- Commit(s):
- AC1:

## Risk

<!-- Normal: geri alınabilir, yalnızca izinli dosyalarda, güvenlik sınırına dokunmaz.
Yüksek: aşağıdakilerden biri varsa — doğrulayıcı ek kontrol yapar ve birleştirme
için insan onayı gerekir:
  - kimlik doğrulama / yetkilendirme / RBAC, gizli anahtar (secret) işleme
  - DB şeması veya veri göçü (migration)
  - müdahale (response) eylemleri: host izolasyonu, hesap kilitleme, engelleme
  - LLM'e giden veri, istem (prompt) enjeksiyonu yüzeyi, dış ağ çıkışı (egress)
  - bağımlılık ekleme / yükseltme, CI değişikliği
Seçilen seviyenin gerekçesini bir cümleyle yazın. -->

- Tier: Normal
- Rationale:
- Rollback: `git revert -m 1 <merge-sha>`

## Notes for the implementer

<!-- İsteğe bağlı: ipuçları, ilgili dosyalar, bilinen tuzaklar. Kullanıcıya görünen
her metin ürün adını **AutoSecOps** olarak yazar ("Vigil" değil). -->
