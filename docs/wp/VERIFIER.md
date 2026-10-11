# WP Verifier

Bir iş paketini (WP) birleştirmeden önce, onu yazmamış bağımsız bir doğrulayıcı
(verifier) kontrol eder. Bu dosya hem insan için kontrol listesi hem de bir
doğrulayıcı ajana verilecek istem (prompt) şablonudur.

## Ground rules

1. **Doğrulayıcı yalnızca iki şey görür: spec ve diff.** Spec =
   `docs/wp/<ID>.md`; diff = `git diff <merge-base>..<branch>`. Uygulayıcının
   raporu, sohbet geçmişi, "şunu da yaptım" notları doğrulayıcıya **verilmez**.
   Spec'teki `Evidence` bölümü de kanıt sayılmaz; yalnızca karşılaştırma içindir.
2. **İddiaya değil, yeniden çalıştırmaya güvenilir.** Her kabul kriteri komutu
   doğrulayıcı tarafından WP worktree'sinde yeniden çalıştırılır.
3. **Doğrulayıcı kodu düzeltmez.** Yalnızca PASS/FAIL ve kanıt üretir. Düzeltme
   uygulayıcıya geri gider; dal (branch) değişirse doğrulama baştan yapılır.
4. Doğrulayıcı uygulayıcıyla aynı ajan/oturum olamaz.
5. Süreçleri adla öldürmeyin (`pkill -f` yasak); başka ajanların süreçleri aynı
   makinede çalışır. Takılan komut için `timeout` kullanın.

## Preparing the input (orchestrator)

```bash
ID=w0.5; BR=wp/w0.5-example; WT=/root/wt/$ID
MB=$(git -C "$WT" merge-base target/main "$BR")
git -C "$WT" show "$BR:docs/wp/$ID.md"            > /tmp/$ID.spec.md
git -C "$WT" diff --stat "$MB" "$BR"              > /tmp/$ID.diff
git -C "$WT" diff "$MB" "$BR"                    >> /tmp/$ID.diff
```

Doğrulayıcıya `/tmp/$ID.spec.md`, `/tmp/$ID.diff`, worktree yolu `$WT` ve aşağıdaki
istem verilir. Başka hiçbir şey verilmez.

## Checklist

Her madde için sonuç `ok` / `FAIL` / `n/a` ve kısa kanıt (komut + çıktı satırı,
veya `dosya:satır`) yazılır. Tek bir `FAIL` → genel sonuç FAIL.

### A. Acceptance (yeniden çalıştırma)

- [ ] A1. Spec'teki her AC komutu worktree kökünden birebir çalıştırıldı;
      çıkış kodu ve beklenen çıktı eşleşiyor.
- [ ] A2. `scripts/wp/gates.sh <worktree>` → çıkış kodu 0. Özet satırları kanıta eklenir.
- [ ] A3. AC'ler gerçekten `Goal`'u ölçüyor (her zaman geçen, boş veya
      `|| true` ile yutulmuş bir komut değil).
- [ ] A4. Çalışma ağacı temiz: `git -C <wt> status --porcelain` boş (commit
      edilmemiş değişiklikle doğrulama yapılmaz).

### B. Scope

- [ ] B1. `git diff --name-only <mb> <branch>` içindeki her dosya `Allowed files`
      ile eşleşiyor ve hiçbiri `Forbidden files` ile eşleşmiyor.
- [ ] B2. Diff `Goal` dışında iş içermiyor: ilgisiz yeniden adlandırma,
      biçimlendirme dalgası, "fırsat bulmuşken" düzeltme, yeni özellik.
- [ ] B3. `Contracts` tablosunda olmayan bir arayüz değişikliği yok (HTTP yolu /
      şeması, env değişkeni, CLI bayrağı, DB kolonu, kuyruk/olay adı).
- [ ] B4. Yeni bağımlılık / lockfile değişikliği yok (spec açıkça izin vermedikçe).

### C. Tests

- [ ] C1. Hiçbir test silinmemiş, `skip`/`xfail`/`.only`/`.skip`/`it.todo`
      eklenmemiş, timeout büyütülmemiş, assert gevşetilmemiş (ör. `==` → `in`,
      tam eşitlik → `toBeTruthy`, beklenen hata türü genişletilmiş).
      Kontrol: `git diff <mb> <branch> -- '*test*' | grep -nE '^-.*(assert|expect)|skip|xfail|\.only|todo'`
- [ ] C2. Ratchet'ler (`tests/unit/_ratchets/`) ve izin listeleri (allowlist)
      genişletilmemiş.
- [ ] C3. Davranış değişikliği yeni/güncellenmiş bir testle örtülü; test,
      değişiklik geri alınınca başarısız olur (şüphe varsa: değişikliği geçici
      olarak geri alıp testi çalıştırın, sonra `git checkout -- .`).

### D. Security

- [ ] D1. Gizli bilgi yok: anahtar, token, parola, `.env` içeriği, gerçek
      müşteri verisi. Kontrol: `git diff <mb> <branch> | grep -nEi '(api[_-]?key|secret|password|token|BEGIN [A-Z ]*PRIVATE KEY)'`
      — her eşleşme açıklanmalı.
- [ ] D2. Yetki denetimi atlanmamış / gevşetilmemiş (`DEV_MODE`, yetki
      dekoratörleri, RBAC izinleri, kimlik doğrulama bağımlılıkları).
- [ ] D3. Girdi doğrulaması: SQL birleştirme (string concat), `shell=True`,
      `eval`, yol geçişi (path traversal), doğrulanmamış URL'ye istek (SSRF),
      TLS doğrulamasını kapatma yok.
- [ ] D4. Hata yanıtlarında istisna metni / iç ayrıntı sızmıyor; loglarda gizli
      bilgi yok.
- [ ] D5. LLM'e giden içerik: güvenilmeyen veri talimat olarak istem içine
      karıştırılmıyor; araç (tool) izinleri genişletilmemiş.
- [ ] D6. `Risk: Yüksek` ise: yukarıdakilerin her biri ayrıntılı kanıtla
      yazılır ve sonuç PASS olsa bile birleştirme için insan onayı gerekir
      (`HUMAN-APPROVAL: required`).

### E. User-visible wording

- [ ] E1. Kullanıcıya görünen her yeni/değişen metin (UI metni, API hata mesajı,
      e-posta/bildirim, CLI çıktısı, belge başlığı) ürün adını **AutoSecOps**
      olarak yazar. Diff'e **eklenen** satırlarda kullanıcıya görünen "Vigil"
      → FAIL. Kontrol: `git diff <mb> <branch> | grep -nE '^\+.*\bVigil\b'`
      İç tanımlayıcılar (paket adı `@vigil/agent`, Python modül yolu, env değişkeni,
      Docker servis adı, upstream'e atıf yapan FORK.md) kapsam dışıdır.
- [ ] E2. Kullanıcıya görünen metin doğru durumu söylüyor (başarısızlık
      "başarılı/yapılandırıldı" olarak gösterilmiyor).

## Output format

Doğrulayıcının çıktısı tam olarak bu biçimdedir (araçlar ilk satırı okur):

```
VERDICT: PASS | FAIL
WP: <ID>  BRANCH: <branch>  HEAD: <sha>  MERGE-BASE: <sha>
RISK: Normal | Yüksek   HUMAN-APPROVAL: not-required | required

FAILURES:            (PASS ise "none")
- <madde no> <tek cümle> — <kanıt: dosya:satır veya komut + çıktı>

EVIDENCE:
- A1 AC1 `<komut>` → exit 0; "<anahtar çıktı satırı>"
- A2 gates → "<özet satırları>"
- B1 files: <n> changed, all within Allowed
- C1 ...
- D1 ...
- E1 ...
```

## Recording the verdict

PASS sonrası orkestratör sonucu dalın **o anki tepe commit'ine** git notu olarak
yazar. `scripts/wp/merge-train.sh` notu olmayan dalı birleştirmez; dal sonradan
değişirse tepe commit değişir ve not geçersiz kalır (yeniden doğrulama gerekir).

```bash
git notes --ref=wp-verify add -f -F /tmp/$ID.verdict "$BR"   # ilk satır "VERDICT: PASS"
git notes --ref=wp-verify show "$BR" | head -1
```

## Prompt template

Aşağıdaki metni `{{...}}` alanlarını doldurarak doğrulayıcı ajana verin.

````text
You are the independent verifier for work package {{ID}} of AutoSecOps (a hard
fork of Vigil). You did not write this change. You are given exactly two inputs:

  SPEC: {{SPEC_PATH}}
  DIFF: {{DIFF_PATH}}
  WORKTREE (read-only for you; run commands here): {{WORKTREE}}
  BRANCH: {{BRANCH}}   MERGE-BASE: {{MERGE_BASE}}

You must not read or ask for the implementer's report, notes or conversation;
the SPEC's "Evidence" section is a claim, not evidence. Judge only the SPEC
against the DIFF, and the results of commands you run yourself.

Do this, in order:
1. Confirm `git -C {{WORKTREE}} status --porcelain` is empty and HEAD is the
   branch tip you were given. If not: VERDICT: FAIL (A4).
2. Re-run every Acceptance criteria command from the worktree root, exactly as
   written, and compare with "Expected". Then run `scripts/wp/gates.sh {{WORKTREE}}`.
   Wrap long commands in `timeout`; never use `pkill -f` or kill processes you
   did not start.
3. Walk the checklist in docs/wp/VERIFIER.md sections A–E (scope vs Allowed /
   Forbidden files and Contracts; weakened, skipped or deleted tests and
   ratchets; secrets, auth bypass, injection, TLS, error-text leaks, LLM prompt
   surface; user-visible wording must say "AutoSecOps", never "Vigil").
4. Do not modify, commit, or fix anything. If you temporarily revert code to
   test C3, restore it with `git checkout -- .` before you finish.

Answer in exactly the output format from docs/wp/VERIFIER.md ("VERDICT: PASS"
or "VERDICT: FAIL" on the first line). Every FAIL needs concrete evidence
(file:line, or command + output). If you cannot run a command, that criterion
is FAIL, not PASS. For Risk: Yüksek, set HUMAN-APPROVAL: required.
````
