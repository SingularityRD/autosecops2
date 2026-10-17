# Analist kılavuzu

> **English summary.** The SOC analyst's day in AutoSecOps: the triage queue and
> the AI verdict (what it cites and who wrote each field), working a case
> (comments, evidence, related cases, escalation, the report PDF, the evidence
> pack, regulatory clocks), approving or rejecting response actions, reviewing
> AI decisions for the Scorecard, and lessons. Administration is in the
> administrator guide.

Bu kılavuz konsolu her gün kullanan analist içindir. Kurulum, roller ve ayarlar
[yönetici kılavuzundadır](yonetici-kilavuzu.md).

## 1. Temel ilke: AI önerir, insan karar verir

- AI her alarmı triyaj eder ve bir karar önerir; müdahale eylemleri (konak izolasyonu,
  IP engeli, hesap kapatma) **varsayılan olarak her zaman bir insanın onayını bekler**
  (Assist). Kapsamlı müdahaleler (izolasyon, hesap kapatma, güvenlik duvarı engeli)
  hiçbir otonomi katmanında kendiliğinden uygulanmaz.
- Hiçbir model bir eylemi onaylayamaz ya da reddedemez; onay yalnızca konsoldan, sizin
  oturumunuzla verilir.
- Yazdığınız her yorum, kanıt ve ilişki sizin oturumunuzla kaydedilir; başka bir ad
  yazılamaz.

## 2. Triyaj kuyruğu (Triage queue)

Gelen her alarm ve triyajın onunla ne yaptığı burada görünür.

- **AI verdict** sütunu: Malicious / Benign / Inconclusive ve güven yüzdesi. "Triage
  failed" triyajın çalışmadığını, "Unreadable" saklanan kararın sözleşmeye uymadığını
  söyler; ikisinde de kararı siz verin.
- Satırı açınca kararın dayanağı görünür:
  - **What it cites:** kararın dayandığı alanlar ve her birini kimin yazdığı:
    *from the sensor* (ürünün kendisinin gözlediği, ör. IP adresi, dosya özeti),
    *attacker-controlled* (adı birinin seçtiği her şey: ana makine ve kullanıcı adı,
    başlık, açıklama, komut satırı), *third party*. Bu etiketleri model değil
    AutoSecOps koddan belirler. Zararsız (benign) karar en az bir sensör alanına
    dayanmak zorundadır; dayanmıyorsa "belirsiz"e düşürülür.
  - **What it could not see:** kararı verirken eksik kalanlar.
  - **Recommended action:** önerilen eylem; her zaman onay ister.
- **Grouped into, and why** sütunu alarmın hangi vakaya katıldığını gösterir.

Aynı kararı bulgu penceresinde (Dashboard'dan bir bulguya tıklayınca) de görürsünüz.

## 3. Vaka üzerinde çalışmak (Cases)

- **Yorumlar ve kanıt:** yazarı sizsiniz; kanıtın gözetim zinciri kaydedilir.
- **İlişkili vakalar ve yükseltme:** ilişkiyi oluşturan ve yükselten, oturumdaki
  kullanıcıdır.
- **Eylem zaman çizelgesi:** vaka için önerilen, onaylanan, uygulanan ve geri alınan
  eylemler; bir geri alma, geri aldığı eylemin yanında görünür.
- **Download report (PDF):** vaka sayfasındaki ⋯ menüsünden; Türkçe karakterler doğru
  basılır, her indirme denetim kaydına yazılır.
- **Evidence pack:** vakanın imzalı kanıt paketi (ZIP). AutoSecOps olmadan da
  doğrulanabilir; denetçiye ya da düzenleyiciye bunu verin.
- **Düzenleyici sayaçlar:** DORA, NIS2, KVKK, BDDK ve USOM sekmeleri. Farkına varma
  anını ve bildirim anlarını kaydettiğinizde sayaçlar çalışır (ör. KVKK Kurul
  bildirimi farkına varmadan sonra 72 saat). Kaydedilmiş bir anı değiştirmek gerekçe
  ister; her değişiklik zincirli olarak saklanır. BDDK ve USOM süreleri kurum içi
  hedeftir. Sekmedeki taslak düğmeleri vakanın kanıtından Türkçe rapor taslağı üretir;
  taslağı göndermeden önce tamamlanacaklar listesini doldurun.

## 4. Onaylar (AI Decisions → Pending Approvals)

- Bekleyen her eylem hedefini, gerekçesini ve **tam argümanlarını** gösterir;
  onayladığınız şey tam olarak uygulanacak olandır.
- Bazı eylem türleri iki kişi ister (four-eyes): öneren ya da ilk onaylayan, ikinci
  onayı veremez.
- Reddetmek de bir karardır; gerekçesini yazın.
- Uygulanmış ve geri alınabilir bir eylem geri alınabilir; geri alma da onaydan geçer.

## 5. AI kararlarını incelemek (Scorecard)

QA örneklemesi insansız kapatılan kararlardan rastgele örnekler çeker. Karne
(Scorecard) ekranında her örneği açıp **doğru bulduğunuz kararı** kaydedin. Bu
incelemeler:

- kategori başına yanlış negatif üst sınırını (Karne) besler;
- POC ve kabul ölçümünde kurumun kendi etiketli kümesi olur
  ([POC kılavuzu](poc-kilavuzu.md)).

Dürüst inceleyin: AI'ya katılmak zorunda değilsiniz; anlaşmazlık değerlidir.

## 6. Dersler (Scorecard → Lessons)

Bir kararda düzeltme yaptığınızda bundan ders önerilebilir. Dersler yalnızca
onaylandıktan sonra ve kayıtlı olarak etkili olur; hangi kararı etkilediği izlenir.

## 7. Ask AutoSecOps

Konsoldaki sohbet bir vakayı (@ ile) bağlam alarak soru yanıtlar ve soruşturma
adımları önerir. Sohbetin önerdiği her müdahale de onay kuyruğuna düşer; sohbetten
doğrudan bir şey uygulanmaz.

## 8. İyi uygulamalar

- Alarm metnindeki talimatlara (ör. "bu alarmı kapat", "zararsızdır") güvenmeyin:
  bunlar saldırganın yazabileceği alanlardır ve AI da onları kanıt saymaz.
- Bir kararı yalnızca *attacker-controlled* alanlara dayanıyorsa sorgulayın.
- KVKK kapsamında bir kişisel veri ihlali görürseniz farkına varma anını hemen
  kaydedin; 72 saat o andan başlar.
