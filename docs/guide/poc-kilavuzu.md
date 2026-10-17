# POC kılavuzu: müşterinin kendi alarmlarıyla ölçüm

> **English summary.** How to run a proof of concept on the customer's own alerts
> and leave with numbers: connect sources, let analysts review a random sample of
> AI decisions, turn those reviews into a labelled eval set, score the triage path
> against it offline, and download the POC report (W0.49). Nothing here is a
> benchmark claim; every number comes from the customer's install.

## 1. Amaç ve süre

POC'nin sonunda müşterinin elinde **kendi alarmları üzerinde** ölçülmüş üç şey olmalıdır:

1. Ne geldi, triyaj ne dedi, analistler neye itiraz etti (POC raporu).
2. Analistlerin incelediği alarmlar üzerinde triyajın isabeti (evalkit, `customer` paketi).
3. Bilinen cevaplı kanaryaların yakalanıp yakalanmadığı.

Önerilen süre iki ile dört haftadır; kategori başına anlamlı bir yanlış negatif üst
sınırı için Karne her kategoride onlarca inceleme ister (Karne gereken inceleme
sayısını kendisi gösterir).

## 2. Kurulum ve kaynaklar

1. Kurulum: [internetsiz kurulum](kurulum-internetsiz.md) ya da
   [bağlantılı Helm](isletim-rehberi.md#3-bağlantılı-internete-erişen-helm-kurulumu).
2. Kaynaklar: SIEM/EDR bağlayıcıları **Ayarlar → Integrations**; syslog/CEF/LEEF ve
   QRadar için [yönetici kılavuzu](yonetici-kilavuzu.md#entegrasyonlar).
3. Model: internetsiz POC'de yerel model şeridi; bulut modeli seçilirse içerik
   sağlayıcıya gider (KVKK değerlendirmesi müşterinindir).
4. Otonomi: POC boyunca **Assist** (her müdahale insan onaylı) önerilir.

Tanıtım için müşteri verisi gelmeden önce: `python -m core.platform.demo_scenario seed`
(onay, geri alma, kanıt paketi ve düzenleyici sayaçları gösteren tek olay; ayrıntı
[yönetici kılavuzu](yonetici-kilavuzu.md#demo-senaryosu-w050)). Gerçek veriye
geçmeden `remove` ile kaldırın.

## 3. Ölçümü açmak

- **QA örnekleme:** analistler Karne (Scorecard) ekranından örnekleri inceler; örnek
  çekme `POST /api/qa/samples/draw` (`ai_decisions.approve`). İnceleme, analistin doğru
  bulduğu kararı kaydeder; bu, müşterinin kendi etiketidir.
- **Kanaryalar:** Admin `PUT /api/quality/canaries/settings` ile açar. Kanaryalar
  müşteri metriklerine, bildirimlere ve rapordaki işletim sayılarına girmez.
- Ayrıntı: [Kalite ölçümü](yonetici-kilavuzu.md#kalite-ölçümü-kanarya-ve-qa).

## 4. İncelemeleri değerlendirme kümesine çevirmek

POC süresince incelenen alarmlar, analistin kararıyla etiketlenmiş bir JSONL dosyasına
yazılır ve triyaj yolu çevrimdışı bu dosyaya karşı ölçülür:

```bash
# Backend imajında ya da depo kökünde (PYTHONPATH=.), veritabanına erişimle
python -m evalkit export-reviewed --out /guvenli/poc/reviewed.jsonl
# Kurulumun kendi modeliyle, bütçe tavanıyla
python -m evalkit run --backend live --budget-usd 5 \
    --cases /guvenli/poc/reviewed.jsonl --out /guvenli/poc/eval --db
```

- Dosya müşterinin alarm içeriğini taşır; alarmların durabileceği yerde saklayın.
- Yalnız `malicious` ve `benign` incelemeler alınır (`--include-inconclusive` ile
  belirsizler de); kanaryalar dışarıda kalır; bir alarm birden çok kez incelendiyse
  son incelemesi geçerlidir.
- `--cases` kendi dosyanız için `customer` paketini koşar; `--suite` verilirse v1
  korpus paketleri de aynı çalıştırmada ölçülür. Rapor (`report.md`, `report.json`)
  dosyanın adını ve sha256'sını kaydeder; `--db` sonucu `eval_runs`'a yazar ve POC
  raporunda görünür.
- Kendi etiketli dosyanızı da verebilirsiniz: satır başına
  `{"alert": {...}, "labels": {"verdict": "malicious|benign|inconclusive"}}`,
  alarmın finding_id değeri benzersiz. Biçim:
  [evalkit/README.md](../../evalkit/README.md).

## 5. POC raporu

Konsolda **Analytics** ya da **Metrics** ekranındaki **Export report** seçili aralığın
raporunu Markdown olarak indirir; API: `GET /api/qa/poc-report?days=30&format=markdown`
(`settings.read`; `format=json` makine okunur hali). Bölümler: gelen alarmlar (kaynağa
göre), AI triyaj kararları, alarm şeritleri, analist incelemesi ve Karne üst sınırları,
kanaryalar, vakalar, önerilen müdahaleler, son çevrimdışı değerlendirmeler. Tabloları
olmayan bir bölüm "bu kurulumda yok" der; sayı uydurulmaz. Kanarya bulguları işletim
sayılarından çıkarılır.

## 6. Raporu okurken

- Karne'deki üst sınır yalnız basit rastgele örneklerden hesaplanır ve tüm
  incelemeleri kapsar (yalnız rapor penceresini değil).
- Ölçümler bu kurulumun modeli, istem sürümü ve kaynaklarıyla geçerlidir; model ya da
  istem değişince `evalkit` yeniden koşulmalıdır.
- Rapordaki sayılar pazarlama iddiası değildir; müşterinin kendi verisiyle POC sonucudur.
