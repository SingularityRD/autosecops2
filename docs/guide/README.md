# AutoSecOps 2.0 — Belge seti

> **English summary.** Customer documentation for AutoSecOps 2.0 (regulated-sector
> release candidate). Every page describes the code at `main` @ `167f7b77`.
> Features from work packages that are not merged yet are marked **Planlı**
> ("planned") with the branch that carries them and are *not* part of this
> release. Start with [kapsam.md](kapsam.md) (release scope), then the install
> guide, the administrator guide, the security technical document, the threat
> model and the regulatory mapping (not legal advice).

Bu dizin, düzenlenmiş sektör (banka, kamu, kritik altyapı) müşterisine verilen
belge setidir. Belgeler yalnızca bu sürümün kodunda (`main` @ `167f7b77`) olanı
anlatır. Henüz birleşmemiş bir iş paketinin getireceği özellik, satırında
**Planlı** işareti ve onu taşıyan dalın adıyla yazılır ve bu sürüme dahil değildir.
Örnek: OIDC SSO (Planlı — `wp/w1.9-oidc`, bu sürümde yok).

| Belge | Kimin için | İçerik |
|---|---|---|
| [Sürüm kapsamı](kapsam.md) | herkes, önce bunu okuyun | Bu sürümde olan / olmayan; iş paketi → dal tablosu |
| [İnternetsiz kurulum kılavuzu](kurulum-internetsiz.md) | kurulum mühendisi | İmzalı paketin üretilmesi, doğrulanması, kurulumu; `airgap.env` profili; sıfır egress kanıtı |
| [Yönetici kılavuzu](yonetici-kilavuzu.md) | AutoSecOps yöneticisi | Kullanıcılar, roller ve izinler, kimlik doğrulama, entegrasyonlar, müdahale politikası ve onaylar, otonomi, saklama ve imha, denetim kayıtları, yedekleme ve sıcak yedek |
| [Güvenlik teknik belgesi](guvenlik-teknik-belgesi.md) | güvenlik mimarı, denetçi | Mimari, güven sınırları, köken/karar sözleşmesi, onaylar, denetim zinciri, egress denetimi, sırlar, kriptografi |
| [Tehdit modeli](tehdit-modeli.md) | güvenlik ekibi, pentest | Bileşen başına STRIDE, uygulanmış önlemler, açık riskler |
| [Mevzuat eşlemesi](mevzuat-eslemesi.md) | uyum ekibi | BDDK, KVKK, DORA, NIS2, SPK, ISO/IEC 27001 kontrolleri → ürün özelliği → kanıt (hukuki görüş değildir) |

İlgili, kodla birlikte yaşayan teknik belgeler (bu setin kaynakları):

- [infra/airgap/README.md](../../infra/airgap/README.md) — paket betiklerinin ayrıntılı başvurusu
- [tests/airgap/README.md](../../tests/airgap/README.md) — sıfır egress envanteri ve çalışma zamanı testi
- [docs/operations/rpo-rto.md](../operations/rpo-rto.md) — RPO/RTO, daemon sıcak yedeği, Helm yedek CronJob'u, geri yükleme
- [core/compliance/RETENTION.md](../../core/compliance/RETENTION.md) — veri sınıfları, saklama, yasal saklama, periyodik imha
- [infra/staging/README.md](../../infra/staging/README.md) — gecelik staging ortamı
- [docs/outbound-webhooks.md](../outbound-webhooks.md) — giden webhook imzası ve alıcı doğrulaması
- [docs/medic/enable.md](../medic/enable.md) — Medic (kurulum sağlığı izleyicisi)
- Yürütücüler: [Defender](../../core/integrations/microsoft_defender/EXECUTOR.md),
  [Entra ID](../../core/integrations/azure_ad/EXECUTOR.md),
  [Palo Alto](../../core/integrations/palo_alto/EXECUTOR.md)
- [INTENT.md](../../INTENT.md) — daemon'un beyan edilen otonomi değerleri
- [SECURITY.md](../../SECURITY.md) — güvenlik açığı bildirimi

## Belgeler nasıl doğru tutulur

`tests/unit/docs/test_guide_docs.py` her değişiklikte şunları denetler:

1. Bu dizindeki her göreli bağlantı var olan bir dosyaya (ve başlığa) çözülür.
2. Belge-kod uzlaşması: kod biçiminde yazılmış her ortam değişkeni, depo yolu,
   `/api/...` yolu, `python -m` modülü, `npm run` betiği ve kurulum/yedek betiği
   bayrağı bu commit'teki kodda vardır. Düz metinde geçen ortam değişkenleri de
   aynı denetimden geçer.
3. "Planlı" ve ardından uzun tire, birleşmemiş bir özelliği işaretler; satır dal
   adını (`wp/...`) ya da "dal yok" ifadesini taşımalıdır. Denetim yalnızca
   işaretin ait olduğu parçayı atlar: işaretin içinde durduğu parantezi, yoksa
   tablo hücresini, yoksa cümleyi. Aynı satırın geri kalanı yine denetlenir.
   Böylece bugünkü bir iddia, yanındaki bir işaretin arkasına saklanamaz.
   İşaret taşıyan düz metin satırları kısa tutulur (en çok 200 karakter).

Çalıştırmak için (depo kökünden, venv etkin):

```bash
python -m pytest -c tests/pytest.ini --rootdir=. -o addopts= -q tests/unit/docs
```

Ürün adı kullanıcıya görünen her yerde **AutoSecOps**'tur. Kodda, Helm grafiğinin
adında (`infra/helm/vigil`), ortam değişkenlerinde (`VIGIL_*`) ve veritabanı rolünde
(`vigil_app`) eski iç ad bilerek korunur; bu belgelerde de o adlarla geçer.
