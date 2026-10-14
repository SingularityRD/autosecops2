# Satışa hazırlık eksik analizi — ortak brief (salt-okunur)

Ürün: AutoSecOps 2.0 (Vigil AI SOC'un sert fork'u). Hedef pazar: Türkiye'de düzenlenmiş sektör (banka, kamu, kritik altyapı); GA 30 Ekim 2026. Satıcı: SingularityRD.
Kod: /root/wt/gap (main @ 87b1438e, SALT-OKUNUR; düzenleme, commit, push YOK). Plan/durum: docs/wp/NORTHSTAR_PLAN.md, docs/wp/STATUS.md, docs/guide/*, docs/release/2.0.0.md, README.md, FORK.md, LICENSE, SECURITY.md, VERSIONING.md, INTENT.md, CONTEXT.md.
Bilinen ve ZATEN listelenmiş olanları tekrar keşfetme ama listede say: rc.1 etiketi atıldı (imajlar yayımlanıyor), Kapı C (temiz VM <30dk) yapılmadı, pentest, W1.4 kararı, yüksek riskli WP ürün onayları, tag ruleset'leri, katalog yer tutucuları, otomatik kapatma/çok kiracılık Kasım'a ertelendi.

Görev: kendi alanındaki her persona için uçtan uca user story/flow'ları yaz (adım adım), sonra her adımı KODA ve BELGELERE karşı doğrula. Hayal etme: her bulgu için kanıt ver — `dosya:satır`, veya "aranan: <grep/glob ifadeleri> → bulunamadı". Gerekirse küçük komutlar çalıştır (grep, pytest -k ile tek test, `python -c` import), ama uygulamayı başlatma, DB'ye yazma, ağ çağrısı yapma, docker'a dokunma. `pkill -f`, `git stash` yasak.

Çıktı: `/tmp/gap/<alan>.md` dosyasına tam liste yaz, ayrıca son mesajında aynısını özetle (en fazla 900 kelime). Her bulgu satırı:
`| ID | Persona | Flow adımı | Eksik (ne yok / ne yanlış) | Kanıt | Önem | Sahip | Tahmini efor |`
Önem: SATIŞ-ENGELİ (bu olmadan müşteriye satılamaz/sözleşme imzalanamaz/kurulamaz), GA-ENGELİ, YÜKSEK, ORTA, DÜŞÜK. Sahip: Mühendislik / Ürün / Hukuk / Satış-Pazarlama / Destek-Operasyon / Uyum. Efor: S (<1g), M (1-3g), L (>3g).
Ayrıca "Var ve çalışıyor görünüyor" diye kısa bir liste ver (neyin hazır olduğunu bilelim). Türkçe yaz.

EK (kullanıcı talebi): Ürünün TÜM yaşam döngüsünü düşün — keşif/değerlendirme → satın alma → teslimat → kurulum (kurulum/ilk açılış sihirbazı dahil) → ilk değer (time-to-value) → günlük kullanım → genişleme → yükseltme/yama → destek/olay → yenileme → sözleşme bitişi/veri iadesi/kaldırma. Her persona için bu döngünün kendine düşen adımlarını gözden geçir. "Hiçbir eksik kalmasın" hedefiyle kapsamlı ol; bulgular kanıtlı olsun.
