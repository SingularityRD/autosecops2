# Düzeltmesi olmayan imaj açıkları: VEX ve risk kabulü

Ürün: **AutoSecOps 2.x** · Sahip: SingularityRD · İlk sürüm: W0.38 (2026-10-16)

Bankaların ve kurumların zafiyet tarayıcıları (Trivy, Grype, Prisma, Qualys)
AutoSecOps imajlarında işletim sistemi paketlerinden gelen bulgular raporlar.
Bunların çoğu temel imajın (Debian) paketlerindedir ve iki türdür:

1. **Düzeltmesi olmayan** (Debian `<no-dsa>`, `will_not_fix`, `postponed`):
   paketin düzeltilmiş sürümü yoktur. Bu repo onu düzeltemez; yalnızca etkisini
   değerlendirebilir.
2. **Bizi etkilemeyen**: açık, imajda bulunmayan ya da AutoSecOps'un hiç
   çalıştırmadığı bir kod yolundadır.

Bu belge iki türün nasıl değerlendirildiğini, nasıl kayda geçtiğini ve risk
kabulünün kimde olduğunu anlatır. Makine okunur karşılığı
[`autosecops.openvex.json`](autosecops.openvex.json) dosyasıdır
([OpenVEX](https://openvex.dev/) v0.2.0).

## Neyin kapıda durduğu

Her PR'da ve sürümde (`.github/workflows/ci-cd.yml`, Agent Image ve Service
Image işleri) Trivy üç adım koşar:

| Adım | Ne yapar | Sonuç |
|---|---|---|
| Rapor | HIGH ve CRITICAL bulguların tamamı | yalnızca günlük |
| Kapı | **düzeltmesi olan** CRITICAL (`ignore-unfixed`) | işi düşürür |
| Gizli bilgi | imajda herhangi bir gizli bilgi | işi düşürür |

Yani düzeltmesi olan bir CRITICAL hiçbir zaman sürüme giremez. Düzeltmesi olan
HIGH bulgular sürüm öncesinde paket sabitlemesiyle (`Dockerfile.agent` içindeki
`libgnutls30`, `perl-base` sabitleri gibi) ya da temel imaj yükseltmesiyle
kapatılır. Bu belge yalnızca kapının bilerek geçirdiği bulgular içindir.

## Süreç

Her sürümden önce (ve bir tarayıcı yeni bir bulgu bildirdiğinde):

1. **Topla.** Sürüm iş akışı her imaj ve platform için CycloneDX SBOM üretir
   (`autosecops-<V>-image-<bileşen>-<mimari>.cdx.json`). Trivy raporu aynı
   imajdan alınır.
2. **Ayır.** Her HIGH/CRITICAL bulgu için: düzeltilmiş paket var mı (Debian
   güvenlik izleyicisi)? Varsa sabitle ya da temel imajı yükselt; bu belgeye
   girmez.
3. **Değerlendir.** Düzeltmesi yoksa: etkilenen kod imajda var mı, AutoSecOps
   onu çalıştırıyor mu, saldırganın o yola erişimi var mı?
   - Etkilemiyorsa OpenVEX dosyasına `not_affected` ifadesi eklenir;
     `justification` OpenVEX değerlerinden biridir
     (`vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
     `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`)
     ve `impact_statement` gerekçeyi bir iki cümleyle söyler.
   - Etkiliyorsa ya da emin olunamıyorsa bulgu aşağıdaki **risk kabul
     kaydına** girer: etki, telafi edici kontrol, son tarih.
4. **Onayla.** Risk kabulünü ürün sahibi onaylar. Kabul en çok **90 gün**
   geçerlidir; süresi dolan kabul yeniden değerlendirilir. Debian bir düzeltme
   yayımladığında bulgu bir sonraki yama sürümünde kapatılır ve kayıttan çıkar.
5. **Yayımla.** OpenVEX dosyası ve bu belge sürümle birlikte güncellenir;
   `timestamp` ve `version` artırılır.

## Müşteri tarafında kullanım

Tarayıcınız OpenVEX okuyorsa dosyayı verin; `not_affected` ifadeleri raporda
bastırılır ya da işaretlenir:

```bash
trivy image --vex docs/security/autosecops.openvex.json \
  ghcr.io/singularityrd/autosecops-agent:<sürüm>
```

OpenVEX okumayan bir tarayıcı için bu belgedeki tablo aynı bilgiyi verir.

## Değerlendirilmiş bulgular

| CVE | İmaj | Paket | Durum | Gerekçe |
|---|---|---|---|---|
| CVE-2023-45853 (CRITICAL) | agent | `zlib1g` (Debian 12) | not_affected (`vulnerable_code_not_present`) | Açık minizip'te (`contrib/minizip`). Debian `zlib1g` paketi minizip içermez (o ayrı `libminizip1` paketidir) ve Debian bu yüzden `will_not_fix` der. İmajda minizip yok. |

## Risk kabul kaydı

Düzeltmesi olmayan HIGH bulgular (W0.23 ölçümü, Trivy v0.75.0): agent imajı
(Debian 12) 53, backend imajı (Debian 13) 58 ve `restic` ikilisi 19, daemon
imajı (Debian 13) 48. Hepsi temel imaj paketlerinde ya da `restic`'in Go
standart kitaplığındadır; hiçbirinin düzeltilmiş sürümü yoktur.

| Kapsam | Telafi edici kontroller | Onay | Son tarih |
|---|---|---|---|
| Yukarıdaki düzeltmesiz HIGH bulgular, toplu | Konteynerler root olmayan kullanıcıyla koşar (Helm `podSecurityContext.runAsNonRoot`); air-gap profili (`networkPolicies.egress.inClusterOnly`) küme dışına çıkışı kapatır; ajan imajında npm kaldırılmıştır. Her sürümde yeniden taranır | **Ürün sahibi kararı bekliyor** (`docs/wp/w0.38.md`) | GA + 90 gün |

Tek tek değerlendirme (her CVE için OpenVEX ifadesi ya da ayrı kabul satırı)
GA öncesi bir sonraki taramada yapılır; o zamana kadar yukarıdaki toplu kabul
satırı geçerlidir.
