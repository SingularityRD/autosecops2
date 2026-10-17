# FortiGate yanıt yürütücüsü (executor)

`core/integrations/fortinet/executor.py`, `Executor` protokolünü
(`core/response/executors/base.py`) uygulayan `FortiGateExecutor` sınıfını ve
`build_executor(config)` fabrikasını içerir (W0.57). AutoSecOps bir IP'yi
engellediğinde güvenlik politikasına **dokunmaz**: `autosecops-<ip>` adlı bir
adres nesnesi oluşturur ve onu, operatörün bir kez bir "deny" politikasına
bağladığı **adres grubuna** ekler. FortiOS CMDB değişikliği hemen uygular; commit
yoktur. Üyeler grubun `member` alt tablosu üzerinden tek tek eklenip çıkarılır;
iki eylem birbirinin listesini ezmez.

> Kayıt: `core/response/executors/wiring.py` (`EXECUTOR_SOURCES`). Entegrasyon
> açıkken API ve daemon bu yürütücüyü kurar ve yapılandırma değişince yeniden
> başlatmadan yeniden kurar. Her eylem onay kapısından ve müdahale politikasından
> geçer. **Deneysel:** kayıtlı FortiOS yanıtlarıyla birim testinden geçer, canlı
> bir cihazda doğrulanmadı.

## Güvenlik duvarında bir kez yapılacaklar

```
config firewall address
    edit "autosecops-placeholder"
        set subnet 192.0.2.255 255.255.255.255
        set comment "AutoSecOps: grubu boş bırakmamak için; silmeyin"
    next
end
config firewall addrgrp
    edit "autosecops-block"
        set member "autosecops-placeholder"
    next
end
config firewall policy
    edit 0
        set name "autosecops-block-out"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "autosecops-block"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

- Gelen trafik için kaynağı `autosecops-block` olan ikinci bir deny politikası
  ekleyin; iki politikayı da izin politikalarının **üstüne** taşıyın.
- IPv6 için aynısını `firewall address6`, `firewall addrgrp6` ve
  `autosecops-block6` ile yapın.
- Yer tutucu üye, bazı FortiOS sürümleri boş grubu kabul etmediği için vardır;
  yürütücü yalnız kendi eklediği `autosecops-` üyelerine dokunur.
- REST API yöneticisi: `System → Administrators → REST API Admin`; profili
  `Firewall → Address` için okuma/yazma, `System` için salt okuma (Test düğmesi
  `monitor/system/status` okur). Güvenilir ana makine olarak yalnız AutoSecOps'un
  çıkış adresini girin.

## Eylemler

| `action_type` | Ne yapar | Geri alma (`reverse`) |
|---|---|---|
| `block_ip` | Adres nesnesini (yoksa) oluşturur, gruba ekler | Bu eylem eklediyse üyeyi ve nesneyi kaldırır; özgün eylem `noop` ise `noop` |
| `unblock_ip` | Üyeyi gruptan ve `autosecops-` nesnesini kaldırır | Yeniden ekler; bu bir engelleme olduğundan önce `block_ip`'in tüm kuralları uygulanır |

- **TTL:** FortiOS adres grubu üyeliğinin süresi yoktur. Eylemin TTL'i (varsayılan
  24 saat, `default_ttl_seconds`; üst sınır 30 gün) `expires_at`'i belirler ve
  daemon'un süre dolumu taraması eylemi o zaman geri alır.
- **İdempotans:** `execute` önce grubu okur; istenen durum zaten geçerliyse `noop`
  döner ve yazma isteği göndermez. "Zaten var" (-5) ve "bulunamadı" (-3, 404)
  yanıtları başarı sayılır.
- **verify:** grubu yeniden okur; üyelik istenen durumdaysa `verified`, değilse
  `failed`, okunamazsa `unknown`.
- Grup yoksa eylem "create address group … and a deny policy that uses it"
  iletisiyle `failed` olur.

## validate kuralları (güvenlik duvarına istek atmaz)

Palo Alto yürütücüsüyle aynıdır: tek bir IPv4/IPv6 adresi; loopback, link-local,
multicast, unspecified ve reserved adresler her zaman reddedilir; özel/iç adresler
yalnız `allowed_internal_cidrs` içindeyse ve insan onayıyla; `protected_cidrs` ve
`hostname` bir IP ise yönetim adresi reddedilir; TTL 30 günü aşamaz.

## Yapılandırma

Konsol formu: `hostname`, `api_token` (şifreli sır deposunda), `vdom` (varsayılan
`root`), `verify_ssl`, `ca_cert_path`. Saklanan yapılandırmada isteğe bağlı:
`group`, `group6`, `default_ttl_seconds`, `protected_cidrs`,
`allowed_internal_cidrs`, `max_attempts`, `backoff_seconds`.

**Tek güvenlik duvarı:** Palo Alto ve FortiGate ikisi de `block_ip` sunar; ikisi
birden etkinse Palo Alto kalır, FortiGate çakışma olarak loglanır ve kayda
alınmaz.
