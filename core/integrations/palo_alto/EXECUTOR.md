# Palo Alto yanıt yürütücüsü (executor)

`core/integrations/palo_alto/executor.py`, W0.5 `Executor` protokolünü
(`core/response/executors/base.py`) uygulayan `PaloAltoExecutor` sınıfını ve
`build_executor(config)` fabrikasını içerir. AutoSecOps bir IP'yi
engellediğinde güvenlik kuralına veya adres nesnesine **dokunmaz**; IP'yi
PAN-OS User-ID API'si ile bir **etiketle (tag) kaydeder**. Bu etiketi eşleştiren
bir **Dynamic Address Group (DAG)** ve onu kullanan bir "deny" kuralı trafiği
keser. Kayıt commit gerektirmez, `timeout` ile kendiliğinden sona erer ve
`unregister` ile birebir geri alınır.

> Kayıt: `core/response/executors/wiring.py` (`EXECUTOR_SOURCES`, `LiveExecutorRegistry`). Entegrasyon açıkken API ve daemon bu executor'ı kurar;
> yapılandırma değişince yeniden başlatma olmadan yeniden kurar (W0.37). Her
> eylem yine onay kapısından ve müdahale politikasından geçer.

## Eylemler

| `action_type` | Ne yapar | Geri alınabilir | Geri alma (`reverse`) |
|---|---|---|---|
| `block_ip` | IP'ye `autosecops-block` etiketini `timeout=<TTL sn>` ile kaydeder (`register`) | evet | Etiketi bu eylem eklediyse `unregister`; özgün eylem `noop` ise geri alma da `noop` (hiçbir istek atmaz, süresi dolmuş etiketi yeniden eklemez) |
| `unblock_ip` | IP'den etiketi kaldırır (`unregister`) | evet | Etiketi eylemin TTL'iyle (yoksa varsayılan) yeniden kaydeder; bu bir engelleme olduğundan önce `block_ip`'in tüm `validate` kuralları (yönetim IP'si, `protected_cidrs`, özel aralıklar, TTL) uygulanır, reddedilirse geri alma `failed` döner. Özgün eylem `noop` ise geri alma `noop` |

- **TTL:** varsayılan 24 saat (`86400` sn); `default_ttl_seconds` ile
  değiştirilir, eylemin `ttl`'i önceliklidir. PAN-OS üst sınırı 30 gündür
  (`2592000` sn); daha uzun TTL `validate`'te reddedilir. Süre dolunca
  güvenlik duvarı etiketi kendisi siler.
- **İdempotans:** `execute` önce `show object registered-ip` ile mevcut
  etiketleri okur (`before_state`). İstenen durum zaten geçerliyse `noop` döner
  ve hiçbir yazma isteği göndermez. Yeniden denenen bir `register` "already
  exists", süresi dolmuş bir kaydın `unregister`'ı "does not exist" yanıtı
  alırsa bu da başarı sayılır.
- **before/after:** `{"ip", "tag", "registered", "tags"}` biçiminde;
  `after_state` değişiklikten sonra yeniden okunur (okunamazsa `None`).
- **verify:** kayıtlı etiketleri tekrar sorgular. `block_ip` için etiket
  varsa, `unblock_ip` için yoksa `verified`; aksi halde `failed` (uyuşmazlık);
  güvenlik duvarı okunamazsa `unknown`. Geri alma satırında (`reverse_of`
  dolu; tür ve hedef özgün eylemle aynı) beklenen yön terstir: `block_ip`
  geri alması etiketin yokluğunu, `unblock_ip` geri alması varlığını doğrular.
  Hiçbir şeyi geri almayan `noop` geri alma `verified` sayılır.
- **XML:** `op` ve `uid-message` komutlarına giren her değer XML-kaçışlıdır;
  IPv6 kapsam kimliği (`fe80::1%eth0`) içeren hedef her adımda reddedilir.

## validate kuralları (güvenlik duvarına hiç istek atmaz)

`block_ip` için hedef:

1. Tek bir IPv4 veya IPv6 adresi olmalı (`1.2.3.4`, `1.2.3.4/32`,
   `2001:db8::1/128` kabul; `/24`, `/64`, `0.0.0.0/0` gibi **her aralık
   reddedilir**). IPv6 adresleri normalleştirilir (`2A01:04F8:0::1` →
   `2a01:4f8::1`).
2. Loopback, link-local, multicast, unspecified ve reserved adresler
   **her zaman** reddedilir. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) reddedilir;
   IPv4 biçimi kullanılmalıdır.
3. Özel/iç adresler (RFC1918, CGNAT `100.64.0.0/10`, IPv6 ULA `fc00::/7`,
   belgeleme aralıkları vb. — `is_global` olmayan her şey) yalnızca
   `allowed_internal_cidrs` içindeyse kabul edilir ve bu durumda
   `requires_approval=True` döner (insan onayı şart).
   `allowed_internal_cidrs` girdisi IPv4'te `/8`, IPv6'da `/32`'den geniş
   olamaz.
4. `protected_cidrs` içindeki adresler ve `hostname` bir IP ise güvenlik
   duvarının yönetim adresi **her zaman** reddedilir (iç izin listesinden
   önce gelir).

`unblock_ip` için yalnızca tek bir geçerli host adresi aranır (etiketi
kaldırmak kimsenin erişimini kesmez). `execute` aynı kuralları yeniden uygular;
`validate`'in reddettiği bir eylem hiçbir zaman güvenlik duvarına ulaşmaz.

## Yapılandırma (`build_executor(config)`)

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `hostname` | — (zorunlu) | Güvenlik duvarı / yönetim adresi; şema yoksa `https://` eklenir |
| `api_key` | — (zorunlu, gizli) | PAN-OS API anahtarı |
| `verify_ssl` | `true` | TLS doğrulaması |
| `ca_cert_path` | — | Yalnızca bu entegrasyon için özel CA (PEM) |
| `vsys` | — | Çoklu vsys cihazlarda hedef vsys (ör. `vsys1`); her isteğe `vsys=` eklenir |
| `timeout` | `30` | İstek zaman aşımı (sn) |
| `tag` | `autosecops-block` | Kaydedilecek etiket; `[A-Za-z0-9._-]`, en fazla 127 karakter |
| `default_ttl_seconds` | `86400` | Eylem `ttl` vermezse kullanılan süre (1 … 2592000) |
| `protected_cidrs` | — | Asla engellenmeyecek aralıklar (liste ya da virgülle ayrılmış metin) |
| `allowed_internal_cidrs` | — | Engellenmesine izin verilen iç aralıklar (onay gerektirir) |
| `max_attempts` | `3` | Toplam deneme sayısı |
| `backoff_seconds` | `0.5` | Üstel geri çekilme tabanı (`0.5`, `1.0`, `2.0` …) |

Geçersiz yapılandırma `PanConfigError` (`ValueError`) fırlatır.

**Yeniden deneme:** ağ hatası, HTTP 429 ve 5xx üstel geri çekilmeyle tekrarlanır.
HTTP 4xx ve PAN-OS `status="error"` yanıtı güvenlik duvarının cevabıdır,
tekrarlanmaz. DTD/ENTITY içeren XML yanıtı ayrıştırılmadan reddedilir.

## API anahtarı

Anahtar `X-PAN-KEY` başlığında gider; URL'de veya form gövdesinde **yer almaz**
(URL'ler proxy loglarına, httpx hata metinlerine ve traceback'lere düşer).
`core/integrations/palo_alto/client.py` (`PanConnection`) hata ve log
metinlerine giren her şeyi önce `redact` ile geçirir (ham ve URL-kodlu biçim
`***` olur); `repr` anahtarı göstermez. Aynı istemciyi `pan_block_ip` /
`pan_get_threats` MCP araçları da kullanır. PAN-OS 9.0 ve sonrası başlıkla
kimlik doğrulamayı destekler.

Anahtar için yalnızca gereken yetkiye sahip bir **Admin Role** önerilir:
XML API altında *User-ID Agent* ve *Operational Requests* açık, *Configuration*
ve *Commit* kapalı.

## Güvenlik duvarında gereken yapılandırma

Bir kez, bir yönetici tarafından yapılır ve commit edilir. Örnekler `vsys1` ve
varsayılan etiket içindir.

### 1. Etiket (tag)

```
set tag autosecops-block color color1 comments "AutoSecOps tarafindan engellenen IP'ler"
```

### 2. Dynamic Address Group

```
set address-group autosecops-blocklist dynamic filter "'autosecops-block'"
set address-group autosecops-blocklist description "AutoSecOps DAG - elle uye eklemeyin"
```

Web arayüzünde: *Objects → Address Groups → Add*, Type = **Dynamic**,
Match = `'autosecops-block'`.

### 3. Güvenlik kuralları

Kaynak **ve** hedef yönü için iki "deny" kuralı, izin veren kuralların
**üstüne**:

```
set rulebase security rules autosecops-block-in  from any to any source autosecops-blocklist destination any application any service any action deny log-end yes
set rulebase security rules autosecops-block-out from any to any source any destination autosecops-blocklist application any service any action deny log-end yes
move rulebase security rules autosecops-block-in top
move rulebase security rules autosecops-block-out after autosecops-block-in
commit
```

Yönetim arayüzüne erişimi bu kurallardan etkilenmeyecek şekilde tutun (yönetim
arayüzü ayrı bir kuralla korunmalı) ve yönetim / atlama (jump) hostlarının
aralıklarını `protected_cidrs`'e ekleyin.

### 4. Panorama

Panorama kullanılıyorsa DAG ve kurallar device-group'ta tanımlanabilir, ancak
bu executor **tek bir güvenlik duvarına** (veya kayıtları dağıtan User-ID
yeniden dağıtım noktasına) bağlanır; `hostname` o cihaz olmalıdır.

## Elle kontrol ve temizlik

```
# Kayıtlı IP'ler ve etiketleri
show object registered-ip tag autosecops-block
show object registered-ip ip 203.0.113.10

# DAG üyeleri
show object dynamic-address-group name autosecops-blocklist
```

Bir IP'nin etiketini elle kaldırmak (XML API, anahtar başlıkta):

```
curl -sk -H "X-PAN-KEY: $PAN_KEY" https://<firewall>/api/ \
  --data-urlencode type=user-id \
  --data-urlencode 'cmd=<uid-message><version>2.0</version><type>update</type><payload><unregister><entry ip="203.0.113.10"><tag><member>autosecops-block</member></tag></entry></unregister></payload></uid-message>'
```

Tüm AutoSecOps kayıtlarını kaldırmak için CLI'da:
`debug object registered-ip clear tag autosecops-block` (sürüme göre
değişebilir; önce laboratuvarda deneyin). Ayrıca TTL dolunca kayıtlar
kendiliğinden silinir.

## Laboratuvar doğrulama prosedürü

Üretimden önce bir laboratuvar güvenlik duvarında (ör. VM-Series deneme
lisansı) yapın:

1. Yukarıdaki etiket, DAG ve iki kuralı oluşturup commit edin.
2. Yalnızca User-ID ve Operational Requests yetkili bir API anahtarı üretin.
3. Bir Python oturumunda:
   ```python
   from datetime import timedelta
   from core.integrations.palo_alto.executor import build_executor
   from core.response.executors.base import TypedAction

   ex = build_executor({"hostname": "lab-fw.example", "api_key": "...",
                        "protected_cidrs": ["<yonetim-araligi>"],
                        "default_ttl_seconds": 600})
   a = TypedAction(action_type="block_ip", target="203.0.113.10", ttl=timedelta(minutes=5))
   print(ex.validate(a))
   r = ex.execute(a); print(r)
   print(ex.verify(a, r))
   ```
4. Güvenlik duvarında `show object registered-ip ip 203.0.113.10` ile etiketi
   ve kalan süreyi, `show object dynamic-address-group name
   autosecops-blocklist` ile DAG üyeliğini görün; test istemcisinden o IP'ye
   giden trafiğin `autosecops-block-out` kuralıyla düştüğünü trafik logunda
   doğrulayın. (Laboratuvarda belgeleme aralığı kullanılıyorsa,
   `allowed_internal_cidrs: ["203.0.113.0/24"]` gerekir.)
5. Aynı eylemi tekrar `execute` edin: `noop` dönmeli, yazma isteği gitmemeli.
6. `ra = a.model_copy(update={"reverse_of": "lab-1"})`; `u = ex.reverse(ra, r)`
   → `executed`; etiket ve DAG üyeliği kalkmalı, trafik geri gelmeli.
   `ex.verify(ra, u)` → `verified`.
7. TTL testi: kısa bir `ttl` ile engelleyip süre dolduğunda kaydın kendiliğinden
   silindiğini doğrulayın.
8. Negatif testler: `10.0.0.1`, yönetim IP'si, `0.0.0.0/0` ve
   `protected_cidrs` içindeki bir adres `validate`'te reddedilmeli; güvenlik
   duvarının sistem logunda hiçbir User-ID isteği görünmemelidir.
