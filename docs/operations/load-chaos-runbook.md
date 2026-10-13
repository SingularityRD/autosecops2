# Yük ve kaos testi runbook'u (W4.1 / W4.2) — staging'de tam koşu

Bu runbook, AutoSecOps'un **staging** kurulumunda (W0.6: tek VM, k3s + Helm,
`infra/staging/`) tam yük testini ve kaos senaryolarını çalıştırmayı anlatır.
Araçlar `tests/perf/` altındadır; sözleşme ve kabul kriterleri
`docs/wp/w4.1.md`'dedir.

> **Duman testi ≠ kapasite ölçümü.** `tests/perf` içindeki yerel koşu (WP
> geliştirme makinesinde, sahte modelle) yalnızca araçların ve alım yolunun
> çalıştığını gösterir. SLO'ların tuttuğu iddiası **yalnızca** bu runbook'taki
> staging koşusunun raporuyla yapılır.

## 1. Ne ölçülür

| Ölçüm | Kaynak | Hedef (plan, "SLO'lar") |
|---|---|---|
| Alımdan karara gecikme, kural şeridi | `findings.created_at` → `alert_lane_decisions.decided_at` | p95 < 5 sn |
| Alımdan karara gecikme, küçük model şeridi | `findings.created_at` → `ai_enrichment.ai_triage.timestamp` | p95 < 60 sn |
| Alımdan karara gecikme, verdict run | `findings.created_at` → `workflow_runs.finished_at` (`verdict_run_id`) | p95 < 10 dk |
| Alarm kaybı | gönderici "kabul edildi" dediği halde `findings`'te olmayan bulgu | 0 |

Notlar:

- Plan tablosu kaynak olarak `alert_routes` der; bu kod tabanında
  `alert_routes` bildirim yönlendirme tablosudur. Şerit kararı
  `alert_lane_decisions` tablosundadır (W2.2, `56_alert_lane_decisions.sql`),
  ölçüm oradan okunur.
- Verdict run şeridi bir verdict-run iş paketi `verdict_enqueuer`'ı bağlayana
  kadar küçük model şeridine düşer (`degraded_from='verdict'`,
  `deferred_verdict=true`); raporda bu bulgular `small_model` altında ve
  `deferred_verdict` sayacında görünür, verdict satırı `n/a` olur.
- Bütün zamanlar veritabanından okunur; yük üreticisinin saati ölçüme girmez.
- Webhook'a 200 dönen ama veritabanına hiç yazılmayan bulgu **kayıptır**.
  Kabul edilmeyip `--max-retry-seconds` boyunca yeniden denenen bulgu ayrıca
  `not_accepted` olarak raporlanır.

## 2. Ön koşullar

- Staging yeşil: `cat /var/lib/autosecops-staging/last-run.json` → `"result": "ok"`.
- Koşu boyunca gece kurulumu ve replay **durdurulur** (Helm yükseltmesi testin
  ortasında pod'ları yeniden başlatır):

  ```bash
  sudo systemctl stop autosecops-staging-nightly.timer autosecops-staging-replay.timer
  ```

- VM'de depo kopyası: `/opt/autosecops-staging/src`. Python ortamı:

  ```bash
  cd /opt/autosecops-staging/src
  python3 -m venv /opt/autosecops-loadtest-venv
  /opt/autosecops-loadtest-venv/bin/pip install -r requirements.txt
  export PATH=/opt/autosecops-loadtest-venv/bin:$PATH
  ```

  (Yük üreticisi yalnızca `httpx` ve `sqlalchemy`/`psycopg2` kullanır; yeni
  bağımlılık yoktur.)

- Kaynak adları `fullnameOverride: autosecops` ile şunlardır (doğrulayın):

  ```bash
  export NS=autosecops-staging
  kubectl -n $NS get sts,deploy,svc
  # beklenen: sts/autosecops-postgres, sts/autosecops-redis, sts/autosecops-daemon,
  #           deploy/autosecops-backend, deploy/autosecops-llm-worker,
  #           deploy/ollama, deploy/bifrost (manifests/llm.yaml)
  ```

## 3. Staging'i teste hazırlama

Staging varsayılanında daemon webhook'u **kapalıdır** (`DAEMON_WEBHOOK_TOKEN`
yok → her istek 503, fail closed) ve alarm şeritleri kapalıdır. Test için
geçici bir değer katmanı uygulanır:

```bash
# 1) Webhook belirteci: yalnızca Secret'ta, komut satırında görünmez.
umask 077
openssl rand -hex 24 > /root/loadtest-webhook-token
kubectl -n $NS create secret generic autosecops-loadtest \
  --from-file=webhook-token=/root/loadtest-webhook-token \
  --dry-run=client -o yaml | kubectl apply -f -

# 2) Değer katmanı
cat > /root/loadtest-values.yaml <<'EOF'
config:
  ALERT_LANES_ENABLED: "true"
  # Yük testinde backfill aralığı üretimdekiyle aynı kalsın; staging'in 60 sn'si
  # API ile alınan bulguların gecikmesine doğrudan eklenir (bkz. 6. bölüm).
daemon:
  extraEnv:
    - name: DAEMON_WEBHOOK_TOKEN
      valueFrom:
        secretKeyRef: {name: autosecops-loadtest, key: webhook-token}
EOF
sudo helm upgrade autosecops /opt/autosecops-staging/src/infra/helm/vigil \
  -n $NS --reuse-values -f /root/loadtest-values.yaml --wait
```

Erişim (VM'nin kendisinden; hepsi `127.0.0.1`'e bağlanır):

```bash
kubectl -n $NS port-forward svc/autosecops-daemon 18081:8081 >/tmp/pf-daemon.log 2>&1 &
echo $! > /tmp/pf-daemon.pid
kubectl -n $NS port-forward svc/autosecops-postgres 15432:5432 >/tmp/pf-pg.log 2>&1 &
kubectl -n $NS port-forward svc/autosecops-backend 18000:8000 >/tmp/pf-api.log 2>&1 &

export DAEMON_WEBHOOK_TOKEN="$(cat /root/loadtest-webhook-token)"
PGPASS="$(kubectl -n $NS get secret autosecops-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"
export LOADTEST_DB_URL="postgresql+psycopg2://deeptempo:${PGPASS}@127.0.0.1:15432/deeptempo_soc"
export LOADTEST_WEBHOOK_URLS="http://127.0.0.1:18081/webhook"
export LOADTEST_API_BASE="http://127.0.0.1:18000"
# API ile alım ve okuma yoklaması için yönetici belirteci (admin.env'deki hesap):
set -a; . /etc/autosecops-staging/admin.env; set +a
export LOADTEST_API_TOKEN="$(curl -s -X POST "$LOADTEST_API_BASE/api/auth/login" \
  -H 'Content-Type: application/json' -H 'X-CSRF-Token: x' -b 'csrf_token=x' \
  --data @- <<<"{\"username_or_email\":\"$STAGING_ADMIN_USER\",\"password\":\"$STAGING_ADMIN_PASSWORD\"}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')"
```

Port-forward tek bağlantı tünelidir ve kendisi bir darboğaz olabilir. Yüksek
oranlarda (> 50 bulgu/sn) yük üreticisini küme içinde bir pod olarak ya da
Traefik üzerinden çalıştırın ve raporda bunu belirtin.

## 4. Yük testi (W4.1)

Pilot alarm hacmi Dalga 0'da netleşir; netleşene kadar aşağıdaki profil
kullanılır ve rapora **varsayılan profil** diye yazılır. `RATE` pilotun
ortalama alarm/sn değeri, `BURST` en yoğun 5 dakikanın alarm/sn değeridir.

```bash
cd /opt/autosecops-staging/src
OUT=/var/lib/autosecops-staging/load/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"

# Sürekli yük + ani yük: 30 dk, 2/sn sürekli, her 5 dk'da 60 sn boyunca +20/sn.
python -m tests.perf.loadgen \
  --webhook "$LOADTEST_WEBHOOK_URLS" \
  --api "$LOADTEST_API_BASE" --api-fraction 0.05 --api-read-rps 1 \
  --rate 2 --duration 1800 \
  --burst-rate 20 --burst-duration 60 --burst-every 300 --burst-offset 120 \
  --rules-fraction 0.3 --seed-rules \
  --settle-timeout 1800 --label "staging sustained+burst" \
  --out "$OUT/report" --enforce-slo
echo "exit=$?"
```

- `--seed-rules`, `data_source=loadtest-rules` için bir `suppression_rules`
  satırı ekler (adı `loadtest-loadtest-rules`); rapordan sonra kapatın:
  `psql "${LOADTEST_DB_URL/+psycopg2/}" -c "UPDATE suppression_rules SET enabled=false WHERE name='loadtest-loadtest-rules'"`.
- Rapor: `$OUT/report.md` ve `$OUT/report.json` (şerit başına p50/p95/p99,
  SLO karşılaştırması, kayıp/çift/ertelenmiş sayıları, istemci tarafı kabul
  gecikmesi, API okuma p95).
- `--enforce-slo` ile bir SLO satırı `FAIL` ise çıkış kodu 1'dir. 20'den az
  örnekli şerit `n/a` yazılır (`--min-samples`).
- Bulgu kimlikleri `lt-<run>-<sıra>` biçimindedir; sonradan temizlemek için:
  `DELETE FROM findings WHERE finding_id LIKE 'lt-%'` (önce `alert_lane_decisions`).

Yorumlama:

| Durum | Anlamı | Ne yapılır |
|---|---|---|
| `small_model` p95 hedefin üstünde, `accept_p95_s` düşük | alım hızlı, model yavaş | Ollama/Bifrost eşzamanlılığı (`OLLAMA_NUM_PARALLEL`, `LLM_MAX_CONCURRENT`), model boyutu |
| `accept_p95_s` yüksek, `final_status` içinde 503 | daemon devir kuyruğu dolu (`DAEMON_HANDOFF_QUEUE_MAXSIZE`) | daemon CPU, `DAEMON_MAX_CONCURRENT_TASKS` |
| API ile alınanlar yavaş | API yolu daemon'a devretmez; backfill taraması bekler | 6. bölüm, bilinen sınır |
| `unsettled` > 0 | bekleme süresinde karar yok | `--settle-timeout` artırın; daemon loglarında kesici (`Pausing AI enrichment`) arayın |

## 5. Kaos senaryoları (W4.2)

Her senaryo, `--rate` hızında `pre + fault + post` saniye yük gönderir,
`pre` saniye sonra arızayı enjekte eder, `fault` saniye sonra iyileştirir ve
her kabul edilen bulgunun kurtarma sınırı içinde karara bağlanmasını bekler.
Geçme koşulu: kayıp 0, çift satır 0, karara bağlanmamış 0, kurtarma ≤ sınır ve
senaryonun kendi kontrolleri. Komutu tanımlanmamış senaryo **atlanır**
(SKIP), taklit edilmez.

Arızalar staging'de kabuk komutlarıyla verilir:

```bash
# Model sağlayıcısı çökmesi: Ollama'yı kapat (Bifrost 5xx döner).
export CHAOS_CMD_LLM_ERROR="kubectl -n $NS scale deploy/ollama --replicas=0"
export CHAOS_CMD_LLM_HEAL="kubectl -n $NS scale deploy/ollama --replicas=1 && kubectl -n $NS rollout status deploy/ollama --timeout=300s"
# Model zaman aşımı: Ollama'ya gelen yeni bağlantıları NetworkPolicy ile düşür
# (k3s'in ağ politikası denetleyicisi paketleri sessizce atar → istemci zaman aşımı).
# Kurulu (established) keep-alive bağlantıları bir süre akmaya devam edebilir.
export CHAOS_CMD_LLM_HANG="kubectl -n $NS apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: chaos-ollama-blackhole}
spec:
  podSelector: {matchLabels: {app.kubernetes.io/name: ollama}}
  policyTypes: [Ingress]
  ingress: []
YAML"
#   iyileştirme (hang için ayrı koşun, aşağıda): kubectl -n $NS delete networkpolicy chaos-ollama-blackhole
# Yavaş satıcı API'si: Ollama pod'unda tc netem ile gecikme (NET_ADMIN gerekir) ya da
# Bifrost önüne toxiproxy; ikisi de yoksa senaryo atlanır.
export CHAOS_CMD_LLM_SLOW="kubectl -n $NS exec deploy/ollama -- tc qdisc add dev eth0 root netem delay 20s"
# Postgres yeniden başlatma
export CHAOS_CMD_PG_STOP="kubectl -n $NS scale sts/autosecops-postgres --replicas=0 && kubectl -n $NS wait --for=delete pod/autosecops-postgres-0 --timeout=120s"
export CHAOS_CMD_PG_START="kubectl -n $NS scale sts/autosecops-postgres --replicas=1 && kubectl -n $NS rollout status sts/autosecops-postgres --timeout=300s"
# Redis yeniden başlatma
export CHAOS_CMD_REDIS_STOP="kubectl -n $NS scale sts/autosecops-redis --replicas=0 && kubectl -n $NS wait --for=delete pod/autosecops-redis-0 --timeout=120s"
export CHAOS_CMD_REDIS_START="kubectl -n $NS scale sts/autosecops-redis --replicas=1 && kubectl -n $NS rollout status sts/autosecops-redis --timeout=300s"
# Daemon öldürme (yedeksiz): pod'u zorla sil, StatefulSet yeniden yaratır.
export CHAOS_CMD_DAEMON_KILL="kubectl -n $NS delete pod autosecops-daemon-0 --grace-period=0 --force"
export CHAOS_CMD_DAEMON_START="kubectl -n $NS rollout status sts/autosecops-daemon --timeout=300s; kill \$(cat /tmp/pf-daemon.pid) 2>/dev/null; (kubectl -n $NS port-forward svc/autosecops-daemon 18081:8081 >/tmp/pf-daemon.log 2>&1 & echo \$! > /tmp/pf-daemon.pid); sleep 3"
```

> Port-forward, öldürülen pod'la birlikte kopar; `CHAOS_CMD_DAEMON_START`
> onu yeniden kurar (PID dosyasıyla, ada göre öldürmeden). Bu, yük
> üreticisinin bağlantı hatası görüp yeniden denemesine yol açar (beklenen
> davranış).

Daemon sıcak yedeği (W3.9 birleştikten sonra; `daemon.leaderElection.enabled=true`,
iki kopya). Lider öldürülür, takipçi devralmalıdır; Service yalnızca hazır
pod'a yönlendirir, takipçi webhook'ta 503 döner ve yük üreticisi yeniden dener:

```bash
LEADER=$(for p in autosecops-daemon-0 autosecops-daemon-1; do
  kubectl -n $NS exec $p -- python -c "import json,urllib.request;print(json.load(urllib.request.urlopen('http://127.0.0.1:9091/health')).get('role'))" | grep -q leader && echo $p; done)
export CHAOS_CMD_LEADER_KILL="kubectl -n $NS delete pod $LEADER --grace-period=0 --force"
export CHAOS_CMD_LEADER_RESTART="kubectl -n $NS rollout status sts/autosecops-daemon --timeout=300s"
```

Çalıştırma (her senaryo ayrı süreç; sonuçlar `results.json` / `results.md`):

```bash
OUT=/var/lib/autosecops-staging/chaos/$(date -u +%Y%m%dT%H%M%SZ)
# Staging'in backfill aralığı 60 sn ve kesici soğuması 120 sn: model
# senaryolarının sınırı buna göre.
export CHAOS_RECOVERY_LLM_OUTAGE=600 CHAOS_RECOVERY_LLM_TIMEOUT=600 CHAOS_RECOVERY_SLOW_VENDOR=600
python -m tests.perf.chaos --target staging --rate 2 --pre 60 --fault 180 --post 60 \
  --scenario llm_outage,pg_restart,redis_restart,daemon_kill --out "$OUT"
# hang ve slow ayrı (LLM_HEAL farklı):
CHAOS_CMD_LLM_HEAL="kubectl -n $NS delete networkpolicy chaos-ollama-blackhole" \
  python -m tests.perf.chaos --target staging --rate 2 --pre 60 --fault 180 --post 60 \
  --scenario llm_timeout --out "$OUT/timeout"
CHAOS_CMD_LLM_HEAL="kubectl -n $NS exec deploy/ollama -- tc qdisc del dev eth0 root" \
  python -m tests.perf.chaos --target staging --rate 2 --pre 60 --fault 180 --post 60 \
  --scenario slow_vendor --out "$OUT/slow"
```

Aynı senaryolar pytest ile de koşar (yalnızca istenince):

```bash
CHAOS_TESTS=1 CHAOS_TARGET=staging PERF_OUT_DIR=$OUT \
  python -m pytest -c tests/pytest.ini -o addopts= -m chaos tests/perf -k "llm_outage or pg_restart"
```

### Senaryo başına beklenen davranış

| Senaryo | Beklenen | Ek kontrol |
|---|---|---|
| `llm_outage` | Bulgular yazılmaya devam eder; kural şeridi karar vermeye devam eder; model şeridindekiler birikir (`ai_triage_error`), kesici açılır; iyileştirmeden sonra backfill hepsini triage eder | kural şeridi bulguları arıza içinde karara bağlanır; birikim (backlog) arıza süresince artar |
| `llm_timeout` | Aynı; çağrılar `DAEMON_TRIAGE_TIMEOUT` ile kesilir | aynı |
| `pg_restart` | Webhook 200 verip bellekteki kuyruğa alır; yazma yeniden denenir (`_STORE_ATTEMPTS`); kesinti uzarsa yazma bırakılır | kayıp 0 |
| `redis_restart` | Tekilleştirme anahtarları ve LLM kuyruğundaki işler kaybolur; bulgular veritabanında olduğu için backfill tamamlar | kayıp 0, çift satır 0 |
| `daemon_kill` | Bellekteki devir kuyruğu kaybolur; yeniden başlayan daemon yazılmış ama karara bağlanmamış bulguları backfill ile tamamlar | kayıp 0 |
| `daemon_kill_standby` | Takipçi kira süresi (`DAEMON_LEADER_LEASE_SECONDS`) içinde lider olur | kayıp 0, kurtarma ≤ sınır |
| `slow_vendor` | Alım yavaşlamaz; triage gecikir | webhook kabul p95 < 2 sn |

Sonuçta `results.md` tablosu, bu runbook'un sonundaki kayıt şablonuna
kopyalanır. `FAIL` olan her senaryo yeni bir iş paketi olur (plan: "her
bulgu yeni bir İP").

## 6. Bilinen sınırlar (yerel duman koşusunda görülenler)

Yerel duman koşusunun sonuçları `docs/wp/w4.1.md` → Evidence bölümündedir.
Staging koşusu bunları doğrulamalı ya da çürütmelidir:

- **Webhook 200 = bellekte kuyruk.** Daemon webhook'u bulguyu bellekteki devir
  kuyruğuna koyduğu anda 200 döner ve Redis tekilleştirme anahtarını işaretler.
  Daemon o anda öldürülürse kuyruktaki bulgular kaybolur; gönderici yeniden
  gönderse bile tekilleştirme onları atlar. `daemon_kill` senaryosu bunu ölçer.
- **API ile alım daemon'a devretmez.** `/api/ingest/ingest-string` bulguyu
  doğrudan yazar; daemon onu ancak backfill taramasında
  (`DAEMON_ENRICH_BACKFILL_INTERVAL`, varsayılan 300 sn) görür. Bu yoldan gelen
  bulguların gecikmesi bu aralıkla sınırlıdır; SLO'yu webhook yolu için okuyun.
- **Backfill, uçuştaki bulguyu yeniden kuyruğa alabilir.** Triage süresi
  backfill aralığından uzunsa aynı bulgu ikinci kez yönlendirilir ve modele
  ikinci kez gider (`re_decided`). Kayıp değildir, maliyettir.
- **Kesici soğuması sabittir (120 sn).** Model çökmesinden sonraki kurtarma
  en az bu kadar sürer.

## 7. Temizlik

```bash
kill $(cat /tmp/pf-daemon.pid) %2 %3 2>/dev/null   # port-forward'lar (aynı kabukta)
sudo helm upgrade autosecops /opt/autosecops-staging/src/infra/helm/vigil -n $NS --reuse-values \
  --set-json 'daemon.extraEnv=[]' --set config.ALERT_LANES_ENABLED=false --wait
kubectl -n $NS delete secret autosecops-loadtest
shred -u /root/loadtest-webhook-token
sudo systemctl start autosecops-staging-nightly.timer autosecops-staging-replay.timer
```

Gece kurulumu değerleri zaten `values-staging.yaml`'dan yeniden uygular; bu
adım bir sonraki geceyi beklemeden staging'i varsayılana döndürür.

## 8. Kayıt şablonu

```
Tarih / commit:           <UTC> / <sha12>
Profil:                   rate=…, burst=…/… her …, süre=…, rules=…, api=…
Ortam:                    staging VM vCPU/RAM, model, port-forward mı küme içi mi
Kural şeridi p95:         … sn (n=…)      hedef < 5 sn     PASS/FAIL
Küçük model şeridi p95:   … sn (n=…)      hedef < 60 sn    PASS/FAIL
Verdict run p95:          … / n/a          hedef < 10 dk
Kayıp:                    …                hedef 0
Kaos:                     llm_outage …, llm_timeout …, pg_restart …, redis_restart …,
                          daemon_kill …, daemon_kill_standby …, slow_vendor …
Açılan iş paketleri:      …
```
