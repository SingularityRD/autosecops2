{{/*
Shared `env:` and `envFrom:` block for backend/daemon/llm-worker pods.

Usage (inside a container spec):
  envFrom:
    {{- include "vigil.envFrom" . | nindent 12 }}
  env:
    {{- include "vigil.env" . | nindent 12 }}

Both helpers take the root context directly. They pull the generated ConfigMap
and Secret, plus the discrete POSTGRES_* connection parts and REDIS_URL (which
have to be assembled at render time because they embed service DNS + a secret
reference). The app builds and URL-encodes the DSN from POSTGRES_* itself, so
passwords with special characters survive intact (no pre-built DATABASE_URL).

NOTE: secret.yaml is only rendered when secrets.existingSecret is empty AND
secrets.externalSecret.enabled is false. Either way the secretRef below points
at a Secret of the same name (user-supplied, ESO-materialized, or
chart-templated).
*/}}
{{- define "vigil.envFrom" -}}
- configMapRef:
    name: {{ include "vigil.configmap.fullname" . }}
- secretRef:
    name: {{ include "vigil.secret.fullname" . }}
{{- end -}}

{{/*
State Directory. VIGIL_DIR is deliberately NOT in vigil.env: it must only be set
where the volume is actually mounted, or a workload advertises a path it cannot
write. Include all three together, or none.
*/}}
{{- define "vigil.stateEnv" -}}
- name: VIGIL_DIR
  value: {{ .Values.stateDirectory.mountPath | quote }}
{{- end -}}

{{- define "vigil.stateVolumeMount" -}}
- name: vigil-state
  mountPath: {{ .Values.stateDirectory.mountPath }}
{{- end -}}

{{- define "vigil.stateVolume" -}}
- name: vigil-state
  {{- toYaml .Values.stateDirectory.volume | nindent 2 }}
{{- end -}}

{{/*
Case evidence store: a persistent volume at <State Directory>/evidence, where
CaseEvidenceService writes (vigil_path("evidence")). Mounted over the State
Directory volume so no extra setting is needed. Include the mount and the
volume together, or neither, and only when evidence.persistence.enabled.
*/}}
{{- define "vigil.evidence.claimName" -}}
{{- .Values.evidence.persistence.existingClaim | default (printf "%s-evidence" (include "vigil.fullname" .)) -}}
{{- end -}}

{{/*
How many pods mount the evidence claim: the backend's replicas (2 for an HPA),
the daemon (2 with its hot standby), the llm-workers (2 for an HPA or KEDA) and
the backup job when it archives the store.
*/}}
{{- define "vigil.evidence.mounters" -}}
{{- $n := ternary 2 (int .Values.backend.replicaCount) .Values.backend.autoscaling.enabled -}}
{{- if .Values.daemon.enabled }}{{ $n = add $n (ternary 2 1 .Values.daemon.leaderElection.enabled) }}{{ end -}}
{{- $w := .Values.llmWorker -}}
{{- if $w.enabled }}{{ $n = add $n (ternary 2 (int $w.replicaCount) (or $w.autoscaling.enabled $w.autoscaling.keda.enabled)) }}{{ end -}}
{{- if and .Values.backup.enabled .Values.backup.includeEvidence }}{{ $n = add $n 1 }}{{ end -}}
{{- $n -}}
{{- end -}}

{{/*
Refuses an evidence store the cluster cannot schedule: accessModes must be set,
and a ReadWriteOnce claim (one node) cannot be shared by several pods that
may land on different nodes.
*/}}
{{- define "vigil.evidence.validate" -}}
{{- $p := .Values.evidence.persistence -}}
{{- if $p.enabled -}}
{{- if not $p.accessModes -}}
{{- fail "evidence.persistence.enabled=true needs an explicit evidence.persistence.accessModes, e.g. {ReadWriteMany} with an RWX storageClassName (NFS, CephFS, Longhorn RWX, EFS ...)" -}}
{{- end -}}
{{- $mounters := int (include "vigil.evidence.mounters" .) -}}
{{- if and (has "ReadWriteOnce" $p.accessModes) (not (has "ReadWriteMany" $p.accessModes)) (gt $mounters 1) -}}
{{- fail (printf "evidence.persistence.accessModes is ReadWriteOnce but %d pods mount the evidence claim (backend, daemon, llm-worker, backup); they may run on different nodes, where a ReadWriteOnce volume cannot attach. Use ReadWriteMany with an RWX storageClassName or existingClaim, or leave evidence.persistence.enabled=false." $mounters) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
"true" when the chart is about to create a ReadWriteMany evidence claim on the
cluster's default StorageClass, which on many clusters (bare metal, local-path,
most block storage) cannot provide ReadWriteMany: the claim then stays Pending
and the pods that mount it never start. NOTES.txt warns about it.
*/}}
{{- define "vigil.evidence.rwxOnDefaultClass" -}}
{{- $p := .Values.evidence.persistence -}}
{{- if and $p.enabled (not $p.existingClaim) (not $p.storageClassName) (has "ReadWriteMany" ($p.accessModes | default list)) }}true{{ end -}}
{{- end -}}

{{- define "vigil.evidenceVolumeMount" -}}
- name: vigil-evidence
  mountPath: {{ printf "%s/evidence" (trimSuffix "/" .Values.stateDirectory.mountPath) }}
{{- end -}}

{{- define "vigil.evidenceVolume" -}}
- name: vigil-evidence
  persistentVolumeClaim:
    claimName: {{ include "vigil.evidence.claimName" . }}
{{- end -}}

{{/*
Operator-supplied CA PEM for TLS-inspecting proxies. Include all three together
(or none) on backend, daemon, llm-worker, agent-worker, and agent-serve only —
the same rule as vigil.state*: env without the mount advertises a path the
container cannot read. Empty existingSecret and existingConfigMap skip every
helper. Prefer the Secret when both are set.
*/}}
{{- define "vigil.caBundleEnv" -}}
{{- if or .Values.caBundle.existingSecret .Values.caBundle.existingConfigMap }}
- name: SSL_CERT_FILE
  value: {{ .Values.caBundle.mountPath | quote }}
- name: REQUESTS_CA_BUNDLE
  value: {{ .Values.caBundle.mountPath | quote }}
- name: NODE_EXTRA_CA_CERTS
  value: {{ .Values.caBundle.mountPath | quote }}
{{- end }}
{{- end -}}

{{- define "vigil.caBundleVolumeMount" -}}
{{- if or .Values.caBundle.existingSecret .Values.caBundle.existingConfigMap }}
- name: vigil-ca-bundle
  mountPath: {{ .Values.caBundle.mountPath }}
  subPath: ca-bundle.pem
  readOnly: true
{{- end }}
{{- end -}}

{{- define "vigil.caBundleVolume" -}}
{{- if .Values.caBundle.existingSecret }}
- name: vigil-ca-bundle
  secret:
    secretName: {{ .Values.caBundle.existingSecret | quote }}
    items:
      - key: {{ .Values.caBundle.key | default "ca.crt" | quote }}
        path: ca-bundle.pem
{{- else if .Values.caBundle.existingConfigMap }}
- name: vigil-ca-bundle
  configMap:
    name: {{ .Values.caBundle.existingConfigMap | quote }}
    items:
      - key: {{ .Values.caBundle.key | default "ca.crt" | quote }}
        path: ca-bundle.pem
{{- end }}
{{- end -}}

{{- define "vigil.env" -}}
- name: HOME
  value: "/home/vigil"
- name: POSTGRES_HOST
  value: {{ include "vigil.postgres.host" . | quote }}
- name: POSTGRES_PORT
  value: {{ include "vigil.postgres.port" . | toString | quote }}
- name: POSTGRES_DB
  value: {{ include "vigil.postgres.database" . | quote }}
{{/* Runtime login; schema owner stays vigil.postgres.username (StatefulSet, db-init). */}}
- name: POSTGRES_USER
  value: "vigil_app"
{{- if .Values.redis.bitnami.enabled }}
{{- if .Values.redis.bitnami.auth.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "vigil.redis.bitnami.passwordSecret" . }}
      key: {{ include "vigil.redis.bitnami.passwordSecretKey" . }}
{{- end }}
- name: REDIS_URL
  value: {{ include "vigil.redis.url" . | quote }}
{{- else if .Values.redis.enabled }}
- name: REDIS_URL
  value: {{ include "vigil.redis.url" . | quote }}
{{- else if .Values.redis.external.url }}
- name: REDIS_URL
  value: {{ .Values.redis.external.url | quote }}
{{- else if .Values.redis.external.existingSecret }}
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.external.existingSecret }}
      key: {{ .Values.redis.external.existingSecretKey | default "REDIS_URL" }}
{{- end }}
{{- end -}}

{{/*
Discrete Redis parts for the agent pods, for the reason vigil.env ships discrete
POSTGRES_*: the kubelet substitutes $(REDIS_PASSWORD) into a URL unencoded, so one
holding @ / : or # misparses. Only the agent reads these, and only when REDIS_HOST
is set (services/agent/core/db.ts::redisConfig). Nothing is emitted for an external
Redis given as a URL — there are no parts to name.
*/}}
{{- define "vigil.agentRedisEnv" -}}
{{- if .Values.redis.bitnami.enabled }}
- name: REDIS_HOST
  value: {{ .Values.redis.bitnami.fullnameOverride | default (printf "%s-redis-master" .Release.Name) | quote }}
- name: REDIS_PORT
  value: "6379"
- name: REDIS_DB
  value: {{ include "vigil.redis.database" . | quote }}
{{- else if .Values.redis.enabled }}
- name: REDIS_HOST
  value: {{ include "vigil.redis.fullname" . | quote }}
- name: REDIS_PORT
  value: {{ .Values.redis.service.port | default 6379 | toString | quote }}
- name: REDIS_DB
  value: {{ include "vigil.redis.database" . | quote }}
{{- end }}
{{- end -}}
