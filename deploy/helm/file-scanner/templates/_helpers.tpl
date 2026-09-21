{{/* Chart name, release-scoped resource name, labels. */}}
{{- define "file-scanner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "file-scanner.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "file-scanner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "file-scanner.labels" -}}
helm.sh/chart: {{ include "file-scanner.chart" . }}
app.kubernetes.io/name: {{ include "file-scanner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels for one component: app, worker, clamav, redis. */}}
{{- define "file-scanner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "file-scanner.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "file-scanner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "file-scanner.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "file-scanner.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "file-scanner.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "file-scanner.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* clamd address the app and worker talk to. */}}
{{- define "file-scanner.clamavHosts" -}}
{{- if .Values.config.CLAMAV_HOSTS -}}
{{- .Values.config.CLAMAV_HOSTS -}}
{{- else if .Values.clamav.enabled -}}
{{- printf "%s-clamav:%d" (include "file-scanner.fullname" .) (int .Values.clamav.port) -}}
{{- end -}}
{{- end -}}

{{/* exav address the app and worker talk to (empty: no exav). */}}
{{- define "file-scanner.exavHosts" -}}
{{- if .Values.config.EXAV_HOSTS -}}
{{- .Values.config.EXAV_HOSTS -}}
{{- else if .Values.exav.enabled -}}
{{- printf "%s-exav:%d" (include "file-scanner.fullname" .) (int .Values.exav.port) -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by the app and the worker. */}}
{{- define "file-scanner.env" -}}
- name: PORT
  value: {{ .Values.app.port | quote }}
- name: CLAMAV_HOSTS
  value: {{ include "file-scanner.clamavHosts" . | quote }}
{{- with (include "file-scanner.exavHosts" .) }}
- name: EXAV_HOSTS
  value: {{ . | quote }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: WORKER_BROKER_URL
  value: {{ printf "redis://%s-redis:6379/0" (include "file-scanner.fullname" .) | quote }}
{{- end }}
{{- range .Values.extraEnv }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end -}}

{{- define "file-scanner.envFrom" -}}
- configMapRef:
    name: {{ include "file-scanner.fullname" . }}
{{- /* The chart's own Secret only exists when an inline value is set, so it
     is optional; a named existingSecret must exist or the pod stays Pending
     rather than start with no signing key. */}}
- secretRef:
    name: {{ include "file-scanner.secretName" . }}
    optional: {{ not .Values.secrets.existingSecret }}
{{- end -}}
