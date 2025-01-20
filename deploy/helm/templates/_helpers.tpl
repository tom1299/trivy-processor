{{/*
Expand the name of the chart.
*/}}
{{- define "trivy-processor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "trivy-processor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "trivy-processor.labels" -}}
helm.sh/chart: {{ include "trivy-processor.chart" . }}
{{ include "trivy-processor.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "trivy-processor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-processor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "trivy-processor.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}