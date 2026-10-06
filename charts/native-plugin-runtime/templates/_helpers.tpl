{{- define "native-plugin-runtime.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "native-plugin-runtime.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "native-plugin-runtime.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "native-plugin-runtime.labels" -}}
app.kubernetes.io/name: {{ include "native-plugin-runtime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Values.plugin.version | quote }}
stellwerk.dev/plugin-id: {{ .Values.plugin.id | quote }}
{{- end -}}

{{- define "native-plugin-runtime.selectorLabels" -}}
app.kubernetes.io/name: {{ include "native-plugin-runtime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "native-plugin-runtime.runtimeSelectorLabels" -}}
{{ include "native-plugin-runtime.selectorLabels" . }}
app.kubernetes.io/component: runtime
{{- end -}}

{{- define "native-plugin-runtime.migrationSelectorLabels" -}}
{{ include "native-plugin-runtime.selectorLabels" . }}
app.kubernetes.io/component: migration
{{- end -}}

{{- define "native-plugin-runtime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ include "native-plugin-runtime.fullname" . }}
{{- else -}}
{{ required "serviceAccount.name is required when create=false" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "native-plugin-runtime.migrationServiceAccountName" -}}
{{- if .Values.migration.serviceAccount.create -}}
{{ include "native-plugin-runtime.fullname" . }}-migration
{{- else -}}
{{ required "migration.serviceAccount.name is required when create=false" .Values.migration.serviceAccount.name }}
{{- end }}
{{- end -}}

{{- define "native-plugin-runtime.commonArgs" -}}
- --package-dir=/package
- --manifest=/package/plugin-manifest.json
- --state-file=/package/runtime-state.json
- --plugin-id={{ .Values.plugin.id }}
- --plugin-version={{ .Values.plugin.version }}
- --manifest-sha256={{ .Values.package.manifestSHA256 }}
{{- if eq .Values.trust.mode "development-untrusted" }}
- --development-untrusted
{{- end }}
{{- end -}}
