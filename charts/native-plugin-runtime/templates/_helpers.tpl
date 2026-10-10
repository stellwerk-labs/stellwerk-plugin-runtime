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

{{/* The package repository without tag or digest. Attestation referrers are
pulled from it by their own digests. */}}
{{- define "native-plugin-runtime.packageRepository" -}}
{{- regexReplaceAll "(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:[0-9a-f]{64}$" .Values.package.reference "" -}}
{{- end -}}

{{/* Every replica fetches and verifies its own package copy into an emptyDir.
Registry credentials, registry CA, ORAS and trust material reach only these init
containers, never the plugin, UI or token containers. */}}
{{- define "native-plugin-runtime.fetchInitContainers" -}}
{{- if and .Values.package.plainHTTP .Values.package.registryCASecret.name }}
{{- fail "package.registryCASecret cannot be combined with package.plainHTTP" }}
{{- end }}
{{- $managedKey := eq .Values.trust.mode "managed-key-no-tlog" }}
{{- $attestations := .Values.package.attestations }}
{{- $predicateTypes := dict "sbom" "https://spdx.dev/Document" "provenance" "https://stellwerk.dev/attestation/source-provenance/v1" }}
- name: fetch-package-envelope
  image: {{ required "images.oras is required" .Values.images.oras | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - manifest
    - fetch
    - --output=/package/oci-manifest.json
    {{- if .Values.package.registryCASecret.name }}
    - --ca-file=/registry/ca.crt
    - --plain-http=false
    {{- end }}
    {{- if .Values.package.plainHTTP }}
    - --plain-http
    {{- end }}
    {{- if .Values.package.registryConfigSecret.name }}
    - --registry-config=/registry/config.json
    {{- end }}
    - {{ .Values.package.reference | quote }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
    {{- if .Values.package.registryConfigSecret.name }}
    - name: registry-config
      mountPath: /registry/config.json
      subPath: config.json
      readOnly: true
    {{- end }}
    {{- if .Values.package.registryCASecret.name }}
    - name: registry-ca
      mountPath: /registry/ca.crt
      subPath: ca.crt
      readOnly: true
    {{- end }}
    - name: temporary
      mountPath: /tmp
- name: verify-package-envelope
  image: {{ required "images.runtime is required" .Values.images.runtime | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - verify-envelope
    - --oci-manifest=/package/oci-manifest.json
    - --package-digest={{ regexFind "sha256:[0-9a-f]{64}$" .Values.package.reference }}
    - --manifest-sha256={{ .Values.package.manifestSHA256 }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
      readOnly: true
{{- if $managedKey }}
{{- range $name := list "sbom" "provenance" }}
{{- with index $attestations $name }}
# Signed attestation referrer of the package, pulled by its own digest.
# Untrusted until the gate and Cosign verified it.
- name: fetch-package-{{ $name }}
  image: {{ $.Values.images.oras | quote }}
  imagePullPolicy: {{ $.Values.images.pullPolicy }}
  args:
    - pull
    - --no-tty
    - --output=/attestations/{{ $name }}
    {{- if $.Values.package.registryCASecret.name }}
    - --ca-file=/registry/ca.crt
    - --plain-http=false
    {{- end }}
    {{- if $.Values.package.plainHTTP }}
    - --plain-http
    {{- end }}
    {{- if $.Values.package.registryConfigSecret.name }}
    - --registry-config=/registry/config.json
    {{- end }}
    - {{ printf "%s@%s" (include "native-plugin-runtime.packageRepository" $) . | quote }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml $.Values.initResources | nindent 4 }}
  volumeMounts:
    - name: attestations
      mountPath: /attestations
    {{- if $.Values.package.registryConfigSecret.name }}
    - name: registry-config
      mountPath: /registry/config.json
      subPath: config.json
      readOnly: true
    {{- end }}
    {{- if $.Values.package.registryCASecret.name }}
    - name: registry-ca
      mountPath: /registry/ca.crt
      subPath: ca.crt
      readOnly: true
    {{- end }}
    - name: temporary
      mountPath: /tmp
{{- end }}
{{- end }}
# Policy gate: the operator's trust bootstrap must pin this plugin's
# publisher with managed-key-no-tlog. Verifies the signature and the SBOM
# and provenance attestations as one release set; a required attestation
# that is not configured fails closed. Writes the pinned key of each part.
- name: verify-package-publisher
  image: {{ .Values.images.runtime | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - verify-publisher
    - --trust-bootstrap=/trust/publishers.json
    - --bundle=/signature/oci-manifest.sigstore.json
    {{- range $name := list "sbom" "provenance" }}
    {{- if index $attestations $name }}
    - --{{ $name }}-bundle=/attestations/{{ $name }}/{{ $name }}.sigstore.json
    {{- end }}
    {{- end }}
    - --oci-manifest=/package/oci-manifest.json
    - --plugin-id={{ .Values.plugin.id }}
    - --key-dir=/verify
    {{- with .Values.package.installedDigest }}
    - --installed-digest={{ . }}
    {{- end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
      readOnly: true
    - name: trust
      mountPath: /trust/publishers.json
      subPath: publishers.json
      readOnly: true
    - name: signature-bundle
      mountPath: /signature/oci-manifest.sigstore.json
      subPath: oci-manifest.sigstore.json
      readOnly: true
    - name: attestations
      mountPath: /attestations
      readOnly: true
    - name: verify
      mountPath: /verify
# Independent Cosign verification of each part with the key the gate
# selected. Skipping the transparency log is valid only after that gate.
- name: verify-package-signature
  image: {{ required "images.cosign is required for managed-key-no-tlog trust" .Values.images.cosign | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - verify-blob
    - --insecure-ignore-tlog
    - --key=/verify/package.pub
    - --bundle=/signature/oci-manifest.sigstore.json
    - /package/oci-manifest.json
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
      readOnly: true
    - name: verify
      mountPath: /verify
      readOnly: true
    - name: signature-bundle
      mountPath: /signature/oci-manifest.sigstore.json
      subPath: oci-manifest.sigstore.json
      readOnly: true
    - name: temporary
      mountPath: /tmp
{{- range $name := list "sbom" "provenance" }}
{{- if index $attestations $name }}
- name: verify-package-{{ $name }}
  image: {{ $.Values.images.cosign | quote }}
  imagePullPolicy: {{ $.Values.images.pullPolicy }}
  args:
    - verify-blob-attestation
    - --insecure-ignore-tlog
    - --key=/verify/{{ $name }}.pub
    - --type={{ index $predicateTypes $name }}
    - --bundle=/attestations/{{ $name }}/{{ $name }}.sigstore.json
    - /package/oci-manifest.json
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml $.Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
      readOnly: true
    - name: verify
      mountPath: /verify
      readOnly: true
    - name: attestations
      mountPath: /attestations
      readOnly: true
    - name: temporary
      mountPath: /tmp
{{- end }}
{{- end }}
{{- end }}
- name: pull-package
  image: {{ .Values.images.oras | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - pull
    - --no-tty
    - --output=/package
    {{- if .Values.package.registryCASecret.name }}
    - --ca-file=/registry/ca.crt
    - --plain-http=false
    {{- end }}
    {{- if .Values.package.plainHTTP }}
    - --plain-http
    {{- end }}
    {{- if .Values.package.registryConfigSecret.name }}
    - --registry-config=/registry/config.json
    {{- end }}
    - {{ .Values.package.reference | quote }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
    {{- if .Values.package.registryConfigSecret.name }}
    - name: registry-config
      mountPath: /registry/config.json
      subPath: config.json
      readOnly: true
    {{- end }}
    {{- if .Values.package.registryCASecret.name }}
    - name: registry-ca
      mountPath: /registry/ca.crt
      subPath: ca.crt
      readOnly: true
    {{- end }}
    - name: temporary
      mountPath: /tmp
- name: validate-package
  image: {{ .Values.images.runtime | quote }}
  imagePullPolicy: {{ .Values.images.pullPolicy }}
  args:
    - validate
    {{- include "native-plugin-runtime.commonArgs" . | nindent 4 }}
    - --trust-state={{ if $managedKey }}verified-local-key{{ else }}untrusted-development{{ end }}
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
  resources:
    {{- toYaml .Values.initResources | nindent 4 }}
  volumeMounts:
    - name: package
      mountPath: /package
{{- end -}}

{{/* The operator's Secrets (trust bootstrap, signature bundle, registry
config and registry CA) are mounted file by file with subPath. A Secret volume
exposes each key as a symlink into its ..data directory, and the runtime opens its inputs
with O_NOFOLLOW; a subPath mount is the plain file itself. subPath mounts do
not follow later Secret updates, which costs nothing here: the init chain
reads them once at Pod start, so a trust change applies on the next Pod
start (rollout restart). */}}
{{- define "native-plugin-runtime.fetchVolumes" -}}
{{- $managedKey := eq .Values.trust.mode "managed-key-no-tlog" }}
{{- if $managedKey }}
- name: verify
  emptyDir:
    medium: Memory
    sizeLimit: 1Mi
- name: attestations
  emptyDir:
    medium: Memory
    sizeLimit: 3Mi
- name: trust
  secret:
    secretName: {{ required "trust.bootstrapSecret.name is required" .Values.trust.bootstrapSecret.name }}
    defaultMode: 0440
    items:
      - key: {{ .Values.trust.bootstrapSecret.key }}
        path: publishers.json
- name: signature-bundle
  secret:
    secretName: {{ required "trust.signatureBundleSecret.name is required" .Values.trust.signatureBundleSecret.name }}
    defaultMode: 0440
    items:
      - key: {{ .Values.trust.signatureBundleSecret.key }}
        path: oci-manifest.sigstore.json
{{- end }}
{{- if .Values.package.registryConfigSecret.name }}
- name: registry-config
  secret:
    secretName: {{ .Values.package.registryConfigSecret.name }}
    defaultMode: 0440
    items:
      - key: {{ .Values.package.registryConfigSecret.key }}
        path: config.json
{{- end }}
{{- if .Values.package.registryCASecret.name }}
- name: registry-ca
  secret:
    secretName: {{ .Values.package.registryCASecret.name }}
    defaultMode: 0440
    items:
      - key: {{ .Values.package.registryCASecret.key | quote }}
        path: ca.crt
{{- end }}
{{- end -}}

{{/* Registry egress for the fetch init containers: exactly the configured
mirror endpoints (single addresses or exact in-cluster selectors) and ports.
NetworkPolicy is per Pod, so the plugin container can reach these endpoints
too; it holds no registry credentials. */}}
{{- define "native-plugin-runtime.registryMirrorEgress" -}}
{{- range .Values.networkPolicy.registryMirrors }}
- to:
    {{- if .cidr }}
    - ipBlock:
        cidr: {{ .cidr | quote }}
    {{- else }}
    - namespaceSelector:
        matchLabels:
          {{- toYaml .namespaceSelector | nindent 10 }}
      podSelector:
        matchLabels:
          {{- toYaml .podSelector | nindent 10 }}
    {{- end }}
  ports:
    - protocol: TCP
      port: {{ .port }}
{{- end }}
{{- end -}}
