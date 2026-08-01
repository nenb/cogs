{{/*
Inert Stage 4 static preparation helpers. Rendering these objects is not a
security claim, a production-readiness claim, or cluster prerequisite proof.
*/}}
{{- define "cogs.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cogs.fullname" -}}
{{- if eq .Release.Name .Chart.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "cogs.componentName" -}}
{{- printf "%s-%s" (include "cogs.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cogs.stage4Labels" -}}
app.kubernetes.io/name: {{ include "cogs.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
app.kubernetes.io/part-of: "cogs"
dev.cogs/stage: "4-preparation"
dev.cogs/session: {{ .Values.stage4Preparation.sessionIdentity | quote }}
dev.cogs/security-claim: "none"
dev.cogs/production-ready: "false"
{{- end -}}

{{- define "cogs.stage4.validate" -}}
{{- $v := .Values.stage4Preparation -}}
{{- if ne $v.enabled true -}}
{{- fail "stage4Preparation.enabled must be exactly true inside the preparation guard" -}}
{{- end -}}
{{- if ne $v.nonProductionAcknowledgement true -}}
{{- fail "stage4Preparation.nonProductionAcknowledgement must be exactly true" -}}
{{- end -}}
{{- if empty $v.sessionIdentity -}}
{{- fail "stage4Preparation.sessionIdentity is required" -}}
{{- end -}}
{{- if empty $v.runtimeClassName -}}
{{- fail "stage4Preparation.runtimeClassName is required" -}}
{{- end -}}
{{- if has $v.runtimeClassName (list "runc" "runsc" "default" "docker" "containerd" "oci") -}}
{{- fail "stage4Preparation.runtimeClassName must name a reviewed non-default VM RuntimeClass" -}}
{{- end -}}
{{- $digestPattern := "^[a-z0-9]+([._-][a-z0-9]+)*(:[1-9][0-9]{0,4})?(/[a-z0-9]+([._-][a-z0-9]+)*)+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}$" -}}
{{- if not (regexMatch $digestPattern $v.images.worker) -}}
{{- fail "stage4Preparation.images.worker must be digest pinned" -}}
{{- end -}}
{{- if ne $v.images.proxy "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb" -}}
{{- fail "stage4Preparation.images.proxy must equal the ADR 0011 Envoy pin" -}}
{{- end -}}
{{- if not (regexMatch $digestPattern $v.images.sandbox) -}}
{{- fail "stage4Preparation.images.sandbox must be digest pinned" -}}
{{- end -}}
{{- if eq (len $v.placement.trusted.nodeSelector) 0 -}}
{{- fail "stage4Preparation.placement.trusted.nodeSelector is required" -}}
{{- end -}}
{{- if eq (len $v.placement.sandbox.nodeSelector) 0 -}}
{{- fail "stage4Preparation.placement.sandbox.nodeSelector is required" -}}
{{- end -}}
{{- if deepEqual $v.placement.trusted.nodeSelector $v.placement.sandbox.nodeSelector -}}
{{- fail "trusted and sandbox nodeSelector maps must differ" -}}
{{- end -}}
{{- if eq (len $v.placement.sandbox.tolerations) 0 -}}
{{- fail "stage4Preparation.placement.sandbox.tolerations requires a dedicated taint toleration" -}}
{{- end -}}
{{- if empty $v.storage.workspaceStorageClass -}}
{{- fail "stage4Preparation.storage.workspaceStorageClass is required" -}}
{{- end -}}
{{- if empty $v.storage.sessionStateStorageClass -}}
{{- fail "stage4Preparation.storage.sessionStateStorageClass is required" -}}
{{- end -}}
{{- if eq $v.storage.workspaceStorageClass $v.storage.sessionStateStorageClass -}}
{{- fail "workspaceStorageClass and sessionStateStorageClass must differ" -}}
{{- end -}}
{{- if or (empty $v.openBao.endpoint) (not (hasPrefix "https://" $v.openBao.endpoint)) (contains "@" $v.openBao.endpoint) (contains "?" $v.openBao.endpoint) (contains "#" $v.openBao.endpoint) -}}
{{- fail "stage4Preparation.openBao.endpoint must be credential-free HTTPS without query or fragment" -}}
{{- end -}}
{{- range $key := list "kubernetesAuthMount" "kubernetesAuthRole" "pkiPath" "tokenAudience" -}}
{{- if empty (index $v.openBao $key) -}}
{{- fail (printf "stage4Preparation.openBao.%s is required" $key) -}}
{{- end -}}
{{- end -}}
{{- if or (eq (len $v.openBao.peer.namespaceLabels) 0) (eq (len $v.openBao.peer.podLabels) 0) (lt (int $v.openBao.peer.port) 1) -}}
{{- fail "stage4Preparation.openBao.peer requires namespaceLabels, podLabels, and port" -}}
{{- end -}}
{{- if or (empty $v.otlp.endpoint) (not (hasPrefix "https://" $v.otlp.endpoint)) (contains "@" $v.otlp.endpoint) (contains "?" $v.otlp.endpoint) (contains "#" $v.otlp.endpoint) -}}
{{- fail "stage4Preparation.otlp.endpoint must be credential-free HTTPS without query or fragment" -}}
{{- end -}}
{{- if not (has $v.otlp.protocol (list "grpc" "http/protobuf")) -}}
{{- fail "stage4Preparation.otlp.protocol must be grpc or http/protobuf" -}}
{{- end -}}
{{- if or (eq (len $v.otlp.peer.namespaceLabels) 0) (eq (len $v.otlp.peer.podLabels) 0) (lt (int $v.otlp.peer.port) 1) -}}
{{- fail "stage4Preparation.otlp.peer requires namespaceLabels, podLabels, and port" -}}
{{- end -}}
{{- if empty $v.proxyIdentity.capabilityAudience -}}
{{- fail "stage4Preparation.proxyIdentity.capabilityAudience is required" -}}
{{- end -}}
{{- if ne $v.proxyIdentity.capabilityHandlePrefix "sessions" -}}
{{- fail "stage4Preparation.proxyIdentity.capabilityHandlePrefix must be sessions" -}}
{{- end -}}
{{- if ne $v.proxyIdentity.sourceBindingRequired true -}}
{{- fail "stage4Preparation.proxyIdentity.sourceBindingRequired must be exactly true" -}}
{{- end -}}
{{- range $component := list "worker" "proxy" "sandbox" -}}
{{- $resources := index $v.resources $component -}}
{{- range $bound := list "requests" "limits" -}}
{{- range $quantity := list "cpu" "memory" -}}
{{- if empty (index (index $resources $bound) $quantity) -}}
{{- fail (printf "stage4Preparation.resources.%s.%s.%s is required" $component $bound $quantity) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if empty $v.publicEgressCa -}}
{{- fail "stage4Preparation.publicEgressCa is required" -}}
{{- end -}}
{{- if or (contains "PRIVATE KEY" $v.publicEgressCa) (not (contains "BEGIN CERTIFICATE" $v.publicEgressCa)) -}}
{{- fail "stage4Preparation.publicEgressCa must contain public certificates only; PRIVATE KEY is forbidden" -}}
{{- end -}}
{{- end -}}
