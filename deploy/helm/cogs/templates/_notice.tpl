{{/*
Default-disabled Stage 4 notes-only static source-shape helpers. The NOTES payload
is unsafe to apply, unqualified, and proves no Kubernetes, runtime, or security property.
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
dev.cogs/qualification: "none"
dev.cogs/production-ready: "false"
{{- end -}}

{{- define "cogs.stage4.validate" -}}
{{- $v := .Values.stage4Preparation -}}
{{- if ne $v.enabled true -}}
{{- fail "stage4Preparation.enabled must be exactly true for notes-only static source shapes" -}}
{{- end -}}
{{- if ne $v.nonProductionAcknowledgement true -}}
{{- fail "stage4Preparation.nonProductionAcknowledgement must be exactly true" -}}
{{- end -}}
{{- $dnsLabel := "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" -}}
{{- $dnsSubdomain := "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$" -}}
{{- if or (not (kindIs "string" $v.sessionIdentity)) (not (regexMatch $dnsLabel $v.sessionIdentity)) -}}
{{- fail "stage4Preparation.sessionIdentity must be a nonempty DNS label" -}}
{{- end -}}
{{- if or (not (kindIs "string" $v.runtimeClassName)) (not (regexMatch $dnsSubdomain $v.runtimeClassName)) -}}
{{- fail "stage4Preparation.runtimeClassName must be a DNS subdomain" -}}
{{- end -}}
{{- if has $v.runtimeClassName (list "runc" "runsc" "default" "docker" "containerd" "oci") -}}
{{- fail "stage4Preparation.runtimeClassName must name a reviewed non-default VM RuntimeClass" -}}
{{- end -}}
{{- $digestPattern := "^[a-z0-9]+([._-][a-z0-9]+)*(:[1-9][0-9]{0,4})?(/[a-z0-9]+([._-][a-z0-9]+)*)+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}$" -}}
{{- if or (not (kindIs "string" $v.images.worker)) (not (regexMatch $digestPattern $v.images.worker)) -}}
{{- fail "stage4Preparation.images.worker must be digest pinned" -}}
{{- end -}}
{{- if ne $v.images.proxy "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb" -}}
{{- fail "stage4Preparation.images.proxy must equal the ADR 0011 Envoy pin" -}}
{{- end -}}
{{- if or (not (kindIs "string" $v.images.sandbox)) (not (regexMatch $digestPattern $v.images.sandbox)) -}}
{{- fail "stage4Preparation.images.sandbox must be digest pinned" -}}
{{- end -}}

{{- if ne (index $v.placement.trusted.nodeSelector "cogs.dev/node-domain") "trusted" -}}
{{- fail "stage4Preparation.placement.trusted.nodeSelector must include cogs.dev/node-domain=trusted" -}}
{{- end -}}
{{- if ne (index $v.placement.sandbox.nodeSelector "cogs.dev/node-domain") "sandbox-kata" -}}
{{- fail "stage4Preparation.placement.sandbox.nodeSelector must include cogs.dev/node-domain=sandbox-kata" -}}
{{- end -}}
{{- if not (deepEqual $v.placement.trusted.tolerations (list)) -}}
{{- fail "stage4Preparation.placement.trusted.tolerations must be exactly empty" -}}
{{- end -}}
{{- $sandboxToleration := list (dict "key" "cogs.dev/sandbox" "operator" "Equal" "value" "kata" "effect" "NoSchedule") -}}
{{- if not (deepEqual $v.placement.sandbox.tolerations $sandboxToleration) -}}
{{- fail "stage4Preparation.placement.sandbox.tolerations must be exactly cogs.dev/sandbox=kata:NoSchedule" -}}
{{- end -}}

{{- $labelKey := "^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*\\/)?[A-Za-z0-9]([-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?$" -}}
{{- $labelValue := "^[A-Za-z0-9]([-_.A-Za-z0-9]{0,61}[A-Za-z0-9])?$" -}}
{{- range $labels := list $v.placement.trusted.nodeSelector $v.placement.sandbox.nodeSelector $v.openBao.peer.namespaceLabels $v.openBao.peer.podLabels $v.otlp.peer.namespaceLabels $v.otlp.peer.podLabels -}}
{{- if or (not (kindIs "map" $labels)) (eq (len $labels) 0) (gt (len $labels) 16) -}}
{{- fail "stage4Preparation selector label maps must contain 1 to 16 labels" -}}
{{- end -}}
{{- range $key, $value := $labels -}}
{{- if not (regexMatch $labelKey $key) -}}
{{- fail "stage4Preparation selector label key is malformed" -}}
{{- end -}}
{{- if or (not (kindIs "string" $value)) (not (regexMatch $labelValue $value)) -}}
{{- fail "stage4Preparation selector label value is malformed" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- if or (not (kindIs "string" $v.storage.workspaceStorageClass)) (not (regexMatch $dnsSubdomain $v.storage.workspaceStorageClass)) -}}
{{- fail "stage4Preparation.storage.workspaceStorageClass must be a DNS subdomain" -}}
{{- end -}}
{{- if or (not (kindIs "string" $v.storage.sessionStateStorageClass)) (not (regexMatch $dnsSubdomain $v.storage.sessionStateStorageClass)) -}}
{{- fail "stage4Preparation.storage.sessionStateStorageClass must be a DNS subdomain" -}}
{{- end -}}
{{- if eq $v.storage.workspaceStorageClass $v.storage.sessionStateStorageClass -}}
{{- fail "workspaceStorageClass and sessionStateStorageClass must differ" -}}
{{- end -}}
{{- if or (ne $v.storage.workspaceSize "20Gi") (ne $v.storage.workspaceAccessMode "ReadWriteOncePod") -}}
{{- fail "stage4Preparation.storage workspace contract must be 20Gi ReadWriteOncePod" -}}
{{- end -}}
{{- if or (ne $v.storage.sessionStateSize "5Gi") (ne $v.storage.sessionStateAccessMode "ReadWriteOncePod") -}}
{{- fail "stage4Preparation.storage session-state contract must be 5Gi ReadWriteOncePod" -}}
{{- end -}}

{{- $httpsEndpoint := "^https://([A-Za-z0-9]([-A-Za-z0-9.]*[A-Za-z0-9])?|\\[[0-9A-Fa-f:]+\\])(:[1-9][0-9]{0,4})?(/[^[:space:]?#]*)?$" -}}
{{- if or (not (kindIs "string" $v.openBao.endpoint)) (not (regexMatch $httpsEndpoint $v.openBao.endpoint)) -}}
{{- fail "stage4Preparation.openBao.endpoint must be credential-free HTTPS without query or fragment" -}}
{{- end -}}
{{- $pathPattern := "^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$" -}}
{{- range $key := list "kubernetesAuthMount" "pkiPath" -}}
{{- $value := index $v.openBao $key -}}
{{- if or (not (kindIs "string" $value)) (not (regexMatch $pathPattern $value)) (gt (len $value) 256) -}}
{{- fail (printf "stage4Preparation.openBao.%s must be a bounded path" $key) -}}
{{- end -}}
{{- end -}}
{{- range $key := list "kubernetesAuthRole" "tokenAudience" -}}
{{- $value := index $v.openBao $key -}}
{{- if or (not (kindIs "string" $value)) (empty $value) (gt (len $value) 256) (contains " " $value) -}}
{{- fail (printf "stage4Preparation.openBao.%s is malformed" $key) -}}
{{- end -}}
{{- end -}}
{{- if or (not (kindIs "string" $v.otlp.endpoint)) (not (regexMatch $httpsEndpoint $v.otlp.endpoint)) -}}
{{- fail "stage4Preparation.otlp.endpoint must be credential-free HTTPS without query or fragment" -}}
{{- end -}}
{{- range $namedEndpoint := list (dict "name" "openBao" "endpoint" $v.openBao.endpoint) (dict "name" "otlp" "endpoint" $v.otlp.endpoint) -}}
{{- $portMatch := regexFind ":[0-9]+(/|$)" $namedEndpoint.endpoint -}}
{{- if $portMatch -}}
{{- $endpointPort := $portMatch | trimPrefix ":" | trimSuffix "/" | int -}}
{{- if or (lt $endpointPort 1) (gt $endpointPort 65535) -}}
{{- fail (printf "stage4Preparation.%s.endpoint port must be from 1 through 65535" $namedEndpoint.name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not (has $v.otlp.protocol (list "grpc" "http/protobuf")) -}}
{{- fail "stage4Preparation.otlp.protocol must be grpc or http/protobuf" -}}
{{- end -}}
{{- range $namedPeer := list (dict "name" "openBao" "peer" $v.openBao.peer) (dict "name" "otlp" "peer" $v.otlp.peer) -}}
{{- $port := $namedPeer.peer.port -}}
{{- if not (or (kindIs "float64" $port) (kindIs "int" $port) (kindIs "int64" $port)) -}}
{{- fail (printf "stage4Preparation.%s.peer.port must be an integer from 1 through 65535" $namedPeer.name) -}}
{{- end -}}
{{- if or (lt (int $port) 1) (gt (int $port) 65535) (ne (float64 (int $port)) (float64 $port)) -}}
{{- fail (printf "stage4Preparation.%s.peer.port must be an integer from 1 through 65535" $namedPeer.name) -}}
{{- end -}}
{{- end -}}

{{- if or (not (kindIs "string" $v.proxyIdentity.capabilityAudience)) (empty $v.proxyIdentity.capabilityAudience) (gt (len $v.proxyIdentity.capabilityAudience) 256) (contains " " $v.proxyIdentity.capabilityAudience) -}}
{{- fail "stage4Preparation.proxyIdentity.capabilityAudience is malformed" -}}
{{- end -}}
{{- if ne $v.proxyIdentity.sourceBindingRequired true -}}
{{- fail "stage4Preparation.proxyIdentity.sourceBindingRequired must be exactly true" -}}
{{- end -}}
{{- if hasKey $v "resources" -}}
{{- fail "stage4Preparation.resources is forbidden; resourceProfile selects fixed positive resource bounds" -}}
{{- end -}}
{{- if ne $v.resourceProfile "stage4-fixed-bounded-v1" -}}
{{- fail "stage4Preparation.resourceProfile must be stage4-fixed-bounded-v1" -}}
{{- end -}}
{{- range $lifecycle := list (dict "name" "idleSeconds" "expected" 1800) (dict "name" "hardSeconds" "expected" 28800) (dict "name" "terminationGraceSeconds" "expected" 30) -}}
{{- $value := index $v.lifecycle $lifecycle.name -}}
{{- if not (or (kindIs "float64" $value) (kindIs "int" $value) (kindIs "int64" $value)) -}}
{{- fail (printf "stage4Preparation.lifecycle.%s must be exactly the required integer" $lifecycle.name) -}}
{{- end -}}
{{- $number := float64 $value -}}
{{- if or (ne $number (floor $number)) (ne $number (float64 $lifecycle.expected)) -}}
{{- fail (printf "stage4Preparation.lifecycle.%s must be exactly %d as an integer" $lifecycle.name $lifecycle.expected) -}}
{{- end -}}
{{- end -}}
{{- if not (or (kindIs "float64" $v.auditWalMaxBytes) (kindIs "int" $v.auditWalMaxBytes) (kindIs "int64" $v.auditWalMaxBytes)) -}}
{{- fail "stage4Preparation.auditWalMaxBytes must be an integer from 1048576 through 1073741824" -}}
{{- end -}}
{{- $walBytes := float64 $v.auditWalMaxBytes -}}
{{- if or (ne $walBytes (floor $walBytes)) (lt $walBytes 1048576.0) (gt $walBytes 1073741824.0) -}}
{{- fail "stage4Preparation.auditWalMaxBytes must be an integer from 1048576 through 1073741824" -}}
{{- end -}}

{{- if hasKey $v "publicEgressCa" -}}
{{- fail "stage4Preparation.publicEgressCa is removed; use publicEgressCaConfigMap without inline CA data" -}}
{{- end -}}
{{- if or (not (kindIs "string" $v.publicEgressCaConfigMap)) (not (regexMatch $dnsSubdomain $v.publicEgressCaConfigMap)) (gt (len $v.publicEgressCaConfigMap) 253) -}}
{{- fail "stage4Preparation.publicEgressCaConfigMap must be a bounded DNS-safe ConfigMap reference" -}}
{{- end -}}
{{- end -}}
