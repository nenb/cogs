{{/* Included only by templates/NOTES.txt; Helm never submits this source shape. */}}
{{- define "cogs.stage4.notes.configmap" -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "cogs.componentName" (dict "root" . "component" "contract") }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "cogs.stage4Labels" . | nindent 4 }}
    dev.cogs/role: "preparation"
  annotations:
    dev.cogs/notice: "notes-only-static-source-shape-unsafe-to-apply-unqualified"
immutable: true
data:
  status: "NOTES_ONLY_STATIC_SOURCE_SHAPE"
  applySafety: "UNSAFE_TO_APPLY_UNQUALIFIED"
  productionReady: "false"
  runtimeClassName: {{ .Values.stage4Preparation.runtimeClassName | quote }}
  workerImage: {{ .Values.stage4Preparation.images.worker | quote }}
  proxyImage: {{ .Values.stage4Preparation.images.proxy | quote }}
  sandboxImage: {{ .Values.stage4Preparation.images.sandbox | quote }}
  trustedNodeSelector: {{ .Values.stage4Preparation.placement.trusted.nodeSelector | toJson | quote }}
  sandboxNodeSelector: {{ .Values.stage4Preparation.placement.sandbox.nodeSelector | toJson | quote }}
  workspaceStorageClass: {{ .Values.stage4Preparation.storage.workspaceStorageClass | quote }}
  workspaceSize: {{ .Values.stage4Preparation.storage.workspaceSize | quote }}
  workspaceAccessMode: {{ .Values.stage4Preparation.storage.workspaceAccessMode | quote }}
  workspaceVolumeMode: {{ .Values.stage4Preparation.storage.workspaceVolumeMode | quote }}
  workspaceVolumeBindingMode: {{ .Values.stage4Preparation.storage.workspaceVolumeBindingMode | quote }}
  workspaceReclaimPolicy: {{ .Values.stage4Preparation.storage.workspaceReclaimPolicy | quote }}
  workspaceRetention: {{ .Values.stage4Preparation.storage.workspaceRetention | quote }}
  sessionStateStorageClass: {{ .Values.stage4Preparation.storage.sessionStateStorageClass | quote }}
  sessionStateSize: {{ .Values.stage4Preparation.storage.sessionStateSize | quote }}
  sessionStateAccessMode: {{ .Values.stage4Preparation.storage.sessionStateAccessMode | quote }}
  sessionStateVolumeMode: {{ .Values.stage4Preparation.storage.sessionStateVolumeMode | quote }}
  sessionStateVolumeBindingMode: {{ .Values.stage4Preparation.storage.sessionStateVolumeBindingMode | quote }}
  sessionStateReclaimPolicy: {{ .Values.stage4Preparation.storage.sessionStateReclaimPolicy | quote }}
  sessionStateRetention: {{ .Values.stage4Preparation.storage.sessionStateRetention | quote }}
  sessionStateRetentionSeconds: {{ printf "%.0f" (float64 .Values.stage4Preparation.storage.sessionStateRetentionSeconds) | quote }}
  storageLaunchContractVersion: "cogs.stage4-storage-launch-contract/v1"
  workspaceExclusiveWriterLease: "ONE_FENCED_WRITER_EXPIRY_NEVER_AUTHORIZES_TAKEOVER"
  storageCleanupContract: "AMBIGUITY_PRESERVES_ATTACHMENTS_STATE_AND_LEASE"
  openBaoEndpointReference: {{ .Values.stage4Preparation.openBao.endpoint | quote }}
  openBaoKubernetesAuthMountReference: {{ .Values.stage4Preparation.openBao.kubernetesAuthMount | quote }}
  openBaoKubernetesAuthRoleReference: {{ .Values.stage4Preparation.openBao.kubernetesAuthRole | quote }}
  openBaoPkiPathReference: {{ .Values.stage4Preparation.openBao.pkiPath | quote }}
  openBaoTokenAudience: {{ .Values.stage4Preparation.openBao.tokenAudience | quote }}
  openBaoPeerSelector: {{ dict "namespaceLabels" .Values.stage4Preparation.openBao.peer.namespaceLabels "podLabels" .Values.stage4Preparation.openBao.peer.podLabels "port" .Values.stage4Preparation.openBao.peer.port | toJson | quote }}
  otlpEndpointReference: {{ .Values.stage4Preparation.otlp.endpoint | quote }}
  otlpProtocol: {{ .Values.stage4Preparation.otlp.protocol | quote }}
  otlpPeerSelector: {{ dict "namespaceLabels" .Values.stage4Preparation.otlp.peer.namespaceLabels "podLabels" .Values.stage4Preparation.otlp.peer.podLabels "port" .Values.stage4Preparation.otlp.peer.port | toJson | quote }}
  proxyCapabilityAudience: {{ .Values.stage4Preparation.proxyIdentity.capabilityAudience | quote }}
  proxyCapabilitySourceBindingRequired: {{ .Values.stage4Preparation.proxyIdentity.sourceBindingRequired | quote }}
  ephemeralProxyCapability: "ABSENT_FUTURE_TRUSTED_LAUNCHER_ONLY"
  policyContractVersion: "cogs.stage4-policy-contract/v1"
  policyContractAuthority: "static-only-stage4-policy"
  policyContractQualification: "pending-exact-eks-cni-runtime"
  trustedWorkerIdentityContract: "SCOPED_PROJECTED_OPENBAO_TOKEN_EXACT_ROLE_AND_USER_HANDLES_ONLY"
  sandboxServiceAccountContract: "cogs-sandbox-inert"
  trustedSandboxServiceAccountsDistinct: "true"
  sandboxIdentityContract: "INERT_SERVICE_ACCOUNT_NO_TOKEN_RBAC_OPENBAO_OR_CLOUD_IDENTITY_FIELDS"
  openBaoHandleScopeContract: "EXACT_USERS_CURRENT_USER_ONLY_ORGANIZATIONS_FORBIDDEN"
  proxyCapabilityContract: "IMMUTABLE_SESSION_INSTANCE_POD_ID_GENERATION_EXPIRY_BOUND_DENY_DRAIN_REPLACE_NO_FALLBACK"
  otlpPayloadContract: "METADATA_ONLY_BOUNDED_DROP_NON_AUTHORIZING"
  auditWalFailureContract: "APPEND_AND_SYNC_BEFORE_CREDENTIAL_USE_FAILURE_DENIES_AND_REQUIRES_RECYCLE"
  resourceProfile: {{ .Values.stage4Preparation.resourceProfile | quote }}
  idleSeconds: {{ .Values.stage4Preparation.lifecycle.idleSeconds | quote }}
  hardSeconds: {{ .Values.stage4Preparation.lifecycle.hardSeconds | quote }}
  terminationGraceSeconds: {{ .Values.stage4Preparation.lifecycle.terminationGraceSeconds | quote }}
  auditWalMaxBytes: {{ printf "%.0f" (float64 .Values.stage4Preparation.auditWalMaxBytes) | quote }}
  publicEgressCaConfigMapReference: {{ .Values.stage4Preparation.publicEgressCaConfigMap | quote }}
  unresolvedChecks: |-
    RuntimeClass existence and non-runc behavior
    KVM, Kata, QEMU, and distinct guest identity
    trusted and sandbox node availability and placement
    CNI default-deny, IPv4, IPv6, UDP, and exact-session enforcement
    CSI access modes, attach, detach, reattach, and writer lease
    OpenBao and OTLP reachability, roles, policy, and TLS chains
    image availability, signatures, and runtime identity
    per-session SSH and proxy capability issuance and source binding
    proxy upstream egress, immutable route materialization, and revocation
    pinned NIC v0.11.0 lacks custom launch-template ID/version and CpuOptions.NestedVirtualization inputs
    EKS launch-template, nested-virtualization, recovery, performance, and cleanup evidence
{{- end -}}
