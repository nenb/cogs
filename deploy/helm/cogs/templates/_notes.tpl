{{/* The complete warning-bounded payload is included only by templates/NOTES.txt. */}}
{{- define "cogs.stage4.notes.payload" -}}
{{- if .Values.stage4Preparation.enabled -}}
{{- include "cogs.stage4.validate" . -}}
# COGS NOTES-ONLY STATIC SOURCE SHAPES BEGIN: WARNING — UNSAFE TO APPLY; UNQUALIFIED
# These are review-only Kubernetes YAML source shapes. Helm does not submit NOTES.txt as manifests.
# They prove no cluster, runtime, storage, network-policy, identity, or security property.
{{ include "cogs.stage4.notes.configmap" . }}
---
{{ include "cogs.stage4.notes.serviceaccounts" . }}
---
{{ include "cogs.stage4.notes.service" . }}
---
{{ include "cogs.stage4.notes.networkpolicies" . }}
---
{{ include "cogs.stage4.notes.podtemplates" . }}
# COGS NOTES-ONLY STATIC SOURCE SHAPES END: WARNING — UNSAFE TO APPLY; UNQUALIFIED
{{- else -}}
COGS Stage 4 notes-only static source shapes are disabled. This chart submits zero Kubernetes manifests.
{{- end -}}
{{- end -}}
