{{/* Included only by templates/NOTES.txt; Helm never submits these source shapes. */}}
{{- define "cogs.stage4.notes.serviceaccounts" -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "cogs.componentName" (dict "root" . "component" "trusted") }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "cogs.stage4Labels" . | nindent 4 }}
    dev.cogs/role: "trusted"
  annotations:
    dev.cogs/notice: "notes-only-static-source-shape-unsafe-to-apply-unqualified"
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cogs-sandbox-inert
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "cogs.stage4Labels" . | nindent 4 }}
    dev.cogs/role: "sandbox"
  annotations:
    dev.cogs/notice: "notes-only-static-source-shape-unsafe-to-apply-unqualified"
automountServiceAccountToken: false
{{- end -}}
