{{/* Included only by templates/NOTES.txt; Helm never submits this source shape. */}}
{{- define "cogs.stage4.notes.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "cogs.componentName" (dict "root" . "component" "proxy") }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "cogs.stage4Labels" . | nindent 4 }}
    dev.cogs/role: "trusted"
    dev.cogs/proxy: "true"
  annotations:
    dev.cogs/notice: "notes-only-static-selector-source-shape-unsafe-to-apply-unqualified"
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/instance: {{ .Release.Name | quote }}
    dev.cogs/session: {{ .Values.stage4Preparation.sessionIdentity | quote }}
    dev.cogs/role: "trusted"
    dev.cogs/proxy: "true"
  ports:
    - name: proxy
      protocol: TCP
      port: 15001
      targetPort: proxy
{{- end -}}
