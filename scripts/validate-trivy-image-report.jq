def nonempty_string:
  type == "string" and length > 0;

def valid_vulnerability:
  type == "object" and
  (.VulnerabilityID | nonempty_string) and
  (.PkgID | nonempty_string) and
  (.PkgName | nonempty_string) and
  (.InstalledVersion | nonempty_string) and
  (.Severity == "UNKNOWN" or .Severity == "LOW" or .Severity == "MEDIUM" or .Severity == "HIGH" or .Severity == "CRITICAL") and
  ((has("FixedVersion") | not) or .FixedVersion == null or (.FixedVersion | type == "string"));

def valid_result($os_family):
  type == "object" and
  (.Class == "os-pkgs" or .Class == "lang-pkgs") and
  (.Target | nonempty_string) and
  (.Type | nonempty_string) and
  (if .Class == "os-pkgs" then .Type == $os_family else true end) and
  ((.Vulnerabilities == null) or (.Vulnerabilities | type == "array")) and
  all((.Vulnerabilities // [])[]; valid_vulnerability);

type == "object" and
.SchemaVersion == 2 and
.ArtifactName == $subject and
.ArtifactType == "container_image" and
(.Metadata | type == "object") and
(.Metadata.RepoDigests | type == "array") and
(.Metadata.RepoDigests | index($subject) != null) and
(.Metadata.OS | type == "object") and
(.Metadata.OS.Family | nonempty_string) and
(.Metadata.OS.Name | nonempty_string) and
(.Metadata.OS.Family as $os_family |
  (.Results | type == "array" and length > 0) and
  all(.Results[]; valid_result($os_family)) and
  any(.Results[]; .Class == "os-pkgs" and .Type == $os_family))
