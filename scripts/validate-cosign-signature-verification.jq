type == "array" and
length > 0 and
all(.[];
  .critical.type == "https://sigstore.dev/cosign/sign/v1" and
  .critical.identity["docker-reference"] == $subject and
  .critical.image["docker-manifest-digest"] == $digest
)
