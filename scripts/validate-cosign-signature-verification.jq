type == "array" and
length == 2 and
([.[].critical.type] | sort) ==
  (["https://sigstore.dev/cosign/sign/v1", "https://spdx.dev/Document"] | sort) and
all(.[];
  .critical.identity["docker-reference"] == $subject and
  .critical.image["docker-manifest-digest"] == $digest
)
