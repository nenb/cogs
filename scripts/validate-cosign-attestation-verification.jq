(length > 0) and
all(.[];
  .payloadType == "application/vnd.in-toto+json" and
  (.payload | type) == "string" and
  (.signatures | type) == "array" and
  (.signatures | length) > 0
) and
(
  [.[] | try (.payload | @base64d | fromjson) catch null] as $statements |
  all($statements[];
    type == "object" and
    ._type == "https://in-toto.io/Statement/v0.1" and
    .predicateType == "https://spdx.dev/Document" and
    (.predicate | type) == "object" and
    .subject == [{
      name: $repository,
      digest: {sha256: $digest_hex}
    }]
  )
)
