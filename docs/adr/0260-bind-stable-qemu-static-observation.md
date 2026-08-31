# ADR 0260: Bind stable-QEMU static observation

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-31

The sole V24 no-KVM static-control observation for stable-QEMU H succeeded on protected `main`: run `33348451013`, attempt 1, workflow head `ad892f4149b78f2d48f289592c4f59211bf7d8f5`, H `1fc2dea2dcefea2aaf71a80356e0f5ed946e9991`, artifact ID `9742819865`, artifact digest `22b10486248bb5ee9b7bf32ae8a0e2d8f08bbbe4f3fa526aff0db520e53faa7b`, and size 37,060 bytes. Every static guard, preparation, production, upload, cleanup, and no-runtime boundary passed.

Exact numeric-ID readback contains 13 members and no others. Static control SHA-256 is `d94af3687d21c432946f3bb1bc40b76fc8dad786fea2cc51366d1651a8a33926`; execution envelope SHA-256 is `a1485942096350516e054fb4cf1c4bf412537c9b3337a9b4141c7e97b83b2e58`; runtime manifest SHA-256 remains `4b37f48d7dbb0eb023ec6f05598d92f8fd88c2d98cf8a0515bb3fc042bd3a347`. The envelope binds source manifest `509dacc4a83b45a2da1ca7892210de8434a2b9de5b2a478ce4d8197f85967f3a` and the earlier H. Stage those exact bytes.

Bind failed qualification run `33323414697`, attempt 1, prior H `bf0479a012b39c074ecb623ea83e85b3dc3ebe36`, control head `95151289288631bfc047983af1f499df2cf7a202`, exact title, and failure conclusion as the fourteenth non-authorizing predecessor. Its full lifecycle and exact cleanup passed but terminal evidence failed and no artifact exists.

After this package and qualification guard merge on protected `main`, freeze that merge as directional G describing earlier H and authorize exactly one attempt-1 formal fresh qualification. Raise only the complete tracked-source cardinality bound from 1,221 to exactly 1,222 files and retain all other bounds. This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
