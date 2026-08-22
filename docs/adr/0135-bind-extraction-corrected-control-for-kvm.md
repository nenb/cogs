# ADR 0135: Bind extraction-corrected control for KVM

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22

After reviewed H `1eaec52dd4e2f1222548362e92adc780a2169025` and static binding `e9e4ea6aef35c9d4cb821e2fcc6adf480eec87f3` passed exact-head CI and were fast-forwarded, attempt-one no-KVM run `32600501461` completed successfully. Exact artifact `9482770087` was independently retained at `/Users/nenb/.pi/artifacts/cogs/issue42-static-control-32600501461`.

Exact identities are:

- ZIP SHA-256 `44730dbdab45e49329f178346257d1e7d9bde177d4244397c283c7521c9a3520`;
- custody SHA-256 `8ef79fed43ebc0dc0686ab82a56fddb64d5c037b987504c90ccd66102453ff85`;
- control SHA-256 `d32dad750fdae5118ba164d394145a3c3e7e45894524c2a17cbd502ecb80e26d`;
- envelope SHA-256 `fe98cac091799369ea8d7b236916812d39bac274d15148ebb89390876c0319b1`;
- runtime SHA-256 `ca120ffffb8b76d37afedaa74688bab42e5fb2c20c1e1711e5a175c043ce6e02`;
- source-manifest SHA-256 `ec4c46f2247df2fad872dd3f1f7e147d775dfb568fcb7e520ceb7d3653108768`.

Commit the thirteen exact members in a later directional G and bind the local qualification guard to these identities and reviewed workflow SHA-256 `b9e4b406740ea7800e7bab0810ebdcb8af6cdf6470520c4923672fc6bc251465`. Run `32596053811` remains the exact third completed/failure predecessor; it did not reach KVM and cleanup certainty is not claimed.

This permits only a reviewed replacement local KVM dispatch after exact-head CI, protected-main fast-forward, variable configuration, and unchanged closed history. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
