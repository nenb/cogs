# ADR 0237: Bind the rejected wrong-ref static dispatch

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

Final G run 33267664208 was incorrectly dispatched from `fix/issue42-static-event-contract`. Guard v21 correctly rejected it before history or source effects because only protected `main` is authorized. The failure grants no static observation, qualification, promotion, or retry claim.

Preserve the run in authenticated history rather than deleting or ignoring it. Guard v22 adds a separate singleton rejected-branch predecessor class bound to run ID 33267664208, attempt 1, failed conclusion, workflow head `77efaff8d306ce1ff0e4a283d83db9ae065ecbb3`, exact title for H `dfb28c2e8deb7fed90da095c41b4d556c737af97`, repository identity, and branch `fix/issue42-static-event-contract`. Every other historical and current run still requires protected `main`; branch, head, title, conclusion, attempt, or repository drift fails closed.

After this correction is reviewed and merged to protected main, authorize exactly one new G dispatch for the same earlier H. This grants no AWS, provider, deployment, campaign, production, release, qualification, or promotion authority.
