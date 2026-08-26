# ADR 0196: Classify the native denied output sibling

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H40 completed production SSH with status zero, no stderr, all eight authenticated network markers, and all 21 measurements. The six required allow/deny sensors increased and the three unrelated input/forward deny sensors remained zero. The host output catch-all deny sensor also increased by three packets and 408 bytes during the 210-second guest program. Because this sensor itself is the terminal drop rule, an increase proves additional traffic was denied rather than admitted.

Classify only `output-other-drop` as a monotonic `denied-sibling`. It may increase but cannot decrease or change identity. All six positive sensors must still increase, all three remaining zero sensors must remain exactly zero, the authenticated markers and restored route digest remain exact, and journal validation binds the sole denied-sibling name and category.

H40 and its uncertain cleanup state were preserved before exact private-infrastructure cleanup. It remains diagnostic-only and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
