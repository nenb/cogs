#!/usr/bin/env python3
"""Portable commitment check for no-mint rehearsal grants."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
spec = importlib.util.spec_from_file_location(
    "stage2_prebuilt_rehearsal_grant_test",
    ROOT / "scripts/stage2-prebuilt-rehearsal-grant.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
import completion_campaign_production as production

fixed = {"implementation_revision": "1" * 40,
         "control_revision": "2" * 40,
         "static_control_sha256": "3" * 64,
         "rootfs_descriptor_sha256": "4" * 64}
for route in ("full", "readiness"):
    value = module.grant_value(route, "123", fixed); value.pop("version")
    production.CycleLaunchGrant(**value)

print("stage2 prebuilt rehearsal grant checks passed")
