#!/usr/bin/python3
"""Provision the fixed host-global NFT writer state from staged trusted source."""

import os
import sys

REMOTE = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1 or os.path.realpath(__file__) != (
        "/var/lib/cogs/stage2-completion-v1/source/scripts/provision-stage2-nft-owner.py"
    ):
        return 64
    sys.path.insert(0, REMOTE)
    import completion_kata_nft_owner as owner

    try:
        owner.provision_initial_free()
    except (owner.NftOwnerError, OSError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
