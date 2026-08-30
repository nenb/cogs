#!/usr/bin/env python3
"""Zero-argument private full-cycle owner entry."""
import os
import completion_cycle_evidence as evidence
import completion_kata_coordinator as coordinator


def main():
    receipt = coordinator._run_fixed_full_cycle()
    raw = evidence._consume_cycle_receipt(receipt)
    os.write(1, raw)


if __name__ == "__main__":
    main()
