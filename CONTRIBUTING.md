# Contributing

## Ground rules

- **Honesty contract:** the README status table must always match the code. A PR that adds a
  capability updates that table in the same change.
- **License:** contributions accepted under [Apache-2.0](LICENSE).
- **Sign-off (DCO):** commit with `git commit -s`.
- **Fail closed:** any change to rule generation must preserve the invariant that an invalid
  policy produces **no** ruleset.

## Dev loop

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m microseg.cli lint examples/kitchen.json
```

## Design conventions

- Keep the linter and generator **pure** (in/out data only) so the zero-trust invariant stays
  unit-testable without a firewall. I/O lives in `cli.py`.
- Every new lint rule ships with a test and a README status row.
- The suite's edge is the security × food-service intersection — prefer checks a generic firewall
  linter can't make (trust-tier pivots, device-zone mapping) over rehashing what nftables already
  validates.
