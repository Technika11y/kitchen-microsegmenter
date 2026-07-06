"""CLI: `lint` a device inventory, or `generate` nftables rules from it.

Fails CLOSED — it refuses to emit firewall rules from a policy that has errors, and it
never applies anything itself. You review the output and apply it deliberately."""
import argparse
import json
import sys

from .model import Policy
from .policy import lint, has_errors
from .nftables import generate


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="kitchen-microsegmenter")
    parser.add_argument("command", choices=["lint", "generate"])
    parser.add_argument("inventory", help="path to a device inventory JSON file")
    args = parser.parse_args(argv)

    with open(args.inventory) as fh:
        policy = Policy.from_dict(json.load(fh))

    findings = lint(policy)
    for f in findings:
        print(f"{f['severity'].upper():5} {f['rule']}  {f['message']}", file=sys.stderr)

    if args.command == "lint":
        return 1 if has_errors(findings) else 0

    # generate
    if has_errors(findings):
        print("refusing to generate rules: policy has errors (fail closed)", file=sys.stderr)
        return 1
    print(generate(policy))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
