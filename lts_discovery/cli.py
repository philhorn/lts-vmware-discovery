"""lts-discover command line. Collectors and importers arrive in later releases."""

import argparse
import json
import sys

from . import __version__
from .redact import redact
from .validate import validate


def _load(path):
    with open(path) as f:
        return json.load(f)


def cmd_validate(args):
    status = 0
    for path in args.reports:
        errors = validate(_load(path))
        for e in errors:
            print(f"{path}: {e}", file=sys.stderr)
        print(f"{path}: {'ok' if not errors else f'{len(errors)} error(s)'}")
        status |= bool(errors)
    return status


def cmd_redact(args):
    report = _load(args.report)
    errors = validate(report)
    if errors:
        print(f"{args.report}: not a valid report, run lts-discover validate", file=sys.stderr)
        return 1
    summary = redact(report)
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=1)
        f.write("\n")
    print(f"wrote {args.output}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="lts-discover", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check reports against the schema")
    v.add_argument("reports", nargs="+")
    v.set_defaults(func=cmd_validate)
    r = sub.add_parser("redact", help="write the redacted summary of a report")
    r.add_argument("report")
    r.add_argument("-o", "--output", default="summary.json")
    r.set_defaults(func=cmd_redact)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
