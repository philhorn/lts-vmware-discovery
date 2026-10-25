"""lts-discover: read-only VMware discovery for Proxmox migration planning."""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

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


def _write_json(path, data):
    # Reports name hosts and addresses: readable by the operator only.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1)
        f.write("\n")


def _password():
    pw = os.environ.get("LTS_DISCOVER_PASSWORD")
    return pw if pw else getpass.getpass("Password: ")


def _split_port(target, default):
    """host, host:port or [v6addr]:port -> (host, port)."""
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default


def _pins(values, targets):
    """--thumbprint values -> {target: fingerprint}. HOST=FP pins one host; a bare FP needs a single target."""
    pins = {}
    for v in values:
        if "=" in v:
            target, fp = v.split("=", 1)
            if target not in targets:
                raise ValueError(f"--thumbprint names {target}, which is not a target")
            pins[target] = fp
        elif len(targets) == 1:
            pins[targets[0]] = v
        else:
            raise ValueError("with several hosts, pin each one as --thumbprint HOST=FINGERPRINT")
    return pins


def cmd_collect(args):
    try:
        from pyVmomi import vim

        from . import collect, vsphere
    except ImportError:
        print("the collector needs pyVmomi: pipx install 'lts-vmware-discovery[vsphere]'", file=sys.stderr)
        return 2

    targets = [args.vcenter] if args.vcenter else args.esxi
    source = "vcenter" if args.vcenter else "esxi"
    try:
        pins = _pins(args.thumbprint or [], targets)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    password = _password()
    reports = []
    for target in targets:
        host, port = _split_port(target, args.port)
        print(f"connecting to {target} ...", file=sys.stderr)
        try:
            si = vsphere.connect(host, args.user, password, port=port, thumbprint=pins.get(target), insecure=args.insecure)
        except vsphere.DiscoveryError as e:
            print(e, file=sys.stderr)
            return 1
        except vim.fault.InvalidLogin:
            print(f"{target}: login failed for {args.user}", file=sys.stderr)
            return 1
        except OSError as e:
            print(f"{target}: cannot connect ({e})", file=sys.stderr)
            return 1
        try:
            content = si.RetrieveContent()
            api_type = content.about.apiType
            if source == "vcenter" and api_type != "VirtualCenter":
                print(f"{target} is an ESXi host, not vCenter: use --esxi", file=sys.stderr)
                return 1
            if source == "esxi" and api_type == "VirtualCenter":
                print(f"{target} is vCenter: use --vcenter", file=sys.stderr)
                return 1
            # Check the account before reading any inventory.
            extra = sorted(set(vsphere.session_privileges(content) or []) - vsphere.ALLOWED_PRIVILEGES)
            if extra and not args.allow_extra_privileges:
                print(f"{target}: account {args.user} holds {len(extra)} privileges beyond read-only "
                      f"(e.g. {', '.join(extra[:3])}). Use a read-only account, or pass --allow-extra-privileges.", file=sys.stderr)
                return 1
            raw = vsphere.fetch(si)
        finally:
            vsphere.disconnect(si)
        report = collect.normalize(raw, source, target)
        if extra:
            report["collection"]["warnings"].append(f"{target}: ran with {len(extra)} privileges beyond read-only")
        reports.append(collect.prefix_ids(report, target) if source == "esxi" and len(targets) > 1 else report)

    report = collect.merge(reports) if len(reports) > 1 else reports[0]
    out = Path(args.output or f"lts-discovery-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "report.json", report)
    errors = validate(report)
    if errors:
        for e in errors:
            print(f"report.json: {e}", file=sys.stderr)
        print(f"wrote {out}/report.json but it does not validate; please send it to LTS anyway", file=sys.stderr)
        return 1
    _write_json(out / "summary.json", redact(report))
    print(f"wrote {out}/report.json and {out}/summary.json "
          f"({len(report['hosts'])} hosts, {len(report['vms'])} VMs, {len(report['datastores'])} datastores)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="lts-discover", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="read inventory from vCenter or ESXi hosts (read-only)")
    target = c.add_mutually_exclusive_group(required=True)
    target.add_argument("--vcenter", metavar="HOST", help="vCenter address")
    target.add_argument("--esxi", metavar="HOST", nargs="+", help="one or more ESXi hosts, each HOST or HOST:PORT")
    c.add_argument("--user", required=True, help="read-only account; password from LTS_DISCOVER_PASSWORD or a prompt")
    c.add_argument("--port", type=int, default=443)
    tls = c.add_mutually_exclusive_group()
    tls.add_argument("--thumbprint", action="append", metavar="[HOST=]FINGERPRINT",
                     help="pin a server certificate by SHA-256 (or SHA-1) fingerprint; repeat as HOST=FP for several hosts")
    tls.add_argument("--insecure", action="store_true", help="skip certificate checks (not recommended)")
    c.add_argument("--allow-extra-privileges", action="store_true", help="run even if the account can do more than read")
    c.add_argument("-o", "--output", help="output folder (default lts-discovery-<UTC time>)")
    c.set_defaults(func=cmd_collect)
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
