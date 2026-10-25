# lts-vmware-discovery

Read-only discovery of VMware vCenter and standalone ESXi estates, for planning a move to Proxmox VE. Built by London Technology Services (LTS).

The tool reads inventory and performance history, writes a report on your own machine, and changes nothing in your environment. Nothing is uploaded unless you ask it to.

> Status: 0.1.0. The report schema, validator and redaction are in place. The live vSphere collector, the RVTools importer and the HTML report come next.

## What you get

| File | Contents | Leaves your site? |
| --- | --- | --- |
| `report.json` | Full inventory: clusters, hosts, NICs, storage adapters, vSAN disk groups, datastores and their SAN or NFS backing, vSwitches, vmkernels, VMs, snapshots, CBT, backup markers, 30-day performance | Only if you send it to LTS |
| `report.html` | The same report as one self-contained page (coming next) | Only if you send it |
| `summary.json` | Redacted subset: no names, IPs, MACs, serials, hostnames, IQNs or LUN ids; names replaced by salted hashes | Only with `--submit` (coming later) |

The format is defined by [`lts_discovery/discovery.schema.json`](lts_discovery/discovery.schema.json) (JSON Schema 2020-12). Every source, whether live vCenter, a single ESXi host or an imported export, produces the same format.

## Access it needs

Create a dedicated account and give it the built-in **Read-only** role at the vCenter root, with *Propagate to children* ticked. That role holds `System.Anonymous`, `System.View` and `System.Read`. Two optional privileges add detail:

| Privilege | Adds |
| --- | --- |
| `StorageProfile.View` | VM storage policies |
| `Global.Licenses` | vSphere edition and licence expiry |

Without vCenter (for example after its licence expires), point the tool at each ESXi host with a local user holding the host's **ReadOnly** role. The report lists the privileges the session actually held.

Supported: vSphere and ESXi 6.5 and later.

## Use

```sh
pipx install git+https://github.com/philhorn/lts-vmware-discovery
lts-discover validate report.json
lts-discover redact report.json -o summary.json
```

## Develop

Python 3.10+, standard library only (pyVmomi is an optional extra for the live collector).

```sh
python3 -m unittest discover -s tests -v
```

Fixtures in `tests/fixtures/` are synthetic. Never commit a real customer report; `.gitignore` blocks the default output names.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
