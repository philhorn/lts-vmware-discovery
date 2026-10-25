# lts-vmware-discovery

Read-only discovery of VMware vCenter and standalone ESXi estates, for planning a move to Proxmox VE. Built by London Technology Services (LTS).

The tool reads inventory and performance history, writes a report on your own machine, and changes nothing in your environment. Nothing is uploaded unless you ask it to.

> Status: 0.2.0. The collector reads vCenter or standalone ESXi hosts (6.5 and later). Performance history, the RVTools importer and the HTML report come next.

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

Install on any machine that can reach the hosts on port 443 (Python 3.10 or later):

```sh
pipx install "lts-vmware-discovery[vsphere] @ git+https://github.com/philhorn/lts-vmware-discovery"
```

Collect from vCenter:

```sh
lts-discover collect --vcenter vcsa.example.test --user lts-discovery@vsphere.local
```

Collect from standalone ESXi hosts, with no vCenter needed. Name each host, and add `:PORT` if it isn't 443:

```sh
lts-discover collect --esxi esx01.example.test esx02.example.test --user lts-discovery
```

The password is read from a prompt, or from `LTS_DISCOVER_PASSWORD` if set. It is never taken as an argument, so it stays out of shell history.

The tool stops if the account can do more than read. Use a read-only account, or pass `--allow-extra-privileges` if you accept the risk.

**Certificates.** ESXi hosts usually have self-signed certificates, so the first run fails with the host's SHA-256 fingerprint in the error. Compare that fingerprint with the one on the host's console or in the Host Client (Manage, Security & users, Certificates). If they match, run again with `--thumbprint <fingerprint>`, or with `--thumbprint HOST=<fingerprint>` once per host when scanning several. The session then trusts only that exact certificate. `--insecure` skips the check entirely and is not recommended.

The output folder (`lts-discovery-<UTC time>/`) holds `report.json` and `summary.json`, both readable only by you. To re-check or re-redact a report:

```sh
lts-discover validate report.json
lts-discover redact report.json -o summary.json
```

## Develop

Python 3.10+. The schema, validator and redaction use only the standard library; the collector needs pyVmomi 8.0.1 or later.

```sh
python3 -m unittest discover -s tests -v                          # collector tests skip without pyVmomi
LTS_VCSIM=/path/to/vcsim python3 -m unittest discover -s tests -v  # plus end-to-end runs against govmomi's vcsim
```

Fixtures in `tests/fixtures/` are synthetic. Never commit a real customer report; `.gitignore` blocks the default output names.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
