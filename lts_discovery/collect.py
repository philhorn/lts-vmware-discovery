"""Turn vSphere objects into a discovery report.

normalize() is pure: it takes what vsphere.fetch() returned and builds the
report dict, so tests can feed it hand-built pyVmomi data objects.
"""

from datetime import datetime, timezone

from . import __version__
from .redact import new_salt

GIB = 1024 ** 3

HBA_TYPES = [  # most specific class first
    ("FibreChannelOverEthernetHba", "fcoe"),
    ("FibreChannelHba", "fc"),
    ("InternetScsiHba", "iscsi"),
    ("SerialAttachedHba", "sas"),
    ("PcieHba", "nvme"),
    ("TcpHba", "nvme"),
    ("RdmaHba", "nvme"),
    ("BlockHba", "sata"),
]
RAID_DRIVERS = ("lsi_mr3", "megaraid", "smartpqi", "nhpsa", "hpsa", "aacraid", "lsi_msgpt")
CONTROLLERS = {
    "ParaVirtualSCSIController": "pvscsi",
    "VirtualLsiLogicSASController": "lsilogic_sas",
    "VirtualLsiLogicController": "lsilogic",
    "VirtualBusLogicController": "buslogic",
    "VirtualAHCIController": "sata",
    "VirtualNVMEController": "nvme",
    "VirtualIDEController": "ide",
}
NICS = {
    "VirtualVmxnet3": "vmxnet3", "VirtualVmxnet3Vrdma": "vmxnet3", "VirtualVmxnet2": "vmxnet2",
    "VirtualE1000e": "e1000e", "VirtualE1000": "e1000", "VirtualPCNet32": "pcnet32", "VirtualSriovEthernetCard": "sriov",
}
DISK_MODES = {"persistent": "persistent", "independent_persistent": "independent_persistent",
              "independent_nonpersistent": "independent_nonpersistent"}
VMK_SERVICES = {
    "management": "management", "vmotion": "vmotion", "vSphereProvisioning": "provisioning",
    "vSphereReplication": "replication", "vSphereReplicationNFC": "nfc", "faultToleranceLogging": "ft",
    "vsan": "vsan", "vsanWitness": "vsan_witness",
}
LINUX_HINTS = ("linux", "rhel", "centos", "ubuntu", "debian", "sles", "oracle", "fedora", "photon",
               "almalinux", "rocky", "coreos", "asianux", "amazonlinux", "mandriva", "turbolinux")
DATASTORE_TYPES = {"VMFS": "vmfs", "NFS": "nfs", "NFS41": "nfs41", "VSAN": "vsan", "VVOL": "vvol"}


def kind(obj):
    """Last part of a pyVmomi type name: vim.vm.device.VirtualE1000e -> VirtualE1000e."""
    return type(obj).__name__.rsplit(".", 1)[-1]


def moid(obj):
    return obj._moId if obj is not None else None


def compact(d):
    """Drop keys whose value is None so optional schema fields are simply absent."""
    return {k: v for k, v in d.items() if v is not None}


def gb(n_bytes):
    return round(n_bytes / GIB, 1) if n_bytes is not None else None


# --- hosts -----------------------------------------------------------------

def _pci_ids(pci_devices):
    return {p.id: f"{p.vendorId & 0xffff:04x}:{p.deviceId & 0xffff:04x}" for p in pci_devices or []}


def _serial(system_info):
    serial = getattr(system_info, "serialNumber", None)
    if serial:
        return serial
    for ident in system_info.otherIdentifyingInfo or []:
        if ident.identifierType and ident.identifierType.key in ("SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag"):
            return ident.identifierValue
    return None


def _hba_type(hba):
    name = kind(hba)
    for cls, t in HBA_TYPES:
        if name == cls:
            return t
    if (hba.driver or "").startswith(RAID_DRIVERS):
        return "raid"
    return "other"


def _hba_identifier(hba):
    name = kind(hba)
    if name == "InternetScsiHba":
        return hba.iScsiName
    if name in ("FibreChannelHba", "FibreChannelOverEthernetHba") and hba.portWorldWideName:
        wwn = f"{hba.portWorldWideName & 0xffffffffffffffff:016x}"
        return ":".join(wwn[i:i + 2] for i in range(0, 16, 2))
    return None


def _disk(lun):
    size = lun.capacity.block * lun.capacity.blockSize if getattr(lun, "capacity", None) else 0
    name = lun.canonicalName or ""
    if lun.ssd is None:
        k = "unknown"
    elif lun.ssd:
        k = "nvme" if name.startswith(("t10.NVMe", "eui.")) else "ssd"
    else:
        k = "hdd"
    return compact({"device": name, "vendor": (lun.vendor or "").strip() or None,
                    "model": (lun.model or "").strip() or None, "size_gb": gb(size), "kind": k})


def _vmk_services(nic_mgr_info):
    services = {}
    for cfg in (nic_mgr_info.netConfig if nic_mgr_info else None) or []:
        for key in cfg.selectedVnic or []:
            device = key.rsplit("-", 1)[-1]  # e.g. management.key-vim.host.VirtualNic-vmk0
            services.setdefault(device, []).append(VMK_SERVICES.get(cfg.nicType, "other"))
    return services


def _vlan(port_config):
    vlan = getattr(port_config, "vlan", None) if port_config else None
    if vlan is None:
        return None
    if kind(vlan) == "TrunkVlanSpec":
        ranges = ",".join(f"{r.start}-{r.end}" if r.start != r.end else str(r.start) for r in vlan.vlanId or [])
        return f"trunk:{ranges}"
    return vlan.vlanId if isinstance(vlan.vlanId, int) else None


def dvs_portgroups(raw):
    """dvs uuid -> [{name, vlan}] for non-uplink distributed port groups (vCenter only)."""
    uuid_by_dvs = {moid(o): p["uuid"] for o, p in raw.get("dvswitches", [])}
    out = {}
    for _, p in raw.get("dvportgroups", []):
        if p.get("config.uplink") or "-DVUplinks-" in p["name"]:  # older APIs lack config.uplink
            continue
        uuid = uuid_by_dvs.get(moid(p.get("config.distributedVirtualSwitch")))
        out.setdefault(uuid, []).append({"name": p["name"], "vlan": _vlan(p.get("config.defaultPortConfig"))})
    return out


def _vswitches(net, dvs_pgs):
    pnic_names = {p.key: p.device for p in net.pnic or []}
    pg_by_key = {pg.key: pg for pg in net.portgroup or []}
    out = []
    for sw in net.vswitch or []:
        pgs = [pg_by_key[k] for k in sw.portgroup or [] if k in pg_by_key]
        out.append({
            "name": sw.name, "kind": "standard", "mtu": sw.mtu,
            "uplinks": [pnic_names.get(k, k) for k in sw.pnic or []],
            "portgroups": [{"name": pg.spec.name, "vlan": pg.spec.vlanId} for pg in pgs],
        })
    for sw in net.proxySwitch or []:
        backing = sw.spec.backing if sw.spec else None
        uplinks = [spec.pnicDevice for spec in (getattr(backing, "pnicSpec", None) or [])]
        out.append({"name": sw.dvsName, "kind": "distributed", "mtu": sw.mtu, "uplinks": uplinks,
                    "portgroups": sorted(dvs_pgs.get(sw.dvsUuid, []), key=lambda pg: pg["name"])})
    return out


def host_report(obj, p, cluster_ids, dvpg_names, dvs_pgs):
    si = p["hardware.systemInfo"]
    cpu = p["hardware.cpuInfo"]
    net = p.get("config.network")
    storage = p.get("config.storageDevice")
    pci = _pci_ids(p.get("hardware.pciDevice"))
    parent = moid(p.get("parent"))
    product = p.get("config.product")

    h = {
        "id": moid(obj), "name": p["name"],
        "cluster_id": parent if parent in cluster_ids else None,
        "connection_state": {"connected": "connected", "disconnected": "disconnected",
                             "notResponding": "not_responding"}.get(p.get("runtime.connectionState"), "unknown"),
        "maintenance_mode": bool(p.get("runtime.inMaintenanceMode")),
        "hardware": compact({"vendor": si.vendor, "model": si.model, "serial": _serial(si), "uuid": si.uuid,
                             "bios_version": getattr(p.get("hardware.biosInfo"), "biosVersion", None)}),
        "cpu": compact({"model": p["hardware.cpuPkg"][0].description.strip() if p.get("hardware.cpuPkg") else None,
                        "sockets": cpu.numCpuPackages, "cores": cpu.numCpuCores, "threads": cpu.numCpuThreads,
                        "mhz": int(cpu.hz / 1_000_000) if cpu.hz else None}),
        "memory_mb": int(p["hardware.memorySize"] // (1024 * 1024)),
    }
    if product:
        h["esxi"] = {"version": product.version, "build": product.build}

    if net:
        # speed_mbps stays null for a link that is down
        h["nics"] = [{**compact({"device": n.device, "mac": n.mac, "driver": n.driver, "pci_id": pci.get(n.pci)}),
                      "speed_mbps": n.linkSpeed.speedMb if n.linkSpeed else None} for n in net.pnic or []]
        h["vswitches"] = _vswitches(net, dvs_pgs)
        services = _vmk_services(p.get("config.virtualNicManagerInfo"))
        h["vmkernels"] = []
        for v in net.vnic or []:
            pg = v.portgroup or (dvpg_names.get(v.spec.distributedVirtualPort.portgroupKey)
                                 if v.spec.distributedVirtualPort else None)
            h["vmkernels"].append(compact({
                "device": v.device, "portgroup": pg,
                "ip": v.spec.ip.ipAddress if v.spec.ip else None, "netmask": v.spec.ip.subnetMask if v.spec.ip else None,
                "mtu": v.spec.mtu, "services": services.get(v.device, []),
            }))
    if storage:
        h["storage_adapters"] = [compact({"device": a.device, "type": _hba_type(a), "model": a.model, "driver": a.driver,
                                          "identifier": _hba_identifier(a)}) for a in storage.hostBusAdapter or []]
        vsan_cfg = p.get("config.vsanHostConfig")
        vsan_disks = set()
        groups = []
        for m in (vsan_cfg.storageInfo.diskMapping if vsan_cfg and vsan_cfg.enabled and vsan_cfg.storageInfo else None) or []:
            groups.append({"cache": [_disk(m.ssd)], "capacity": [_disk(d) for d in m.nonSsd or []]})
            vsan_disks.update([m.ssd.canonicalName] + [d.canonicalName for d in m.nonSsd or []])
        if groups:
            h["vsan"] = {"disk_groups": groups}
        h["local_disks"] = [_disk(l) for l in storage.scsiLun or []
                            if kind(l) == "ScsiDisk" and getattr(l, "localDisk", False) and l.canonicalName not in vsan_disks]
    return h


# --- datastores ------------------------------------------------------------

def _lun_index(hosts_raw):
    """canonicalName -> (lun, protocol, multipath policy) across all hosts."""
    index = {}
    for _, p in hosts_raw:
        storage = p.get("config.storageDevice")
        if not storage:
            continue
        hba_type = {a.key: _hba_type(a) for a in storage.hostBusAdapter or []}
        lun_by_key = {l.key: l for l in storage.scsiLun or []}
        for mp in (storage.multipathInfo.lun if storage.multipathInfo else None) or []:
            lun = lun_by_key.get(mp.lun)
            if not lun:
                continue
            protos = {hba_type.get(path.adapter) for path in mp.path or []}
            proto = next((t for t in ("fc", "fcoe", "iscsi") if t in protos), None)
            index[lun.canonicalName] = (lun, proto, mp.policy.policy if mp.policy else None)
        for lun in storage.scsiLun or []:
            index.setdefault(lun.canonicalName, (lun, None, None))
    return index


def datastore_report(obj, p, lun_index):
    s = p["summary"]
    info = p.get("info")
    info_kind = kind(info) if info is not None else ""
    ds = {
        "id": s.url or moid(obj), "name": p["name"],
        "type": DATASTORE_TYPES.get((s.type or "").upper(), "other"),
        "capacity_gb": gb(s.capacity), "free_gb": gb(s.freeSpace),
        "host_ids": sorted({moid(m.key) for m in p.get("host") or []}),
    }
    if info_kind == "VmfsDatastoreInfo" and info.vmfs:
        devices = [e.diskName for e in info.vmfs.extent or []]
        lun, proto, policy = lun_index.get(devices[0], (None, None, None)) if devices else (None, None, None)
        local = bool(getattr(info.vmfs, "local", False))
        ds["backing"] = compact({
            "protocol": "local" if local else (proto or "other"),
            "array_vendor": (lun.vendor or "").strip() or None if lun and not local else None,
            "array_model": (lun.model or "").strip() or None if lun and not local else None,
            "devices": devices, "multipath_policy": policy,
        })
    elif info_kind == "NasDatastoreInfo" and info.nas:
        ds["backing"] = {"protocol": "nfs", "nfs_server": info.nas.remoteHost, "nfs_path": info.nas.remotePath}
    elif info_kind == "VsanDatastoreInfo":
        ds["backing"] = {"protocol": "vsan"}
    elif info_kind == "LocalDatastoreInfo":
        ds["backing"] = {"protocol": "local"}
    return ds


# --- VMs -------------------------------------------------------------------

def _os_family(guest_id, family):
    gid = (guest_id or "").lower()
    if family == "windowsGuest" or gid.startswith("win"):
        return "windows"
    if family == "linuxGuest" or any(h in gid for h in LINUX_HINTS):
        return "linux"
    return "other"


def _tools_status(running, version):
    if version == "guestToolsNotInstalled":
        return "not_installed"
    if running == "guestToolsNotRunning":
        return "not_running"
    if version in ("guestToolsCurrent", "guestToolsUnmanaged"):
        return "ok"
    if version in ("guestToolsNeedUpgrade", "guestToolsSupportedOld", "guestToolsTooOld", "guestToolsBlacklisted"):
        return "old"
    return "unknown"


def _snapshots(tree):
    out = []
    for node in tree or []:
        out.append({"name": node.name, "created": node.createTime.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")})
        out.extend(_snapshots(node.childSnapshotList))
    return out


def _disk_entry(dev, controllers, ds_ids):
    b = dev.backing
    bk = kind(b)
    size = dev.capacityInBytes or (dev.capacityInKB or 0) * 1024
    entry = {"label": dev.deviceInfo.label if dev.deviceInfo else None, "size_gb": gb(size),
             "controller": controllers.get(dev.controllerKey),
             "datastore_id": ds_ids.get(moid(getattr(b, "datastore", None)))}
    if bk == "RawDiskMappingVer1BackingInfo":
        entry["rdm"] = "physical" if b.compatibilityMode == "physicalMode" else "virtual"
        entry["mode"] = DISK_MODES.get(b.diskMode)
    else:
        entry["rdm"] = "none"
        entry["mode"] = DISK_MODES.get(getattr(b, "diskMode", None))
        if getattr(b, "thinProvisioned", False):
            entry["provisioning"] = "thin"
        elif getattr(b, "eagerlyScrub", False):
            entry["provisioning"] = "thick_eager"
        elif bk == "FlatVer2BackingInfo":
            entry["provisioning"] = "thick_lazy"
    return compact(entry)


def _nic_entry(dev, dvpg_names):
    b = dev.backing
    network = getattr(b, "deviceName", None)
    port = getattr(b, "port", None)
    if not network and port is not None:
        network = dvpg_names.get(port.portgroupKey, port.portgroupKey)
    return compact({"adapter": NICS.get(kind(dev), "other"), "mac": dev.macAddress, "network": network,
                    "connected": dev.connectable.connected if dev.connectable else None})


def vm_report(obj, p, host_cluster, ds_ids, dvpg_names):
    cfg = p.get("config")
    host_id = moid(p.get("runtime.host"))
    devices = cfg.hardware.device or []
    controllers = {d.key: CONTROLLERS[kind(d)] for d in devices if kind(d) in CONTROLLERS}
    hw = (cfg.version or "").removeprefix("vmx-")
    ips = []
    for n in p.get("guest.net") or []:
        ips.extend(a for a in n.ipAddress or [] if not a.startswith("fe80:"))
    vm = {
        "id": moid(obj), "name": p["name"], "host_id": host_id, "cluster_id": host_cluster.get(host_id),
        "template": bool(cfg.template),
        "power_state": {"poweredOn": "on", "poweredOff": "off", "suspended": "suspended"}[p["runtime.powerState"]],
        "guest": compact({
            "os_id": cfg.guestId, "os_family": _os_family(cfg.guestId, p.get("guest.guestFamily")),
            "os_full_name": cfg.guestFullName, "hostname": p.get("guest.hostName") or None, "ip_addresses": ips,
            "tools_status": _tools_status(p.get("guest.toolsRunningStatus"), p.get("guest.toolsVersionStatus2")),
        }),
        "cpu": compact({"vcpus": cfg.hardware.numCPU, "cores_per_socket": cfg.hardware.numCoresPerSocket or None,
                        "reservation_mhz": cfg.cpuAllocation.reservation if cfg.cpuAllocation else None}),
        "memory_mb": cfg.hardware.memoryMB,
        "memory_reservation_mb": cfg.memoryAllocation.reservation if cfg.memoryAllocation else None,
        "firmware": cfg.firmware if cfg.firmware in ("bios", "efi") else None,
        "secure_boot": bool(cfg.bootOptions and cfg.bootOptions.efiSecureBootEnabled),
        "vtpm": any(kind(d) == "VirtualTPM" for d in devices),
        "hw_version": int(hw) if hw.isdigit() else None,
        "encrypted": bool(getattr(cfg, "keyId", None)),
        "ft_enabled": cfg.ftInfo is not None,
        "cbt_enabled": bool(cfg.changeTrackingEnabled),
        "passthrough_devices": sum(1 for d in devices if kind(d) in ("VirtualPCIPassthrough", "VirtualSriovEthernetCard")),
        "disks": [_disk_entry(d, controllers, ds_ids) for d in devices if kind(d) == "VirtualDisk"],
        "nics": [_nic_entry(d, dvpg_names) for d in devices if hasattr(d, "macAddress") and hasattr(d, "addressType")],
        "snapshots": _snapshots(p["snapshot"].rootSnapshotList if p.get("snapshot") else None),
        # Veeam names replicas <vm>_replica by default; anything else needs Veeam's own data.
        "backup_markers": {"veeam_replica": p["name"].endswith("_replica")},
    }
    return compact(vm)


# --- whole report ----------------------------------------------------------

def normalize(raw, source, source_detail, collected_at=None):
    about = raw["about"]
    cluster_ids = {moid(o) for o, _ in raw["clusters"]}
    dvpg_names = {p["key"]: p["name"] for _, p in raw["dvportgroups"]}
    dvs_pgs = dvs_portgroups(raw)
    hosts = [host_report(o, p, cluster_ids, dvpg_names, dvs_pgs) for o, p in raw["hosts"]]
    host_cluster = {h["id"]: h["cluster_id"] for h in hosts}
    lun_index = _lun_index(raw["hosts"])
    datastores = [datastore_report(o, p, lun_index) for o, p in raw["datastores"]]
    ds_ids = {moid(o): ds["id"] for (o, _), ds in zip(raw["datastores"], datastores)}
    vms = [vm_report(o, p, host_cluster, ds_ids, dvpg_names) for o, p in raw["vms"] if p.get("config") is not None]

    clusters = []
    for o, p in raw["clusters"]:
        cx = p.get("configurationEx")
        clusters.append(compact({
            "id": moid(o), "name": p["name"],
            "ha_enabled": bool(cx and cx.dasConfig and cx.dasConfig.enabled),
            "drs_enabled": bool(cx and cx.drsConfig and cx.drsConfig.enabled),
            "evc_mode": getattr(p.get("summary"), "currentEVCModeKey", None),
            "vsan_enabled": bool(cx and getattr(cx, "vsanConfigInfo", None) and cx.vsanConfigInfo.enabled),
            "host_ids": [moid(h) for h in p.get("host") or []],
        }))

    missing = ["performance"]
    warnings = [f"{p.get('name', moid(o))}: configuration not readable, skipped" for o, p in raw["vms"] if p.get("config") is None]
    if raw["privileges"] is None:
        warnings.append("could not read the session's privileges")
    if source == "esxi":
        missing.append("clusters")
    for vm in vms:
        if vm["power_state"] == "on" and not vm["guest"].get("ip_addresses"):
            warnings.append(f"{vm['name']}: powered on with no guest IP (VMware Tools not reporting)")

    return {
        "schema_version": 1,
        "collection": {
            "tool": "lts-discover", "tool_version": __version__, "source": source, "source_detail": source_detail,
            "collected_at": (collected_at or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "product": compact({"name": about.name, "version": about.version, "build": about.build,
                                "api_version": about.apiVersion, "licence_expires": raw.get("licence_expires")}),
            "privileges_used": raw["privileges"] or [],
            "perf_window_days": 0, "redacted": False, "redaction_salt": new_salt(),
            "missing": missing, "warnings": warnings,
        },
        "clusters": clusters, "hosts": hosts, "datastores": datastores, "vms": vms,
    }


def prefix_ids(report, prefix):
    """Make host and VM ids unique when several standalone hosts go into one report.

    Datastore ids are the datastore URL, which is already the same on every host
    that mounts the datastore, so shared LUNs merge naturally.
    """
    def p(x):
        return f"{prefix}/{x}" if x is not None else None
    for h in report["hosts"]:
        h["id"] = p(h["id"])
    for ds in report["datastores"]:
        ds["host_ids"] = [p(x) for x in ds.get("host_ids", [])]
    for vm in report["vms"]:
        vm["id"], vm["host_id"] = p(vm["id"]), p(vm.get("host_id"))
    return report


def merge(reports):
    """Combine per-host ESXi reports into one."""
    first = reports[0]
    out = {**first, "collection": dict(first["collection"]), "clusters": [], "hosts": [], "datastores": [], "vms": []}
    by_ds = {}
    versions = set()
    for r in reports:
        out["hosts"] += r["hosts"]
        out["vms"] += r["vms"]
        versions.add(r["collection"]["product"].get("version"))
        out["collection"]["warnings"] = sorted(set(out["collection"]["warnings"]) | set(r["collection"]["warnings"]))
        for ds in r["datastores"]:
            if ds["id"] in by_ds:
                by_ds[ds["id"]]["host_ids"] = sorted(set(by_ds[ds["id"]]["host_ids"]) | set(ds["host_ids"]))
            else:
                by_ds[ds["id"]] = ds
        privs = r["collection"]["privileges_used"]
        out["collection"]["privileges_used"] = sorted(set(out["collection"]["privileges_used"]) | set(privs))
    out["datastores"] = list(by_ds.values())
    if len(versions) > 1:
        out["collection"]["warnings"].append(f"hosts run different ESXi versions: {', '.join(sorted(v for v in versions if v))}")
    return out
