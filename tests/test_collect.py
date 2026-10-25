"""Collector normalisation, fed hand-built pyVmomi data objects (no server needed)."""

import unittest
from datetime import datetime, timezone

try:
    from pyVmomi import vim
except ImportError:  # the collector is an optional extra
    vim = None

from lts_discovery.validate import validate

if vim:
    from lts_discovery import collect

GIB = 1024 ** 3


def lun(key, name, vendor, model, gib, ssd, local):
    return vim.host.ScsiDisk(key=key, canonicalName=name, vendor=vendor, model=model, ssd=ssd, localDisk=local,
                             capacity=vim.host.DiskDimensions.Lba(block=gib * GIB // 512, blockSize=512))


def fake_host():
    fc = vim.host.FibreChannelHba(key="hba-fc", device="vmhba2", model="Example 32Gb FC", driver="qlnativefc",
                                  portWorldWideName=0x2000000000000001)
    iscsi = vim.host.InternetScsiHba(key="hba-iscsi", device="vmhba64", model="iSCSI Software Adapter", driver="iscsi_vmk",
                                     iScsiName="iqn.1998-01.com.vmware:esx01")
    raid = vim.host.ParallelScsiHba(key="hba-raid", device="vmhba0", model="Example RAID", driver="lsi_mr3")
    san = lun("lun-san", "naa.600000000000000000000000000f0001", "EXAMPLE ", "ARRAY-1 ", 8192, False, False)
    boot = lun("lun-boot", "naa.6000000000000000000000000000b010", "EXAMPLE", "M.2 BOOT", 480, True, True)
    cache = lun("lun-cache", "t10.NVMe____EXAMPLE_CACHE", "NVMe", "CACHE", 1600, True, True)
    cap = [lun(f"lun-cap{i}", f"naa.50000000000000000000000000000d0{i}", "EXAMPLE", "SSD", 3840, True, True) for i in range(2)]
    storage = vim.host.StorageDeviceInfo(
        hostBusAdapter=[raid, fc, iscsi],
        scsiLun=[san, boot, cache] + cap,
        multipathInfo=vim.host.MultipathInfo(lun=[vim.host.MultipathInfo.LogicalUnit(
            key="mp-san", id="mp-san", lun="lun-san",
            policy=vim.host.MultipathInfo.LogicalUnitPolicy(policy="VMW_PSP_RR"),
            path=[vim.host.MultipathInfo.Path(key="p1", name="p1", adapter="hba-fc")])]),
    )
    net = vim.host.NetworkInfo(
        pnic=[vim.host.PhysicalNic(key="pnic-0", device="vmnic0", mac="02:00:00:00:00:10", driver="ntg3", pci="0000:01:00.0",
                                   linkSpeed=vim.host.PhysicalNic.LinkSpeedDuplex(speedMb=1000, duplex=True)),
              vim.host.PhysicalNic(key="pnic-2", device="vmnic2", mac="02:00:00:00:00:12", driver="nmlx5_core", pci="0000:3b:00.0")],
        vswitch=[vim.host.VirtualSwitch(name="vSwitch0", key="vsw0", mtu=1500, pnic=["pnic-0"], portgroup=["pg-mgmt"])],
        portgroup=[vim.host.PortGroup(key="pg-mgmt", spec=vim.host.PortGroup.Specification(name="Management Network", vlanId=0))],
        proxySwitch=[vim.host.HostProxySwitch(dvsUuid="dvs-uuid-1", dvsName="DSwitch-A", mtu=9000,
                                              spec=vim.host.HostProxySwitch.Specification(backing=vim.dvs.HostMember.PnicBacking(
                                                  pnicSpec=[vim.dvs.HostMember.PnicSpec(pnicDevice="vmnic2")])))],
        vnic=[vim.host.VirtualNic(device="vmk0", portgroup="Management Network",
                                  spec=vim.host.VirtualNic.Specification(mtu=1500, ip=vim.host.IpConfig(ipAddress="192.0.2.11", subnetMask="255.255.255.0"))),
              vim.host.VirtualNic(device="vmk1", portgroup="",
                                  spec=vim.host.VirtualNic.Specification(mtu=9000, ip=vim.host.IpConfig(ipAddress="198.51.100.11", subnetMask="255.255.255.0"),
                                                                         distributedVirtualPort=vim.dvs.PortConnection(portgroupKey="dvportgroup-31", switchUuid="dvs-uuid-1")))],
    )
    props = {
        "name": "esx01.example.test", "parent": vim.ClusterComputeResource("domain-c8"),
        "hardware.systemInfo": vim.host.SystemInfo(vendor="Example Systems", model="Rack Server 2U", uuid="00000000-0000-0000-0000-000000000001",
                                                   otherIdentifyingInfo=[vim.host.SystemIdentificationInfo(
                                                       identifierValue="EX000001", identifierType=vim.ElementDescription(key="SerialNumberTag", label="", summary=""))]),
        "hardware.biosInfo": vim.host.BIOSInfo(biosVersion="1.0.0"),
        "hardware.cpuInfo": vim.host.CpuInfo(numCpuPackages=2, numCpuCores=48, numCpuThreads=96, hz=2_100_000_000),
        "hardware.cpuPkg": [vim.host.CpuPackage(description="Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz  ")],
        "hardware.memorySize": 512 * GIB,
        # vSphere returns PCI ids as signed shorts
        "hardware.pciDevice": [vim.host.PciDevice(id="0000:3b:00.0", vendorId=0x15b3, deviceId=0x1015),
                               vim.host.PciDevice(id="0000:01:00.0", vendorId=0x8086 - 0x10000, deviceId=0x1572)],
        "runtime.connectionState": "connected", "runtime.inMaintenanceMode": False,
        "config.product": vim.AboutInfo(version="8.0.2", build="22380479"),
        "config.network": net,
        "config.storageDevice": storage,
        "config.virtualNicManagerInfo": vim.host.VirtualNicManagerInfo(netConfig=[
            vim.host.VirtualNicManager.NetConfig(nicType="management", multiSelectAllowed=True, selectedVnic=["management.key-vim.host.VirtualNic-vmk0"]),
            vim.host.VirtualNicManager.NetConfig(nicType="vmotion", multiSelectAllowed=True, selectedVnic=["vmotion.key-vim.host.VirtualNic-vmk1"]),
            vim.host.VirtualNicManager.NetConfig(nicType="vsan", multiSelectAllowed=True, selectedVnic=["vsan.key-vim.host.VirtualNic-vmk1"]),
        ]),
        "config.vsanHostConfig": vim.vsan.host.ConfigInfo(enabled=True, storageInfo=vim.vsan.host.ConfigInfo.StorageInfo(
            diskMapping=[vim.vsan.host.DiskMapping(ssd=cache, nonSsd=cap)])),
    }
    return vim.HostSystem("host-1"), props


def fake_vm():
    scsi = vim.vm.device.ParaVirtualSCSIController(key=1000, busNumber=0, sharedBus="noSharing")
    sas = vim.vm.device.VirtualLsiLogicSASController(key=1001, busNumber=1, sharedBus="noSharing")
    ds = vim.Datastore("datastore-11")
    thin = vim.vm.device.VirtualDisk(key=2000, controllerKey=1000, capacityInBytes=80 * GIB, deviceInfo=vim.Description(label="Hard disk 1", summary=""),
                                     backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName="[x] a.vmdk", diskMode="persistent", thinProvisioned=True, datastore=ds))
    eager = vim.vm.device.VirtualDisk(key=2001, controllerKey=1000, capacityInKB=500 * 1024 * 1024, deviceInfo=vim.Description(label="Hard disk 2", summary=""),
                                      backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName="[x] b.vmdk", diskMode="independent_persistent", thinProvisioned=False, eagerlyScrub=True, datastore=ds))
    rdm = vim.vm.device.VirtualDisk(key=2002, controllerKey=1001, capacityInBytes=1024 * GIB, deviceInfo=vim.Description(label="Hard disk 3", summary=""),
                                    backing=vim.vm.device.VirtualDisk.RawDiskMappingVer1BackingInfo(fileName="[x] c.vmdk", compatibilityMode="physicalMode", diskMode="independent_persistent", datastore=ds))
    nic = vim.vm.device.VirtualE1000e(key=4000, macAddress="00:50:56:00:00:01", addressType="assigned",
                                      connectable=vim.vm.device.VirtualDevice.ConnectInfo(connected=True, startConnected=True, allowGuestControl=True),
                                      backing=vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo(
                                          port=vim.dvs.PortConnection(portgroupKey="dvportgroup-30", switchUuid="dvs-uuid-1")))
    tpm = vim.vm.device.VirtualTPM(key=11000)
    created = datetime(2026, 8, 2, 22, 0, tzinfo=timezone.utc)
    config = vim.vm.ConfigInfo(
        name="FILE01", guestId="windows2019srv_64Guest", guestFullName="Microsoft Windows Server 2019 (64-bit)", version="vmx-19",
        template=False, firmware="efi", changeTrackingEnabled=True,
        bootOptions=vim.vm.BootOptions(efiSecureBootEnabled=True),
        cpuAllocation=vim.ResourceAllocationInfo(reservation=0), memoryAllocation=vim.ResourceAllocationInfo(reservation=4096),
        hardware=vim.vm.VirtualHardware(numCPU=4, numCoresPerSocket=2, memoryMB=16384, device=[scsi, sas, thin, eager, rdm, nic, tpm]),
    )
    snap = vim.vm.SnapshotInfo(rootSnapshotList=[vim.vm.SnapshotTree(name="before-patching", createTime=created, childSnapshotList=[
        vim.vm.SnapshotTree(name="after", createTime=created, childSnapshotList=[])])])
    props = {
        "name": "FILE01", "config": config, "runtime.powerState": "poweredOn", "runtime.host": vim.HostSystem("host-1"),
        "snapshot": snap, "guest.toolsRunningStatus": "guestToolsRunning", "guest.toolsVersionStatus2": "guestToolsNeedUpgrade",
        "guest.hostName": "file01.corp.example.test", "guest.guestFamily": "windowsGuest",
        "guest.net": [vim.vm.GuestInfo.NicInfo(ipAddress=["192.0.2.103", "fe80::1"], connected=True, deviceConfigId=4000)],
    }
    return vim.VirtualMachine("vm-103"), props


def fake_datastore():
    info = vim.host.VmfsDatastoreInfo(name="SAN-LUN01", url="ds:///vmfs/volumes/0001/", vmfs=vim.host.VmfsVolume(
        name="SAN-LUN01", local=False, extent=[vim.host.ScsiDisk.Partition(diskName="naa.600000000000000000000000000f0001", partition=1)]))
    summary = vim.Datastore.Summary(name="SAN-LUN01", url="ds:///vmfs/volumes/0001/", type="VMFS", capacity=8192 * GIB, freeSpace=5020 * GIB, accessible=True)
    return vim.Datastore("datastore-11"), {"name": "SAN-LUN01", "summary": summary, "info": info,
                                          "host": [vim.Datastore.HostMount(key=vim.HostSystem("host-1"))]}


def fake_raw():
    cluster = vim.ClusterComputeResource("domain-c8")
    return {
        "about": vim.AboutInfo(name="VMware vCenter Server", version="8.0.2", build="22617221", apiVersion="8.0.2.0", apiType="VirtualCenter"),
        "privileges": ["System.Anonymous", "System.Read", "System.View"],
        "licence_expires": "2027-03-31",
        "hosts": [fake_host()],
        "vms": [fake_vm(), (vim.VirtualMachine("vm-999"), {"name": "orphan", "config": None})],
        "datastores": [fake_datastore()],
        "clusters": [(cluster, {"name": "Cluster-A", "summary": vim.ClusterComputeResource.Summary(currentEVCModeKey="intel-icelake"),
                                "host": [vim.HostSystem("host-1")],
                                "configurationEx": vim.cluster.ConfigInfoEx(
                                    dasConfig=vim.cluster.DasConfigInfo(enabled=True), drsConfig=vim.cluster.DrsConfigInfo(enabled=False),
                                    vsanConfigInfo=vim.vsan.cluster.ConfigInfo(enabled=True))})],
        "dvswitches": [(vim.DistributedVirtualSwitch("dvs-8"), {"name": "DSwitch-A", "uuid": "dvs-uuid-1"})],
        "dvportgroups": [
            (vim.dvs.DistributedVirtualPortgroup("dvportgroup-29"), {"name": "DSwitch-A-DVUplinks-9", "key": "dvportgroup-29",
             "config.distributedVirtualSwitch": vim.DistributedVirtualSwitch("dvs-8"), "config.defaultPortConfig": None, "config.uplink": None}),
            (vim.dvs.DistributedVirtualPortgroup("dvportgroup-30"), {"name": "PG-Servers", "key": "dvportgroup-30",
             "config.distributedVirtualSwitch": vim.DistributedVirtualSwitch("dvs-8"),
             "config.defaultPortConfig": vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy(
                 vlan=vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec(vlanId=20, inherited=False)), "config.uplink": False}),
            (vim.dvs.DistributedVirtualPortgroup("dvportgroup-31"), {"name": "PG-Trunk", "key": "dvportgroup-31",
             "config.distributedVirtualSwitch": vim.DistributedVirtualSwitch("dvs-8"),
             "config.defaultPortConfig": vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy(
                 vlan=vim.dvs.VmwareDistributedVirtualSwitch.TrunkVlanSpec(inherited=False, vlanId=[
                     vim.NumericRange(start=100, end=199), vim.NumericRange(start=300, end=300)])), "config.uplink": False}),
        ],
    }


@unittest.skipUnless(vim, "pyVmomi not installed")
class Normalize(unittest.TestCase):
    def setUp(self):
        self.report = collect.normalize(fake_raw(), "vcenter", "vcsa.example.test",
                                        collected_at=datetime(2026, 10, 24, 14, 5, tzinfo=timezone.utc))

    def test_report_is_valid(self):
        self.assertEqual(validate(self.report), [])
        self.assertEqual(self.report["collection"]["collected_at"], "2026-10-24T14:05:00Z")
        self.assertEqual(self.report["collection"]["product"]["licence_expires"], "2027-03-31")

    def test_host_hardware(self):
        h = self.report["hosts"][0]
        self.assertEqual(h["cluster_id"], "domain-c8")
        self.assertEqual(h["hardware"]["serial"], "EX000001")
        self.assertEqual(h["cpu"], {"model": "Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz", "sockets": 2, "cores": 48, "threads": 96, "mhz": 2100})
        self.assertEqual(h["memory_mb"], 512 * 1024)
        self.assertEqual(h["nics"][0]["pci_id"], "8086:1572")
        self.assertEqual(h["nics"][1], {"device": "vmnic2", "mac": "02:00:00:00:00:12", "driver": "nmlx5_core", "pci_id": "15b3:1015", "speed_mbps": None})

    def test_storage_adapters(self):
        types = {a["device"]: (a["type"], a.get("identifier")) for a in self.report["hosts"][0]["storage_adapters"]}
        self.assertEqual(types["vmhba0"], ("raid", None))
        self.assertEqual(types["vmhba2"], ("fc", "20:00:00:00:00:00:00:01"))
        self.assertEqual(types["vmhba64"], ("iscsi", "iqn.1998-01.com.vmware:esx01"))

    def test_vsan_and_local_disks(self):
        h = self.report["hosts"][0]
        group = h["vsan"]["disk_groups"][0]
        self.assertEqual(group["cache"][0]["kind"], "nvme")
        self.assertEqual([d["size_gb"] for d in group["capacity"]], [3840.0, 3840.0])
        # vSAN disks and the SAN LUN are not local disks; the boot device is
        self.assertEqual([d["model"] for d in h["local_disks"]], ["M.2 BOOT"])

    def test_networking(self):
        h = self.report["hosts"][0]
        std, dvs = h["vswitches"]
        self.assertEqual((std["kind"], std["uplinks"], std["portgroups"]), ("standard", ["vmnic0"], [{"name": "Management Network", "vlan": 0}]))
        self.assertEqual(dvs["kind"], "distributed")
        self.assertEqual(dvs["uplinks"], ["vmnic2"])
        self.assertEqual(dvs["portgroups"], [{"name": "PG-Servers", "vlan": 20}, {"name": "PG-Trunk", "vlan": "trunk:100-199,300"}])
        vmk = {v["device"]: v for v in h["vmkernels"]}
        self.assertEqual(vmk["vmk0"]["services"], ["management"])
        self.assertEqual(vmk["vmk1"]["portgroup"], "PG-Trunk")
        self.assertEqual(vmk["vmk1"]["services"], ["vmotion", "vsan"])

    def test_datastore_backing(self):
        ds = self.report["datastores"][0]
        self.assertEqual(ds["id"], "ds:///vmfs/volumes/0001/")
        self.assertEqual(ds["backing"], {"protocol": "fc", "array_vendor": "EXAMPLE", "array_model": "ARRAY-1",
                                         "devices": ["naa.600000000000000000000000000f0001"], "multipath_policy": "VMW_PSP_RR"})

    def test_vm(self):
        vm = self.report["vms"][0]
        self.assertEqual((vm["host_id"], vm["cluster_id"]), ("host-1", "domain-c8"))
        self.assertEqual(vm["guest"]["os_family"], "windows")
        self.assertEqual(vm["guest"]["ip_addresses"], ["192.0.2.103"])
        self.assertEqual(vm["guest"]["tools_status"], "old")
        self.assertEqual((vm["firmware"], vm["secure_boot"], vm["vtpm"], vm["hw_version"], vm["cbt_enabled"]), ("efi", True, True, 19, True))
        self.assertEqual(vm["memory_reservation_mb"], 4096)
        disks = vm["disks"]
        self.assertEqual([(d["provisioning"] if "provisioning" in d else None, d["controller"], d["rdm"], d.get("mode")) for d in disks], [
            ("thin", "pvscsi", "none", "persistent"),
            ("thick_eager", "pvscsi", "none", "independent_persistent"),
            (None, "lsilogic_sas", "physical", "independent_persistent"),
        ])
        self.assertEqual(disks[1]["size_gb"], 500.0)
        self.assertEqual({d["datastore_id"] for d in disks}, {"ds:///vmfs/volumes/0001/"})
        self.assertEqual(vm["nics"], [{"adapter": "e1000e", "mac": "00:50:56:00:00:01", "network": "PG-Servers", "connected": True}])
        self.assertEqual([s["name"] for s in vm["snapshots"]], ["before-patching", "after"])
        self.assertEqual(vm["snapshots"][0]["created"], "2026-08-02T22:00:00Z")

    def test_unreadable_vm_is_skipped_with_warning(self):
        self.assertEqual([v["id"] for v in self.report["vms"]], ["vm-103"])
        self.assertIn("orphan: configuration not readable, skipped", self.report["collection"]["warnings"])

    def test_cluster(self):
        self.assertEqual(self.report["clusters"], [{"id": "domain-c8", "name": "Cluster-A", "ha_enabled": True, "drs_enabled": False,
                                                    "evc_mode": "intel-icelake", "vsan_enabled": True, "host_ids": ["host-1"]}])

    def test_performance_reported_missing(self):
        self.assertIn("performance", self.report["collection"]["missing"])
        self.assertEqual(self.report["collection"]["perf_window_days"], 0)


@unittest.skipUnless(vim, "pyVmomi not installed")
class MergeStandaloneHosts(unittest.TestCase):
    def per_host(self, target):
        raw = fake_raw()
        raw["about"] = vim.AboutInfo(name="VMware ESXi", version="6.5.0", build="1", apiVersion="6.5", apiType="HostAgent")
        raw["clusters"] = raw["dvswitches"] = raw["dvportgroups"] = []
        raw["vms"] = raw["vms"][:1]
        return collect.prefix_ids(collect.normalize(raw, "esxi", target), target)

    def test_shared_datastore_merges_and_ids_stay_unique(self):
        report = collect.merge([self.per_host("esx01.example.test"), self.per_host("esx02.example.test")])
        self.assertEqual(validate(report), [])
        self.assertEqual([h["id"] for h in report["hosts"]], ["esx01.example.test/host-1", "esx02.example.test/host-1"])
        self.assertEqual(len(report["datastores"]), 1)
        self.assertEqual(report["datastores"][0]["host_ids"], ["esx01.example.test/host-1", "esx02.example.test/host-1"])
        self.assertEqual(report["vms"][1]["host_id"], "esx02.example.test/host-1")
        self.assertIn("clusters", report["collection"]["missing"])
        self.assertTrue(all(h["cluster_id"] is None for h in report["hosts"]))


if __name__ == "__main__":
    unittest.main()
