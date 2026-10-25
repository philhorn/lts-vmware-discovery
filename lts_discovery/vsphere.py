"""vSphere connection and bulk property retrieval (read-only).

Everything is read through the PropertyCollector with explicit property paths:
one round trip per object type, and no property is fetched that the report
does not use.
"""

import hashlib
import socket
import ssl

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl

# Privileges a discovery session may hold. The built-in Read-only role is the first three.
ALLOWED_PRIVILEGES = {"System.Anonymous", "System.View", "System.Read", "StorageProfile.View", "Global.Licenses"}

HOST_PATHS = [
    "name", "parent",
    "hardware.systemInfo", "hardware.biosInfo", "hardware.cpuInfo", "hardware.cpuPkg", "hardware.memorySize", "hardware.pciDevice",
    "runtime.connectionState", "runtime.inMaintenanceMode",
    "config.product", "config.network", "config.storageDevice", "config.virtualNicManagerInfo", "config.vsanHostConfig",
]
VM_PATHS = [
    "name", "config", "runtime.powerState", "runtime.host", "snapshot",
    "guest.toolsRunningStatus", "guest.toolsVersionStatus2", "guest.hostName", "guest.net", "guest.guestFamily",
]
DATASTORE_PATHS = ["name", "summary", "info", "host"]
CLUSTER_PATHS = ["name", "configurationEx", "summary", "host"]
DVPG_PATHS = ["name", "key", "config.distributedVirtualSwitch", "config.defaultPortConfig", "config.uplink"]
DVS_PATHS = ["name", "uuid"]


class DiscoveryError(Exception):
    pass


def server_certificate(host, port=443, timeout=10):
    """The server's TLS certificate in DER form, fetched without verification."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def fingerprint(der, algorithm="sha256"):
    digest = hashlib.new(algorithm, der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def server_fingerprint(host, port=443):
    """SHA-256 fingerprint of the server's TLS certificate, as colon-separated hex."""
    return fingerprint(server_certificate(host, port))


def pinned_context(der):
    """An SSL context that trusts exactly this one certificate and nothing else."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # the pin identifies the server; hosts are often reached by IP
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=der)
    return ctx


def connect(host, user, password, port=443, thumbprint=None, insecure=False):
    """Open a session. TLS is verified against the system CAs unless a SHA-256 or SHA-1 thumbprint is pinned."""
    if thumbprint:
        # Checked here rather than by pyVmomi: some pyVmomi releases ignore their thumbprint argument.
        der = server_certificate(host, port)
        pin = thumbprint.replace(":", "").lower()
        algorithm = {40: "sha1", 64: "sha256"}.get(len(pin))
        if not algorithm:
            raise DiscoveryError("--thumbprint must be a SHA-256 (64 hex digits) or SHA-1 (40 hex digits) fingerprint")
        if hashlib.new(algorithm, der).hexdigest() != pin:
            raise DiscoveryError(f"{host}: certificate fingerprint {fingerprint(der)} does not match --thumbprint")
        # The session itself only accepts that same certificate, so a swap after the check fails the handshake.
        return SmartConnect(host=host, port=port, user=user, pwd=password, sslContext=pinned_context(der))
    if insecure:
        return SmartConnect(host=host, port=port, user=user, pwd=password, disableSslCertValidation=True)
    try:
        return SmartConnect(host=host, port=port, user=user, pwd=password)
    except ssl.SSLError as e:
        raise DiscoveryError(
            f"{host}: TLS certificate not trusted ({e.reason}). ESXi hosts usually have self-signed certificates; "
            f"check the fingerprint on the host console and pass --thumbprint {host}={server_fingerprint(host, port)}"
        ) from e


def disconnect(si):
    Disconnect(si)


def retrieve(content, obj_type, paths):
    """Return [(managed object, {path: value})] for every object of obj_type under the root folder."""
    view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
    try:
        pc = vmodl.query.PropertyCollector
        spec = pc.FilterSpec(
            objectSet=[pc.ObjectSpec(obj=view, skip=True, selectSet=[pc.TraversalSpec(name="view", path="view", skip=False, type=vim.view.ContainerView)])],
            propSet=[pc.PropertySpec(type=obj_type, pathSet=paths)],
        )
        out = []
        result = content.propertyCollector.RetrievePropertiesEx([spec], pc.RetrieveOptions())
        while result:
            for obj in result.objects:
                props = {p.name: p.val for p in obj.propSet or []}
                for missing in obj.missingSet or []:
                    props.setdefault(missing.path, None)
                out.append((obj.obj, props))
            if not result.token:
                break
            result = content.propertyCollector.ContinueRetrievePropertiesEx(result.token)
        return out
    finally:
        view.Destroy()


def session_privileges(content):
    """Privileges the session holds on the root folder, or None if the server can't say."""
    try:
        user = content.sessionManager.currentSession.userName
        result = content.authorizationManager.FetchUserPrivilegeOnEntities(entities=[content.rootFolder], userName=user)
    except (vmodl.MethodFault, AttributeError):
        return None
    return sorted(result[0].privileges) if result else []


def licence_expiry(content):
    """Earliest licence expiry date as YYYY-MM-DD, or None (perpetual, evaluation-free, or not readable)."""
    try:
        licences = content.licenseManager.licenses
    except vmodl.MethodFault:
        return None
    dates = []
    for lic in licences or []:
        for prop in lic.properties or []:
            if prop.key == "expirationDate" and prop.value:
                dates.append(prop.value.date().isoformat())
    return min(dates) if dates else None


def fetch(si):
    """Read everything the report needs into plain Python structures of pyVmomi objects."""
    content = si.RetrieveContent()
    about = content.about
    raw = {
        "about": about,
        "privileges": session_privileges(content),
        "licence_expires": licence_expiry(content),
        "hosts": retrieve(content, vim.HostSystem, HOST_PATHS),
        "vms": retrieve(content, vim.VirtualMachine, VM_PATHS),
        "datastores": retrieve(content, vim.Datastore, DATASTORE_PATHS),
        "clusters": [],
        "dvportgroups": [],
        "dvswitches": [],
    }
    if about.apiType == "VirtualCenter":
        raw["clusters"] = retrieve(content, vim.ClusterComputeResource, CLUSTER_PATHS)
        raw["dvportgroups"] = retrieve(content, vim.dvs.DistributedVirtualPortgroup, DVPG_PATHS)
        raw["dvswitches"] = retrieve(content, vim.DistributedVirtualSwitch, DVS_PATHS)
    return raw
