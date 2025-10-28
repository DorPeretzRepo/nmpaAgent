"""Attack vector cataloguing and host risk assessment."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping
import re

from .scanning import parse_greppable_ports


@dataclass(frozen=True)
class AttackVectorDefinition:
    """Description of an attack vector heuristic."""

    vector_id: str
    title: str
    severity: str
    description: str
    port_any: tuple[int, ...] = ()
    service_keywords: tuple[str, ...] = ()
    required_factor: str | None = None
    follow_up: tuple[str, ...] = ()

    def matches(self, observation: "HostObservation") -> bool:
        if self.required_factor and not observation.risk_factors.get(self.required_factor):
            return False
        if self.port_any:
            if not any(port in observation.services for port in self.port_any):
                return False
        if self.service_keywords:
            lowered = {service.lower() for service in observation.services.values()}
            if not any(keyword in service for keyword in self.service_keywords for service in lowered):
                return False
        return True


@dataclass
class HostObservation:
    target: str
    open_ports: List[int]
    services: Dict[int, str]
    protocols: List[str]
    risk_factors: Dict[str, bool]
    risk_score: int
    vendor: str | None = None


MAC_LINE_RE = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \(([^)]+)\)")

VENDOR_HEURISTICS: Mapping[str, Dict[str, object]] = {
    "LG": {"priority_bonus": 3, "scripts": ["upnp-info", "http-title"]},
    "SAMSUNG": {"priority_bonus": 3, "scripts": ["upnp-info", "http-title"]},
    "SONY": {"priority_bonus": 2, "scripts": ["upnp-info"]},
    "ROKU": {"priority_bonus": 2, "scripts": ["http-title"]},
}


ATTACK_VECTOR_LIBRARY: tuple[AttackVectorDefinition, ...] = (
    AttackVectorDefinition(
        vector_id="remote_desktop_exposure",
        title="Remote desktop surface exposed",
        severity="high",
        description="Remote desktop services are reachable and could allow remote control if authentication is weak.",
        port_any=(3389, 5900),
        service_keywords=("ms-wbt-server", "rdp", "vnc"),
        follow_up=(
            "Validate remote desktop configuration",
            "Enumerate security options and network level authentication",
            "Consider brute-force or credential stuffing once authorised",
        ),
    ),
    AttackVectorDefinition(
        vector_id="smb_lateral_movement",
        title="SMB lateral movement opportunities",
        severity="high",
        description="SMB shares or services may enable credential harvesting or remote execution.",
        port_any=(139, 445),
        service_keywords=("microsoft-ds", "netbios", "smb"),
        follow_up=(
            "Enumerate SMB shares",
            "Check for SMB signing and guest access",
            "Attempt credential reuse where permitted",
        ),
    ),
    AttackVectorDefinition(
        vector_id="winrm_remote_admin",
        title="WinRM exposed",
        severity="high",
        description="Windows Remote Management is available and may support remote code execution with valid credentials.",
        port_any=(5985, 5986),
        service_keywords=("wsman", "winrm"),
        follow_up=(
            "Enumerate WinRM authentication methods",
            "Attempt Kerberos or password auth as authorised",
            "Review PowerShell remoting configuration",
        ),
    ),
    AttackVectorDefinition(
        vector_id="ftp_cleartext_login",
        title="FTP service accepting clear-text credentials",
        severity="medium",
        description="FTP offers clear-text authentication which is vulnerable to sniffing and weak password attacks.",
        port_any=(21,),
        service_keywords=("ftp",),
        follow_up=(
            "Gather banner information",
            "Attempt anonymous login if authorised",
            "Run brute-force helpers if permitted",
        ),
    ),
    AttackVectorDefinition(
        vector_id="telnet_legacy_access",
        title="Telnet service exposed",
        severity="medium",
        description="Legacy Telnet offers unencrypted remote shell access and often ships with weak credentials.",
        port_any=(23,),
        service_keywords=("telnet",),
        follow_up=(
            "Collect Telnet banner",
            "Attempt credential reuse once approved",
        ),
    ),
    AttackVectorDefinition(
        vector_id="iot_http_admin",
        title="IoT web administration surface",
        severity="medium",
        description="Embedded web interfaces may expose administrative consoles with weak defaults.",
        required_factor="iot_surface",
        follow_up=(
            "Capture screenshots of the administrative interface",
            "Check for default credentials",
            "Review firmware patch levels",
        ),
    ),
    AttackVectorDefinition(
        vector_id="snmp_information_leakage",
        title="SNMP information disclosure",
        severity="medium",
        description="SNMP services often rely on default community strings and disclose device configuration.",
        port_any=(161,),
        service_keywords=("snmp",),
        follow_up=(
            "Attempt read access with public/private",
            "Leverage snmpwalk tooling where authorised",
        ),
    ),
    AttackVectorDefinition(
        vector_id="upnp_reflection_surface",
        title="UPnP discovery enabled",
        severity="medium",
        description="UPnP services expose device metadata and sometimes insecure remote administration.",
        port_any=(1900,),
        service_keywords=("upnp",),
        follow_up=(
            "Query UPnP device description",
            "Check for remote management endpoints",
        ),
    ),
)


def parse_open_ports_enhanced(output: str, *, vendor_cache: Dict[str, str]) -> Dict[str, Dict[str, object]]:
    """Parse greppable output and enrich it with risk heuristics."""

    base = parse_greppable_ports(output)
    enhanced: Dict[str, Dict[str, object]] = {}

    for line in output.splitlines():
        match = MAC_LINE_RE.search(line)
        if not match:
            continue
        mac, vendor = match.groups()
        oui = ":".join(mac.upper().split(":")[:3])
        vendor_cache.setdefault(oui, vendor.strip())

    for target, raw in base.items():
        services: Dict[int, str] = raw["services"]
        risk_factors = _compute_risk_factors(services)
        score = _score_host(risk_factors, services)
        vendor_name = raw.get("vendor")
        enhanced[target] = {
            "open_ports": raw["open_ports"],
            "services": services,
            "protocols": raw["protocols"],
            "risk_factors": risk_factors,
            "risk_score": score,
            "vendor": vendor_name,
        }
    return enhanced


def _compute_risk_factors(services: Mapping[int, str]) -> Dict[str, bool]:
    lowered = {port: (name or "").lower() for port, name in services.items()}
    has_remote_desktop = any(port in {3389, 5900} or "ms-wbt" in name for port, name in lowered.items())
    has_smb = any(port in {139, 445} for port in lowered)
    has_winrm = any(port in {5985, 5986} or "wsman" in name for port, name in lowered.items())
    has_ftp = any(port == 21 or "ftp" in name for port, name in lowered.items())
    has_telnet = any(port == 23 or "telnet" in name for port, name in lowered.items())
    has_snmp = any(port == 161 or "snmp" in name for port, name in lowered.items())
    has_upnp = any(port == 1900 or "upnp" in name for port, name in lowered.items())
    has_web = any(port in {80, 443, 8080, 8443} or "http" in name for port, name in lowered.items())
    has_rtsp = any(port == 554 or "rtsp" in name for port, name in lowered.items())

    return {
        "remote_admin": has_remote_desktop or has_winrm,
        "smb": has_smb,
        "winrm": has_winrm,
        "ftp": has_ftp,
        "telnet": has_telnet,
        "snmp": has_snmp,
        "upnp": has_upnp,
        "web_ports": has_web,
        "iot_surface": has_web and (has_snmp or has_upnp or has_rtsp),
        "weak_protocols": has_telnet or has_ftp,
    }


def _score_host(risk_factors: Mapping[str, bool], services: Mapping[int, str]) -> int:
    score = len(services)
    if risk_factors.get("remote_admin"):
        score += 4
    if risk_factors.get("smb"):
        score += 3
    if risk_factors.get("winrm"):
        score += 2
    if risk_factors.get("weak_protocols"):
        score += 2
    if risk_factors.get("snmp"):
        score += 1
    if risk_factors.get("upnp"):
        score += 1
    if risk_factors.get("iot_surface"):
        score += 1
    return score


def build_attack_vector_catalog(hosts: Mapping[str, Mapping[str, object]]) -> Dict[str, object]:
    entries: List[Dict[str, object]] = []
    for target, meta in hosts.items():
        observation = HostObservation(
            target=target,
            open_ports=list(meta.get("open_ports", [])),
            services={int(port): service for port, service in meta.get("services", {}).items()},
            protocols=list(meta.get("protocols", [])),
            risk_factors=dict(meta.get("risk_factors", {})),
            risk_score=int(meta.get("risk_score", 0)),
            vendor=meta.get("vendor"),
        )
        matched = [
            {
                "vector_id": vector.vector_id,
                "title": vector.title,
                "severity": vector.severity,
                "description": vector.description,
                "follow_up": list(vector.follow_up),
            }
            for vector in ATTACK_VECTOR_LIBRARY
            if vector.matches(observation)
        ]
        if not matched:
            continue
        entries.append(
            {
                "target": target,
                "overall_priority": observation.risk_score + len(matched),
                "risk_score": observation.risk_score,
                "risk_factors": observation.risk_factors,
                "vectors": matched,
            }
        )
    entries.sort(key=lambda entry: entry["overall_priority"], reverse=True)
    return {"vector_entries": entries}
