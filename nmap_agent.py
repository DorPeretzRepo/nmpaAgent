from __future__ import annotations

import getpass, json, os, re, subprocess, sys, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

import requests

__all__ = ["PORT_HISTORY","VENDOR_CACHE","EXPLOIT_HISTORY","ATTACK_VECTOR_CATALOG_FILE","parse_open_ports_enhanced","build_attack_vector_catalog","refresh_attack_vector_catalog","plan_exploit_actions","request_and_execute_exploit","execute_nmap","load_manifest","build_manifest_prompt","run_agent"]


@dataclass(frozen=True)
class AgentPaths:
    state_dir: Path; exploit_dir: Path; vendor_cache_file: Path; port_history_file: Path
    attack_vector_catalog_file: Path; exploit_log_file: Path; tasks_log_file: Path
    last_run_summary_file: Path; database_file: Path


@dataclass(frozen=True)
class AgentSettings:
    ollama_base_url: str; ollama_remote_url: str | None; ollama_mode: str
    ollama_auto_start: bool; ollama_health_timeout: float; skip_ollama_check: bool
    default_target: str; auto_approve_exploits: bool


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name); return default if value is None else value.lower() in {"1","true","yes","on"}


def load_paths() -> AgentPaths:
    state_dir = Path(os.getenv("NMAP_AGENT_STATE_DIR",".")).expanduser().resolve(); state_dir.mkdir(parents=True,exist_ok=True)
    exploit_dir = Path(os.getenv("NMAP_AGENT_EXPLOITS_DIR",state_dir/"exploits")).expanduser().resolve(); exploit_dir.mkdir(parents=True,exist_ok=True)
    return AgentPaths(state_dir,exploit_dir,state_dir/"vendors_cache.json",state_dir/"ports_history.json",state_dir/"attack_vectors.json",state_dir/"exploit_history.json",state_dir/"tasks.json",state_dir/"last_run_summary.json",state_dir/"nmap_agent.db")


def load_settings() -> AgentSettings:
    return AgentSettings(os.getenv("OLLAMA_BASE_URL","http://127.0.0.1:11434").rstrip("/"),os.getenv("OLLAMA_REMOTE_URL"),os.getenv("OLLAMA_MODE","auto").lower(),_bool_env("OLLAMA_AUTO_START",True),float(os.getenv("OLLAMA_HEALTH_TIMEOUT","4")),_bool_env("OLLAMA_SKIP_CHECK",False),os.getenv("NMAP_DEFAULT_TARGET","192.168.1.0/24"),_bool_env("NMAP_AGENT_AUTO_APPROVE_EXPLOITS",False))


@dataclass
class JsonStore:
    path: Path; default: Any; _data: Any | None = field(default=None, init=False, repr=False)
    def load(self) -> Any:
        if self._data is None:
            if not self.path.exists(): self._data = self.default() if callable(self.default) else self.default
            else:
                try:
                    with self.path.open("r",encoding="utf-8") as fh: self._data = json.load(fh)
                except json.JSONDecodeError:
                    self._data = self.default() if callable(self.default) else self.default
        return self._data
    def save(self) -> None:
        if self._data is not None:
            with self.path.open("w",encoding="utf-8") as fh: json.dump(self._data,fh,indent=2,sort_keys=isinstance(self._data,dict))
    def clear(self) -> None:
        self._data = self.default() if callable(self.default) else self.default; self.save()


@dataclass(frozen=True)
class OllamaStatus:
    base_url: str; reachable: bool; used_remote: bool


def _probe(url: str, timeout: float) -> bool:
    try:
        return requests.get(f"{url}/api/tags",timeout=timeout).status_code < 500
    except Exception:
        return False


def ensure_ollama(settings: AgentSettings) -> OllamaStatus:
    preferred = (settings.ollama_remote_url or settings.ollama_base_url).rstrip("/")
    if settings.ollama_remote_url and _probe(preferred,settings.ollama_health_timeout): return OllamaStatus(preferred,True,True)
    local = settings.ollama_base_url
    return OllamaStatus(local,_probe(local,settings.ollama_health_timeout),False)


@dataclass(frozen=True)
class CommandSpec:
    name: str; template: str


DEFAULT_COMMANDS: Dict[str, CommandSpec] = {
    "ping_discovery": CommandSpec("ping_discovery","nmap -T5 -sn --max-retries 0 -oG - {target}"),
    "top_ports_scan": CommandSpec("top_ports_scan","nmap -T5 --max-retries 1 --host-timeout 20s -p {ports} -oG - {target}"),
    "udp_top_ports_scan": CommandSpec("udp_top_ports_scan","nmap -T5 -sU --top-ports 50 --stats-every 20s -oG - {target}"),
    "service_discovery": CommandSpec("service_discovery","nmap -T4 -sV -p {ports} -oG - {target}"),
    "script_lookup": CommandSpec("script_lookup","nmap -T4 --script {scripts} -p {ports} -oN - {target}"),
}


def _coerce_arg(value: object) -> object:
    return ",".join(str(v) for v in value) if isinstance(value,(list,tuple,set)) else value


def _requires_privileges(output: str) -> bool:
    out = output.lower(); return "root privileges" in out or "requires root" in out


def _try_sudo(command: str, timeout: int) -> str | None:
    try: password = getpass.getpass("Root password required for this scan (leave blank to skip): ")
    except (EOFError,KeyboardInterrupt): return None
    if not password: return None
    proc = subprocess.run(f"echo {password!r} | sudo -S {command}",shell=True,capture_output=True,text=True,timeout=timeout)
    return (proc.stdout+proc.stderr).strip()


def execute_nmap(name: str, *, arguments: Dict[str, object] | None = None, default_target: str | None = None, commands: Mapping[str, CommandSpec] | None = None, timeout: int = 90) -> str:
    commands = dict(commands or DEFAULT_COMMANDS)
    if name not in commands: raise ValueError(f"Unknown command '{name}'")
    args = {**(arguments or {})}; args.setdefault("target",default_target or DEFAULT_TARGET); args.setdefault("ports","22,80,443"); args.setdefault("scripts","http-title")
    command = commands[name].template.format(**{k:_coerce_arg(v) for k,v in args.items()})
    proc = subprocess.run(command,shell=True,capture_output=True,text=True,timeout=timeout)
    output = (proc.stdout+proc.stderr).strip()
    if _requires_privileges(output):
        sudo_out = _try_sudo(command,timeout)
        if sudo_out is not None: return sudo_out
    return output


def parse_greppable_ports(output: str) -> Dict[str, Dict[str, object]]:
    hosts: Dict[str, Dict[str, object]] = {}
    for line in output.splitlines():
        if not line.startswith("Host:"): continue
        head,*rest = line.split("Ports:")
        if not rest: continue
        tokens = head.split(); ip = tokens[1] if len(tokens) > 1 else None
        if not ip: continue
        ports_section = rest[0]; meta = hosts.setdefault(ip,{"open_ports":[],"services":{},"protocols":set()})
        for entry in ports_section.split(","):
            entry = entry.strip()
            if not entry or "/" not in entry: continue
            fragments = entry.split("/")
            try: port = int(fragments[0])
            except ValueError: continue
            protocol = fragments[2] if len(fragments) > 2 else "tcp"; state = fragments[1]; service = fragments[4] if len(fragments) > 4 else ""
            if state != "open": continue
            meta["open_ports"].append(port); meta["services"][port] = service; meta["protocols"].add(protocol)
        meta["open_ports"].sort(); meta["protocols"] = sorted(meta["protocols"])
    return hosts


_MAC_RE = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \(([^)]+)\)")


def _risk_factors(services: Mapping[int,str]) -> Dict[str,bool]:
    lowered = {port:(name or "").lower() for port,name in services.items()}
    def has(ports: Iterable[int] | None = None, keyword: str | None = None) -> bool:
        return any((ports and port in ports) or (keyword and keyword in name) for port,name in lowered.items())
    factors = {
        "remote_admin": has({3389,5900}) or has(keyword="ms-wbt") or has(keyword="rdp"),
        "smb": has({139,445}) or has(keyword="smb"),
        "winrm": has({5985,5986}) or has(keyword="wsman"),
        "ftp": has({21}) or has(keyword="ftp"),
        "telnet": has({23}) or has(keyword="telnet"),
        "snmp": has({161}) or has(keyword="snmp"),
        "upnp": has({1900}) or has(keyword="upnp"),
        "web_ports": has({80,443,8080,8443}) or has(keyword="http"),
    }
    factors["iot_surface"] = factors["web_ports"] and (factors["snmp"] or any(port==554 for port in services) or factors["upnp"])
    factors["weak_protocols"] = factors["ftp"] or factors["telnet"]
    return factors


def _score_host(factors: Mapping[str,bool], services: Mapping[int,str]) -> int:
    score = len(services)
    if factors.get("remote_admin"): score += 4
    if factors.get("smb"): score += 3
    if factors.get("winrm"): score += 2
    if factors.get("weak_protocols"): score += 2
    if factors.get("snmp"): score += 1
    if factors.get("upnp"): score += 1
    if factors.get("iot_surface"): score += 1
    return score


ATTACK_VECTORS: tuple[Dict[str,object],...] = (
    {"id":"remote_desktop_exposure","severity":"high","ports":{3389,5900},"keywords":("ms-wbt","rdp","vnc"),"description":"Remote desktop services exposed.","follow_up":["Validate remote desktop configuration","Check authentication strength","Consider authorised credential testing"]},
    {"id":"smb_lateral_movement","severity":"high","ports":{139,445},"keywords":("microsoft-ds","smb","netbios"),"description":"SMB services could allow lateral movement.","follow_up":["Enumerate SMB shares","Review signing requirements","Attempt authorised credential reuse"]},
    {"id":"winrm_remote_admin","severity":"high","ports":{5985,5986},"keywords":("winrm","wsman"),"description":"WinRM remote administration surface discovered.","follow_up":["Enumerate WinRM authentication options","Validate Kerberos/password requirements","Inspect PowerShell remoting policy"]},
    {"id":"ftp_cleartext_login","severity":"medium","ports":{21},"keywords":("ftp",),"description":"FTP allows clear-text logins.","follow_up":["Gather banner information","Attempt anonymous login if approved"]},
    {"id":"telnet_legacy_access","severity":"medium","ports":{23},"keywords":("telnet",),"description":"Telnet exposes unencrypted shell access.","follow_up":["Capture Telnet banner","Check credential policy"]},
    {"id":"iot_http_admin","severity":"medium","ports":set(),"keywords":(),"requires_factor":"iot_surface","description":"Embedded web administration detected.","follow_up":["Capture screenshots","Check default credentials","Review firmware levels"]},
    {"id":"snmp_information_leakage","severity":"medium","ports":{161},"keywords":("snmp",),"description":"SNMP may leak configuration data.","follow_up":["Attempt public/private community strings","Run snmpwalk if authorised"]},
    {"id":"upnp_reflection_surface","severity":"medium","ports":{1900},"keywords":("upnp",),"description":"UPnP discovery and control exposed.","follow_up":["Query UPnP description","Check for remote management"]},
)


def _matches_vector(vector: Mapping[str,object], services: Mapping[int,str], factors: Mapping[str,bool]) -> bool:
    if vector.get("requires_factor") and not factors.get(vector["requires_factor"]): return False
    ports = vector.get("ports") or set()
    if ports and not any(port in ports for port in services): return False
    keywords: Iterable[str] = vector.get("keywords",())
    if keywords:
        lowered = {port:(service or "").lower() for port,service in services.items()}
        if not any(keyword in service for keyword in keywords for service in lowered.values()): return False
    return True


def parse_open_ports_enhanced(output: str) -> Dict[str, Dict[str, object]]:
    parsed = parse_greppable_ports(output)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    enhanced: Dict[str, Dict[str, object]] = {}
    for line in output.splitlines():
        match = _MAC_RE.search(line)
        if match:
            mac,vendor = match.groups(); oui = ":".join(mac.upper().split(":")[:3]); VENDOR_CACHE.setdefault(oui,vendor.strip())
    for target, meta in parsed.items():
        services = meta["services"]
        factors = _risk_factors(services)
        score = _score_host(factors, services)
        entry = {"open_ports":meta["open_ports"],"services":services,"protocols":meta["protocols"],"risk_factors":factors,"risk_score":score,"vendor":meta.get("vendor"),"last_seen":timestamp}
        PORT_HISTORY[target] = {"last_seen":timestamp,"open_ports":entry["open_ports"],"tcp_ports":entry["open_ports"],"udp_ports":[],"protocols":entry["protocols"],"risk_score":score,"services":services,"risk_factors":factors,"vendor":entry["vendor"]}
        enhanced[target] = entry
    _PORT_STORE.save(); _VENDOR_STORE.save()
    return enhanced


def build_attack_vector_catalog() -> Dict[str, object]:
    entries: List[Dict[str, object]] = []
    for target, meta in PORT_HISTORY.items():
        services = {int(port): name for port, name in meta.get("services", {}).items()}; factors = dict(meta.get("risk_factors", {}))
        matched = [{"vector_id":vector["id"],"severity":vector["severity"],"description":vector["description"],"follow_up":list(vector["follow_up"])} for vector in ATTACK_VECTORS if _matches_vector(vector, services, factors)]
        if matched:
            entries.append({"target":target,"overall_priority":int(meta.get("risk_score",0))+len(matched),"risk_score":int(meta.get("risk_score",0)),"risk_factors":factors,"vectors":matched})
    entries.sort(key=lambda item: item["overall_priority"], reverse=True)
    return {"vector_entries": entries}


def refresh_attack_vector_catalog() -> Path:
    catalog = build_attack_vector_catalog(); path = _PATHS.attack_vector_catalog_file; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(catalog,indent=2)); return path


EXPLOIT_DEFINITIONS: tuple[Dict[str,object],...] = (
    {"id":"enum_smb_shares","title":"Enumerate SMB shares","description":"Uses smbclient helper to list shares.","helper":"smb_enumeration.sh","ports":(445,),"factors":()},
    {"id":"probe_rdp_nla","title":"Probe RDP Network Level Authentication","description":"Validates RDP configuration and captures banners.","helper":"rdp_nla_probe.sh","ports":(3389,),"factors":()},
    {"id":"audit_snmp","title":"Audit SNMP communities","description":"Runs snmpwalk helper to inspect community strings.","helper":"snmp_community_audit.sh","ports":(161,),"factors":()},
    {"id":"winrm_password_spray","title":"WinRM password spray","description":"Stub helper for WinRM credential testing.","helper":"winrm_bruteforce_stub.sh","ports":(5985,5986),"factors":("winrm",)},
)


def plan_exploit_actions(target: str) -> List[Dict[str, object]]:
    host_meta = PORT_HISTORY.get(target)
    if not host_meta: return []
    services = {int(port): name for port, name in host_meta.get("services", {}).items()}; factors = host_meta.get("risk_factors", {})
    plans: List[Dict[str, object]] = []
    for definition in EXPLOIT_DEFINITIONS:
        if definition["ports"] and not any(port in services for port in definition["ports"]): continue
        if definition["factors"] and not all(factors.get(f) for f in definition["factors"]): continue
        helper_path = _PATHS.exploit_dir / definition["helper"] if definition.get("helper") else None
        available = helper_path.exists() if helper_path else False
        rationale = []
        if definition["ports"]:
            observed = [str(port) for port in definition["ports"] if port in services]
            if observed: rationale.append(f"observed port(s) {', '.join(observed)}")
        if definition["factors"]:
            rationale.append(f"risk factors: {', '.join(f for f in definition['factors'] if factors.get(f))}")
        plans.append({"id":definition["id"],"title":definition["title"],"description":definition["description"],"helper_path":str(helper_path) if helper_path else None,"target":target,"rationale":"; ".join(rationale) or "Heuristic match","available":available})
    return plans


def _record_history(plan: Mapping[str, object], status: str, output: str | None) -> None:
    entry = {"id":plan.get("id"),"target":plan.get("target"),"status":status,"timestamp":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}
    if output: entry["output"] = output
    EXPLOIT_HISTORY.append(entry); _EXPLOIT_STORE.save()


def request_and_execute_exploit(plan: Mapping[str, object], auto_approve: bool | None = None) -> str | None:
    auto = AUTO_APPROVE_EXPLOITS if auto_approve is None else auto_approve
    helper_path = plan.get("helper_path")
    if not helper_path: _record_history(plan,"not_available",None); return None
    helper = Path(str(helper_path))
    if not helper.exists(): _record_history(plan,"missing_helper",None); return None
    if not auto:
        stdin = sys.stdin
        if not stdin or not hasattr(stdin,"isatty") or not stdin.isatty(): _record_history(plan,"no_tty",None); return None
        if input(f"Execute exploit helper '{helper.name}' against {plan.get('target')}? [y/N]: ").strip().lower() not in {"y","yes"}:
            _record_history(plan,"denied",None); return None
    result = subprocess.run([str(helper)],capture_output=True,text=True)
    output = (result.stdout+result.stderr).strip(); status = "completed" if result.returncode == 0 else "failed"
    _record_history(plan,status,output); return output


def load_manifest(path: str | Path | None = None) -> Dict[str, object]:
    manifest_path = Path(path) if path else Path(__file__).resolve().parent / "manifests" / "nmap_manifest.json"
    with manifest_path.open("r",encoding="utf-8") as handle: return json.load(handle)


def build_manifest_prompt(manifest: Mapping[str, object]) -> str:
    lines = [manifest.get("description","Nmap function manifest"),"","Functions:"]
    for item in manifest.get("functions", []):
        lines.append(f"- {item['name']}: {item.get('purpose','unknown purpose')}")
        allowed = ", ".join(item.get("allowed_verbosity", []))
        if allowed: lines.append(f"  Verbosity: {allowed}")
    return "\n".join(lines)


def run_agent() -> None:
    print("Nmap agent ready for duty.")
    if OLLAMA_STATUS.reachable:
        origin = "remote" if OLLAMA_STATUS.used_remote else "local"; print(f"Ollama endpoint reachable via {origin} base at {OLLAMA_STATUS.base_url}.")
    else:
        print("Ollama endpoint unreachable; operate with manual planning.")
    print(f"State directory: {_PATHS.state_dir}"); print(f"Default target: {DEFAULT_TARGET}")
    print("Use execute_nmap(name, arguments={}) to run scans and parse outputs via parse_open_ports_enhanced().")
    print("Call refresh_attack_vector_catalog() to export the latest heuristics.")


_PATHS = load_paths(); _SETTINGS = load_settings()
_VENDOR_STORE = JsonStore(_PATHS.vendor_cache_file, default=dict)
_PORT_STORE = JsonStore(_PATHS.port_history_file, default=dict)
_EXPLOIT_STORE = JsonStore(_PATHS.exploit_log_file, default=list)

VENDOR_CACHE: Dict[str, str] = _VENDOR_STORE.load()
PORT_HISTORY: Dict[str, Dict[str, object]] = _PORT_STORE.load()
EXPLOIT_HISTORY: List[Dict[str, object]] = _EXPLOIT_STORE.load()

ATTACK_VECTOR_CATALOG_FILE = str(_PATHS.attack_vector_catalog_file)
DEFAULT_TARGET = _SETTINGS.default_target
AUTO_APPROVE_EXPLOITS = _SETTINGS.auto_approve_exploits

OLLAMA_STATUS = ensure_ollama(_SETTINGS) if not _SETTINGS.skip_ollama_check else OllamaStatus(_SETTINGS.ollama_base_url,False,False)
