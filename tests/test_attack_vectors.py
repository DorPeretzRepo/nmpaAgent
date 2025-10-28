import importlib
import json
import sys
import types
from pathlib import Path

import pytest


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv('OLLAMA_SKIP_CHECK', '1')
    monkeypatch.setenv('NMAP_AGENT_STATE_DIR', str(tmp_path))
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    if 'requests' not in sys.modules:
        requests_stub = types.SimpleNamespace(get=lambda *a, **k: types.SimpleNamespace(status_code=503))
        sys.modules['requests'] = requests_stub
    if 'nmap_agent' in sys.modules:
        del sys.modules['nmap_agent']
    module = importlib.import_module('nmap_agent')
    module.PORT_HISTORY.clear()
    module.VENDOR_CACHE.clear()
    return module


def test_hackthebox_windows_surface(agent):
    sample_output = """# Nmap 7.94 scan initiated Wed Nov 08 12:00:00 2023 as: nmap -T4 -sV -oG - 10.10.10.5\nHost: 10.10.10.5 ()  Status: Up\nHost: 10.10.10.5 ()  Ports: 80/open/tcp//http///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 445/open/tcp//microsoft-ds///, 3389/open/tcp//ms-wbt-server///, 5985/open/tcp//wsman///, 53/open/udp//domain///\n# Nmap done at Wed Nov 08 12:01:05 2023 -- 1 IP address (1 host up) scanned\n"""

    mapping = agent.parse_open_ports_enhanced(sample_output)
    host_meta = mapping['10.10.10.5']

    assert sorted(host_meta['open_ports']) == [53, 80, 135, 139, 445, 3389, 5985]
    assert host_meta['risk_score'] >= 5  # stacked remote admin services should still elevate risk

    catalog = agent.build_attack_vector_catalog()
    entry = next(item for item in catalog['vector_entries'] if item['target'] == '10.10.10.5')
    vector_ids = {vector['vector_id'] for vector in entry['vectors']}

    assert 'remote_desktop_exposure' in vector_ids
    assert 'smb_lateral_movement' in vector_ids
    assert 'winrm_remote_admin' in vector_ids
    assert entry['overall_priority'] >= host_meta['risk_score']


def test_hackthebox_iot_exposure(agent):
    sample_output = """# Nmap 7.94 scan initiated Wed Nov 08 12:10:00 2023 as: nmap -T4 -sU -sV -oG - 10.10.10.24\nHost: 10.10.10.24 ()  Status: Up\nHost: 10.10.10.24 ()  Ports: 80/open/tcp//http///, 443/open/tcp//https///, 554/open/tcp//rtsp///, 161/open/udp//snmp///, 1900/open/udp//upnp///\n# Nmap done at Wed Nov 08 12:11:10 2023 -- 1 IP address (1 host up) scanned\n"""

    agent.PORT_HISTORY.clear()
    mapping = agent.parse_open_ports_enhanced(sample_output)
    host_meta = mapping['10.10.10.24']

    assert sorted(host_meta['open_ports']) == [80, 161, 443, 554, 1900]
    assert host_meta['risk_factors']['web_ports']

    agent.refresh_attack_vector_catalog()
    with open(agent.ATTACK_VECTOR_CATALOG_FILE) as f:
        catalog_data = json.load(f)

    entry = next(item for item in catalog_data['vector_entries'] if item['target'] == '10.10.10.24')
    vector_ids = {vector['vector_id'] for vector in entry['vectors']}

    assert 'iot_http_admin' in vector_ids
    assert 'snmp_information_leakage' in vector_ids
    assert 'upnp_reflection_surface' in vector_ids
    assert entry['overall_priority'] >= host_meta['risk_score']
