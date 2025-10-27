import json, subprocess, sys, requests, time, os, threading, signal, sqlite3, ast, re, getpass, socket

def check_ollama():
    """Ensure Ollama running; attempt quick start if not."""
    try:
        r = requests.get('http://localhost:11434/api/tags', timeout=4)
        if r.status_code == 200:
            print("Ollama is running.")
            return True
    except Exception:
        pass
    print("Ollama not running. Starting Ollama...")
    subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(16):
        time.sleep(0.4)
        try:
            r = requests.get('http://localhost:11434/api/tags', timeout=1)
            if r.status_code == 200:
                print("Ollama started.")
                return True
        except Exception:
            continue
    print("Proceeding; model may still initialize.")
    return True

check_ollama()

# Vendor cache and port history
VENDOR_CACHE_FILE='vendors_cache.json'
PORT_HISTORY_FILE='ports_history.json'
try:
    if os.path.exists(VENDOR_CACHE_FILE):
        with open(VENDOR_CACHE_FILE,'r') as vf: VENDOR_CACHE=json.load(vf)
    else:
        VENDOR_CACHE={}
except Exception:
    VENDOR_CACHE={}

try:
    if os.path.exists(PORT_HISTORY_FILE):
        with open(PORT_HISTORY_FILE,'r') as pf: PORT_HISTORY=json.load(pf)
    else:
        PORT_HISTORY={}
except Exception:
    PORT_HISTORY={}

def save_vendor_cache():
    try:
        with open(VENDOR_CACHE_FILE,'w') as vf: json.dump(VENDOR_CACHE,vf,indent=2)
    except Exception:
        pass

def save_port_history():
    try:
        with open(PORT_HISTORY_FILE,'w') as pf: json.dump(PORT_HISTORY,pf,indent=2)
    except Exception:
        pass

def update_port_history(ip, parsed_data):
    """Store current ports for delta comparison in future runs."""
    timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    PORT_HISTORY[ip]={
        'last_seen': timestamp,
        'tcp_ports': list(parsed_data.get('tcp',{}).keys()),
        'udp_ports': list(parsed_data.get('udp',{}).keys()),
        'risk_score': parsed_data.get('risk_score',0),
        'services': parsed_data.get('services',{})
    }
    save_port_history()

# Database setup
conn = sqlite3.connect('nmap_agent.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS tasks (
id INTEGER PRIMARY KEY,
task TEXT,
handling TEXT,
expected TEXT,
actual TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS prompts (
id INTEGER PRIMARY KEY,
name TEXT UNIQUE,
template TEXT,
description TEXT
)''')

# Insert prompts into database
prompts = [
    ('task_decomposer', 'You are an Nmap agent. Task: {task}\nDecompose into steps using functions: {functions}\nOutput Python list: [{{"function":"name","arguments":{{}}}}]', 'Main decomposition'),
    ('iot_specialist', 'You are an IoT specialist. Task: {task}\nFor IoT/smart devices:\n1. Network discovery\n2. IoT ports (80,443,8080,1883,5683)\n3. Vulnerability scan\nOutput function calls: [{{"function":"name","arguments":{{}}}}]', 'IoT specialist'),
    ('vuln_hunter', 'You are a vulnerability researcher. Task: {task}\nApproach:\n1. Port scan\n2. Service discovery\n3. Vulnerability scripts\nOutput: [{{"function":"name","arguments":{{}}}}]', 'Vulnerability hunter'),
    ('suggestions', 'Based on result: {result}\nFor task: {task}\nSuggest 3-5 next steps.', 'Suggestions')
]

for name, template, desc in prompts:
    c.execute('INSERT OR REPLACE INTO prompts (name, template, description) VALUES (?, ?, ?)', (name, template, desc))

conn.commit()

with open('manifests/short_manifest.json') as f: manifest = json.load(f)

cmds = {
    'ping_discovery': 'nmap -T4 -sn -oG - {target}',
    'top_ports_scan': 'nmap -T4 -p {ports} -oG - {target}',
    'udp_top_ports_scan': 'nmap -T4 -sU --top-ports 50 -oG - {target}',
    'service_discovery': 'nmap -T4 -sV -p {ports} {target}',
    'script_lookup': 'nmap -T4 --script {scripts} {target}',
    'snmp_probe': 'nmap -T4 -sU -p 161 --script snmp-info,snmp-interfaces -oN - {target}',
    'upnp_probe': 'nmap -T4 -sU -p 1900 --script upnp-info -oN - {target}',
    'udp_script_lookup': 'nmap -T4 -sU --script {scripts} -p {ports} -oN - {target}',
    # added refinement steps
    'focused_top': 'nmap -T4 -F -oG - {target}',
    'light_vuln': 'nmap -T4 -sV --script vuln,default,safe -p {ports} {target}'
}

def get_prompt(name, **kwargs):
    result = c.execute('SELECT template FROM prompts WHERE name = ?', (name,)).fetchone()
    if result:
        return result[0].format(**kwargs)
    return f"Task: {kwargs.get('task', 'Unknown')}"

def progress_bar(stop_event, label="Waiting for LLM", budget=10):
    start = time.time(); frames=['|','/','-','\\']; i=0
    while not stop_event.is_set():
        elapsed = time.time() - start
        remaining = max(0, budget - elapsed)
        print(f"\r{label} {frames[i%4]} {remaining:4.1f}s budget", end='', flush=True)
        i+=1; time.sleep(0.25)
    print('\r' + ' '*60 + '\r', end='', flush=True)

def build_context(limit=3):
    try:
        rows = c.execute('SELECT task, actual FROM tasks ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        if not rows:
            return ''
        return 'Recent:\n' + '\n'.join(f"- {t[:60]} (time {a})" for t,a in rows) + '\n'
    except Exception:
        return ''

def db_informed_functions():
    try:
        rows = c.execute('SELECT handling FROM tasks ORDER BY id DESC LIMIT 5').fetchall()
        text = ' '.join(r[0].lower() for r in rows)
        if 'fast_track' in text and 'vuln' not in text:
            return ['ping_discovery','top_ports_scan','service_discovery','script_lookup','light_vuln']
    except Exception:
        pass
    return ['ping_discovery','top_ports_scan','service_discovery','script_lookup']

def execute_nmap(name, args):
    args = dict(args)
    args.setdefault('target','192.168.1.0/24')
    args.setdefault('ports','22,80,443')
    args.setdefault('scripts','http-title')
    if 'ports' in args and isinstance(args['ports'], list):
        args['ports']=','.join(str(p) for p in args['ports'])
    if 'scripts' in args and isinstance(args['scripts'], list):
        args['scripts']=','.join(args['scripts'])
    # Special handling for parallel command
    if name == 'parallel_tcp_udp':
        parallel_res = parallel_tcp_udp_scan(args.get('target', '192.168.1.0/24'))
        return f"TCP Output:\n{parallel_res['tcp_output']}\n\nUDP Output:\n{parallel_res['udp_output']}"
    
    if name not in cmds:
        print(f"Unknown function {name}"); return ''
    cmd = cmds[name].format(**args)
    # tuning
    if name=='ping_discovery': cmd=cmd.replace('-T4','-T5')+' --max-retries 0'
    elif name in ('top_ports_scan','focused_top'): cmd=cmd.replace('-T4','-T5')+' --max-retries 1 --host-timeout 20s'
    if 'vuln' in args.get('scripts','') or name=='light_vuln': cmd=cmd.replace('-T4','-T5')+' --host-timeout 30s --max-retries 1'
    print(f"Running: {cmd}")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=65)
        combined = (r.stdout + r.stderr).strip()
        if ('root privileges' in combined.lower() or 'requires root' in combined.lower()) and os.geteuid() != 0:
            # Attempt sudo escalation if interactive terminal
            try:
                pw = getpass.getpass(prompt='Root password required for this scan (leave blank to skip): ')
                if pw:
                    sudo_cmd = f"echo {pw!r} | sudo -S {cmd}"
                    print("Re-running with sudo...")
                    r2 = subprocess.run(sudo_cmd, shell=True, capture_output=True, text=True, timeout=65)
                    combined = (r2.stdout + r2.stderr).strip()
            except Exception as esc_e:
                print(f"Privilege escalation skipped: {esc_e}")
        return combined
    except subprocess.TimeoutExpired:
        print('Nmap timed out. Partial/empty result.'); return ''

def extract_hosts(scan_output, limit=6):
    hosts=[]
    for line in scan_output.splitlines():
        if 'Nmap scan report for' in line:
            parts=line.split()
            if parts and parts[-1] != 'for':
                hosts.append(parts[-1])
    uniq=[]; seen=set()
    for h in hosts:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq[:limit]

MAC_LINE_RE=re.compile(r'MAC Address: ([0-9A-Fa-f:]{17}) \(([^)]+)\)')
def parse_mac_vendors(output):
    """Extract MAC -> vendor from nmap output, update cache by OUI (first 3 bytes)."""
    updated=False
    for line in output.splitlines():
        m=MAC_LINE_RE.search(line)
        if m:
            mac=m.group(1).upper(); vendor=m.group(2).strip()
            oui=':'.join(mac.split(':')[:3])
            if oui not in VENDOR_CACHE:
                VENDOR_CACHE[oui]=vendor
                updated=True
    if updated: save_vendor_cache()

def lookup_vendor_by_mac(mac):
    mac=mac.upper()
    oui=':'.join(mac.split(':')[:3])
    return VENDOR_CACHE.get(oui)

VENDOR_HEURISTICS={
    'LG': {'priority_bonus': 4, 'common_ports': [80,443,1900,8080,8888,9000], 'scripts': ['http-title','upnp-info','http-methods']},
    'SAMSUNG': {'priority_bonus': 4, 'common_ports': [80,443,1900,8080,7001,8001], 'scripts': ['http-title','upnp-info']},
    'SONY': {'priority_bonus': 3, 'common_ports': [80,443,1900,8080,8001], 'scripts': ['http-title','upnp-info']},
    'SMART': {'priority_bonus': 3, 'common_ports': [80,443,1900,8080,8888], 'scripts': ['http-title','upnp-info']},
    'ROKU': {'priority_bonus': 3, 'common_ports': [80,8060,8080], 'scripts': ['http-title']},
    'APPLE': {'priority_bonus': 2, 'common_ports': [80,443,5000,7000], 'scripts': ['http-title']}
}

def apply_vendor_heuristics(vendor_name, base_score=0):
    """Boost priority and suggest ports/scripts based on vendor."""
    vendor_upper=vendor_name.upper()
    for key, data in VENDOR_HEURISTICS.items():
        if key in vendor_upper:
            return base_score + data['priority_bonus'], data
    return base_score, {}

def parse_open_ports_enhanced(output):
    """Parse grepable (-oG -) nmap output for both TCP and UDP open ports with risk scoring."""
    mapping={}
    for line in output.splitlines():
        if line.startswith('Host:') and 'Ports:' in line:
            try:
                ip=line.split()[1]
                ports_seg=line.split('Ports:')[1]
                entries=[p.strip() for p in ports_seg.split(',') if '/open/' in p]
                tcp_services={}; udp_services={}
                for e in entries:
                    # Example tokens: 80/open/tcp//http/// or 161/open/udp//snmp///
                    parts=e.split('/')
                    if len(parts) >= 5:
                        port_raw=parts[0]; state=parts[1]; proto=parts[2]; svc=parts[4] or 'unknown'
                        if state!='open' or not port_raw.isdigit():
                            continue
                        port=int(port_raw)
                        if proto=='tcp':
                            tcp_services[port]=svc
                        elif proto=='udp':
                            udp_services[port]=svc
                combined_services={**udp_services, **tcp_services}  # tcp overwrites if overlap
                all_ports=sorted(set(list(tcp_services.keys())+list(udp_services.keys())))
                # risk heuristics
                high_value_ports=[p for p in all_ports if p in (22,23,445,3389,5900)]
                web_ports=[p for p in all_ports if p in (80,443,8080,8443,8000,8888)]
                broadcast_ports=[p for p in all_ports if p in (161,1900,5353)]
                streaming_ports=[p for p in all_ports if p in (554,1935)]
                data_ports=[p for p in all_ports if p in (9200,6379)]
                risk= (len(high_value_ports)*2 + len(web_ports)*1.5 + len(broadcast_ports)*2 +
                       len(streaming_ports)*3 + len(data_ports)*2)
                mapping[ip]={
                    'open_ports': all_ports,
                    'tcp': tcp_services,
                    'udp': udp_services,
                    'services': combined_services,
                    'risk_score': risk,
                    'risk_factors': {
                        'high_value_ports': high_value_ports,
                        'management_ports': data_ports,
                        'broadcast_ports': broadcast_ports,
                        'streaming_ports': streaming_ports,
                        'web_ports': web_ports
                    }
                }
                update_port_history(ip, mapping[ip])
            except Exception:
                continue
    return mapping

def parse_grepable_hosts(output):
    hosts=[]
    for line in output.splitlines():
        if line.startswith('Host:'):
            # Format: Host: 192.168.1.10 ()  Status: Up
            parts=line.split()
            if len(parts)>=2:
                ip=parts[1]
                name=None
                if '(' in line and ')' in line:
                    inside=line.split('(')[1].split(')')[0].strip()
                    if inside:
                        name=inside
                if not name:
                    name=ip
                hosts.append((name, ip))
    # de-dup by ip
    seen=set(); out=[]
    for n,ip in hosts:
        if ip not in seen:
            seen.add(ip); out.append((n,ip))
    return out

def pick_tv_candidate(hosts):
    # 🧠 SMART TARGET SELECTION: Use learned network topology
    best_candidate = None
    best_score = 0
    
    for h in hosts:
        score = 0
        
        # 🧠 Use learned topology knowledge
        if h in AGENT_INTELLIGENCE['network_topology']:
            topo = AGENT_INTELLIGENCE['network_topology'][h]
            score += topo['seen_count']  # Prefer frequently seen hosts
            score += topo['reliability'] * 5  # Prefer reliable hosts
            
            # Boost score if we've seen TV-like ports before
            tv_ports = {80, 443, 554, 1900, 8080, 8000, 8888}
            common_ports = set(topo.get('typical_ports', []))
            if tv_ports.intersection(common_ports):
                score += 15
                print(f"🧠 {h} has TV-like ports from history: {tv_ports.intersection(common_ports)}")
        
        # Original IP range heuristic
        try:
            last=int(h.split('.')[-1])
            if 5<=last<=60: 
                score += 8
        except Exception:
            pass
        
        if score > best_score:
            best_score = score
            best_candidate = h
    
    if best_candidate and best_score > 5:
        print(f"🧠 Smart candidate selection: {best_candidate} (score: {best_score})")
        return best_candidate
    
    # Fallback to original logic
    for h in hosts:
        try:
            last=int(h.split('.')[-1])
            if 5<=last<=60: return h
        except Exception:
            continue
    return hosts[0] if hosts else None

VULN_PATTERNS = [
    'cve-','vulnerable','vulnerability','exploit','weak cipher','default credential',
    'authentication bypass','information disclosure','denial of service','buffer overflow',
    'sql injection','xss','path traversal','remote code execution','privilege escalation'
]

def count_vulns(text):
    t=text.lower(); count=0
    for p in VULN_PATTERNS: count += t.count(p)
    if '|_' in text: count += text.count('|_')
    return count

# Learning and Intelligence System
LEARNING_FILE = 'agent_intelligence.json'
try:
    if os.path.exists(LEARNING_FILE):
        with open(LEARNING_FILE, 'r') as f:
            AGENT_INTELLIGENCE = json.load(f)
    else:
        AGENT_INTELLIGENCE = {
            'success_patterns': {},
            'failure_analysis': {},
            'network_topology': {},
            'vendor_intelligence': {},
            'timing_optimization': {},
            'scan_effectiveness': {},
            'iteration_count': 0
        }
except Exception:
    AGENT_INTELLIGENCE = {
        'success_patterns': {},
        'failure_analysis': {},
        'network_topology': {},
        'vendor_intelligence': {},
        'timing_optimization': {},
        'scan_effectiveness': {},
        'iteration_count': 0
    }

def save_agent_intelligence():
    try:
        with open(LEARNING_FILE, 'w') as f:
            json.dump(AGENT_INTELLIGENCE, f, indent=2)
    except Exception as e:
        print(f"Warning: could not save intelligence: {e}")

def learn_from_iteration(task, strategy, execution_time, findings, success_indicators):
    """Core learning function - updates agent intelligence from each run."""
    AGENT_INTELLIGENCE['iteration_count'] += 1
    
    # 1. Success Pattern Learning
    task_type = classify_task_type(task)
    if task_type not in AGENT_INTELLIGENCE['success_patterns']:
        AGENT_INTELLIGENCE['success_patterns'][task_type] = {'wins': 0, 'total': 0, 'best_strategy': None, 'avg_time': 0}
    
    pattern = AGENT_INTELLIGENCE['success_patterns'][task_type]
    pattern['total'] += 1
    
    if success_indicators > 0:
        pattern['wins'] += 1
        pattern['best_strategy'] = strategy
        pattern['avg_time'] = (pattern['avg_time'] + execution_time) / 2
    
    # 2. Timing Optimization Learning
    if strategy not in AGENT_INTELLIGENCE['timing_optimization']:
        AGENT_INTELLIGENCE['timing_optimization'][strategy] = {'avg_time': execution_time, 'runs': 1, 'success_rate': 0}
    else:
        opt = AGENT_INTELLIGENCE['timing_optimization'][strategy]
        opt['avg_time'] = (opt['avg_time'] * opt['runs'] + execution_time) / (opt['runs'] + 1)
        opt['runs'] += 1
        if success_indicators > 0:
            opt['success_rate'] = (opt['success_rate'] + 1) / opt['runs']
    
    # 3. Network Topology Memory
    if findings:
        for host_ip, host_data in findings.items():
            if host_ip not in AGENT_INTELLIGENCE['network_topology']:
                AGENT_INTELLIGENCE['network_topology'][host_ip] = {
                    'seen_count': 0, 'last_seen': None, 'typical_ports': set(),
                    'response_time': None, 'reliability': 1.0
                }
            
            topo = AGENT_INTELLIGENCE['network_topology'][host_ip]
            topo['seen_count'] += 1
            topo['last_seen'] = time.strftime('%Y-%m-%dT%H:%M:%SZ')
            if 'ports' in host_data:
                topo['typical_ports'].update(host_data['ports'])
                topo['typical_ports'] = list(topo['typical_ports'])  # JSON serializable
    
    save_agent_intelligence()

def classify_task_type(task):
    """Classify task into learning categories."""
    task_lower = task.lower()
    if any(k in task_lower for k in ['tv', 'smart', 'iot']):
        return 'smart_device_hunting'
    elif any(k in task_lower for k in ['vuln', 'security', 'exploit']):
        return 'vulnerability_assessment'  
    elif any(k in task_lower for k in ['discover', 'scan', 'network']):
        return 'network_discovery'
    else:
        return 'general_reconnaissance'

def get_smart_recommendations(task):
    """Provide intelligent recommendations based on learning history."""
    task_type = classify_task_type(task)
    recommendations = {'strategy': None, 'estimated_time': 30, 'confidence': 0.5, 'insights': []}
    
    # Get success pattern insights
    if task_type in AGENT_INTELLIGENCE['success_patterns']:
        pattern = AGENT_INTELLIGENCE['success_patterns'][task_type]
        if pattern['total'] > 0:
            success_rate = pattern['wins'] / pattern['total']
            recommendations['strategy'] = pattern['best_strategy']
            recommendations['estimated_time'] = pattern['avg_time']
            recommendations['confidence'] = success_rate
            recommendations['insights'].append(f"Success rate for {task_type}: {success_rate:.1%}")
    
    # Get timing optimization insights
    best_strategy = None
    best_success_rate = 0
    for strategy, data in AGENT_INTELLIGENCE['timing_optimization'].items():
        if data['success_rate'] > best_success_rate:
            best_success_rate = data['success_rate'] 
            best_strategy = strategy
            recommendations['insights'].append(f"{strategy} avg: {data['avg_time']:.1f}s, success: {data['success_rate']:.1%}")
    
    if best_strategy and not recommendations['strategy']:
        recommendations['strategy'] = best_strategy
    
    # Network topology insights
    active_hosts = len([h for h in AGENT_INTELLIGENCE['network_topology'].values() if h['seen_count'] > 1])
    if active_hosts > 0:
        recommendations['insights'].append(f"{active_hosts} reliable hosts in topology memory")
    
    return recommendations

def update_tasks_json(entry):
    path='tasks.json'
    try:
        data=[]
        if os.path.exists(path):
            with open(path,'r') as f:
                data=json.load(f)
        data.append(entry)
        with open(path,'w') as f:
            json.dump(data,f,indent=2)
    except Exception as e:
        print(f"Warning: could not update tasks.json: {e}")

def parallel_tcp_udp_scan(target, tcp_timeout=25, udp_timeout=30):
    """Run top TCP and UDP scans in parallel threads, return combined results."""
    tcp_result=[None]; udp_result=[None]; errors=[]
    
    def tcp_scan():
        try:
            tcp_result[0]=execute_nmap('top_ports_scan', {'target': target, 'ports': '80,443,22,23,8080,8888,9000,5000'})
        except Exception as e:
            errors.append(f"TCP: {e}")
    
    def udp_scan():
        try:
            udp_result[0]=execute_nmap('udp_top_ports_scan', {'target': target})
        except Exception as e:
            errors.append(f"UDP: {e}")
    
    tcp_thread=threading.Thread(target=tcp_scan)
    udp_thread=threading.Thread(target=udp_scan)
    
    start=time.time()
    tcp_thread.start(); udp_thread.start()
    tcp_thread.join(timeout=tcp_timeout); udp_thread.join(timeout=udp_timeout)
    elapsed=time.time()-start
    
    if tcp_thread.is_alive() or udp_thread.is_alive():
        print(f"Warning: parallel scan threads may still be running after {elapsed:.1f}s")
    
    return {
        'tcp_output': tcp_result[0] or '',
        'udp_output': udp_result[0] or '',
        'elapsed': elapsed,
        'errors': errors
    }

def ssdp_preselect_tv(timeout=2):
    """Quick SSDP M-SEARCH to identify smart TV devices."""
    try:
        msg='M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try: 
            sock.sendto(msg.encode(), ('239.255.255.250',1900))
        except Exception: 
            pass
        start=time.time()
        while time.time()-start<timeout:
            try:
                data, addr=sock.recvfrom(2048)
                low=data.decode(errors='ignore').lower()
                if any(k in low for k in ['lg','webos','lge']) and 'tv' in low:
                    sock.close()
                    return addr[0], 'LG'
                if 'smart' in low and 'tv' in low:
                    sock.close()
                    return addr[0], 'SMART'
                if any(k in low for k in ['samsung','sony','roku']) and ('tv' in low or 'media' in low):
                    brand=next((k.upper() for k in ['samsung','sony','roku'] if k in low), 'SMART')
                    sock.close()
                    return addr[0], brand
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception as e:
        print(f"SSDP discovery error: {e}")
    return None, None

def heuristic_fallback_analysis(prompt):
    """Provide smart fallback function calls when LLM is unavailable."""
    prompt_lower = prompt.lower()
    
    # Extract target from prompt if present
    target = '192.168.1.0/24'  # Default subnet
    import re
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', prompt)
    if ip_match:
        target = ip_match.group(1)
    
    # If it's a vulnerability/security analysis request
    if 'vulnerabilit' in prompt_lower or 'security' in prompt_lower:
        return '[{"name": "ping_discovery", "args": {"target": "' + target + '"}}, {"name": "top_ports_scan", "args": {"target": "' + target + '", "ports": "22,23,80,443,8080"}}, {"name": "script_lookup", "args": {"target": "' + target + '", "scripts": "vuln"}}]'
    
    # If it's an IoT/smart device analysis
    elif 'iot' in prompt_lower or 'smart' in prompt_lower or 'tv' in prompt_lower:
        return '[{"name": "ping_discovery", "args": {"target": "192.168.1.0/24"}}, {"name": "top_ports_scan", "args": {"target": "192.168.1.0/24", "ports": "80,443,554,8080,1900,8000,8888"}}, {"name": "udp_top_ports_scan", "args": {"target": "192.168.1.0/24"}}]'
    
    # If it's about specific host analysis
    elif ip_match:
        return '[{"name": "top_ports_scan", "args": {"target": "' + target + '", "ports": "22,23,80,443,8080"}}, {"name": "script_lookup", "args": {"target": "' + target + '", "scripts": "default"}}]'
    
    # Default fallback - network discovery
    return '[{"name": "ping_discovery", "args": {"target": "192.168.1.0/24"}}]'

def call_llm(prompt, model='tinyllama:latest', timeout=8, retries=1):
    attempt=0
    while attempt<=retries:
        stop_event=threading.Event()
        t=threading.Thread(target=progress_bar, args=(stop_event,f'LLM attempt {attempt+1}/{retries+1}', timeout))
        t.start()
        try:
            resp = requests.post('http://localhost:11434/api/generate', json={'model':model,'prompt':prompt,'stream':False,'options':{'temperature':0.15}}, timeout=timeout)
            stop_event.set(); t.join()
            data=resp.json(); text=data.get('response','').strip()
            m=re.search(r'[\[\{].*[\]\}]', text, re.DOTALL)
            if m: text=m.group(0)
            print(f"\033[92mLLM: {text}\033[0m")
            return text,0,0,0
        except Exception as e:
            stop_event.set(); t.join()
            print(f'LLM error attempt {attempt+1}: {e}')
            attempt+=1; time.sleep(0.6*attempt)
    print('LLM unreachable after retries. Using heuristic fallback.')
    # Smart fallback analysis
    fallback_result = heuristic_fallback_analysis(prompt)
    return fallback_result,0,0,0

def select_strategy(task):
    task_lower = task.lower()
    if any(k in task_lower for k in ['light', 'bulb', 'smart', 'iot', 'tv']):
        return 'iot_specialist'
    elif any(k in task_lower for k in ['vulnerab', 'vuln', 'security']):
        return 'vuln_hunter'
    else:
        return 'task_decomposer'

def fast_track_iot(task):
    task_lower=task.lower()
    if any(str(i) in task_lower for i in range(30,121)) and 'second' in task_lower:
        if any(k in task_lower for k in ['tv','smart','iot']):
            # Try SSDP preselection first for TV tasks
            if 'tv' in task_lower:
                candidate_ip, brand = ssdp_preselect_tv(timeout=1.8)
                if candidate_ip:
                    print(f"SSDP preselected: {candidate_ip} brand={brand}")
                    vendor_score, vendor_hints = apply_vendor_heuristics(brand or '')
                    target_ports = vendor_hints.get('common_ports', [80,443,1900,8080,8888])
                    target_scripts = vendor_hints.get('scripts', ['http-title','upnp-info'])
                    return [
                        {'function':'parallel_tcp_udp','arguments':{'target':candidate_ip}},
                        {'function':'service_discovery','arguments':{'target':candidate_ip,'ports':','.join(str(p) for p in target_ports[:15])}},
                        {'function':'script_lookup','arguments':{'target':candidate_ip,'scripts':','.join(target_scripts),'ports':','.join(str(p) for p in target_ports[:15])}},
                        {'function':'light_vuln','arguments':{'target':candidate_ip,'ports':','.join(str(p) for p in target_ports[:15])}}
                    ]
            # Fallback to original fast track
            return [
                {'function':'ping_discovery','arguments':{'target':'192.168.1.0/24'}},
                {'function':'top_ports_scan','arguments':{'ports':'22,23,80,443,554,7001,8000,8080,8888,9000','target':'192.168.1.0/24'}},
                {'function':'script_lookup','arguments':{'scripts':'vuln','target':'192.168.1.0/24'}}
            ]
    return None

if len(sys.argv) > 1:
    initial_task = ' '.join(sys.argv[1:])
    interactive = False
else:
    initial_task = "Scan this network for devices"
    interactive = True

history = [{"user": initial_task}]
history_start_time = time.time()

while True:
    funcs = db_informed_functions()
    
    # 🧠 SMART LEARNING: Get intelligent recommendations based on past iterations
    smart_recs = get_smart_recommendations(history[0]['user'])
    if smart_recs['confidence'] > 0.7:
        print(f"\033[94m🧠 SMART MODE: Using learned strategy '{smart_recs['strategy']}' (confidence: {smart_recs['confidence']:.1%})\033[0m")
        for insight in smart_recs['insights']:
            print(f"  💡 {insight}")
    elif AGENT_INTELLIGENCE['iteration_count'] > 0:
        print(f"\033[93m🧠 Learning Mode: Iteration #{AGENT_INTELLIGENCE['iteration_count']} (building intelligence...)\033[0m")

    # Special task: just list machines
    task_lower_all = history[0]['user'].lower()
    if ('list' in task_lower_all and 'machine' in task_lower_all) or ('list' in task_lower_all and 'host' in task_lower_all):
        print("Enumerating hosts (ping sweep)...")
        sweep = execute_nmap('ping_discovery', {'target': '192.168.1.0/24'})
        parse_mac_vendors(sweep)  # Extract vendor info
        host_pairs = parse_grepable_hosts(sweep)
        if not host_pairs:
            # fallback simple extraction
            simple = extract_hosts(sweep, limit=32)
            host_pairs=[(h,h) for h in simple]
        for name, ip in host_pairs:
            print(f"{name} - {ip}")
        elapsed_time = time.time() - history_start_time
        c.execute('INSERT INTO tasks (task, handling, expected, actual) VALUES (?, ?, ?, ?)',
                  (history[0]['user'], 'enumeration', '10-30s', f"{elapsed_time:.2f}s"))
        update_tasks_json({'task': history[0]['user'], 'mode': 'enumeration', 'hosts_found': len(host_pairs), 'execution_time_sec': round(elapsed_time,2)})
        if interactive:
            next_task = input("Next task (or 'exit'): ")
            if next_task.lower() == 'exit':
                break
            history=[{"user": next_task}]; history_start_time=time.time(); continue
        else:
            break
    
    # Check for fast-track optimization first
    fast_calls = fast_track_iot(history[0]['user'])
    if fast_calls:
        print(f"\033[91mFAST-TRACK MODE: executing {len(fast_calls)} optimized commands (heuristic)\033[0m")
        all_results = []
        for func_call in fast_calls:
            result = execute_nmap(func_call['function'], func_call['arguments'])
            history.append({'call': func_call, 'result': result})
            all_results.append(result)
            print(f"Result: {result[:600]}")
            # Parse MAC vendors from discovery scans
            if func_call['function'] in ('ping_discovery',):
                parse_mac_vendors(result)
            # Parse and store port data from scans
            if func_call['function'] in ('top_ports_scan', 'parallel_tcp_udp'):
                port_data = parse_open_ports_enhanced(result)
                for ip, data in port_data.items():
                    update_port_history(ip, data)
        
        elapsed_time = time.time() - history_start_time
        # Better vulnerability counting - look for actual vulnerability indicators in all results
        combined_results = '\n'.join(all_results)
        vuln_count = count_vulns(combined_results)
        print(f"\033[92mFast-track finished in {elapsed_time:.1f}s; indicators_of_vuln={vuln_count}\033[0m")
        
        c.execute('INSERT INTO tasks (task, handling, expected, actual) VALUES (?, ?, ?, ?)', 
                 (history[0]['user'], f"fast_track, {len(fast_calls)} calls", "50s", f"{elapsed_time:.2f}s"))
        update_tasks_json({
            'task': history[0]['user'],
            'mode': 'fast_track',
            'calls': len(fast_calls),
            'execution_time_sec': round(elapsed_time,2),
            'indicators_of_vuln': vuln_count,
            'status': 'vulns_detected' if vuln_count>0 else 'no_findings'
        })
        
        # Export run summary
        try:
            summary={
                'task': history[0]['user'],
                'elapsed_seconds': round(elapsed_time,2),
                'mode': 'fast_track',
                'calls_executed': len(fast_calls),
                'indicators_of_vuln': vuln_count,
                'status': 'vulns_detected' if vuln_count>0 else 'no_findings',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            }
            with open('last_run_summary.json','w') as f: json.dump(summary,f,indent=2)
        except Exception as e:
            print(f"Warning: could not write last_run_summary.json: {e}")
        
        # 🧠 LEARN FROM THIS ITERATION
        findings_data = {}
        for ip, data in PORT_HISTORY.items():
            if data.get('last_seen') and time.time() - time.mktime(time.strptime(data['last_seen'], '%Y-%m-%dT%H:%M:%SZ')) < 300:  # within 5 mins
                findings_data[ip] = {'ports': data.get('tcp_ports', []) + data.get('udp_ports', []), 'risk_score': data.get('risk_score', 0)}
        
        learn_from_iteration(
            task=history[0]['user'],
            strategy='fast_track',
            execution_time=elapsed_time,
            findings=findings_data,
            success_indicators=vuln_count
        )
        print(f"\033[96m🧠 Learned from iteration (now {AGENT_INTELLIGENCE['iteration_count']} total)\033[0m")
        
        if interactive:
            next_task = input("Next task (or 'exit'): ")
            if next_task.lower() == 'exit':
                break
            history = [{"user": next_task}]
            history_start_time = time.time()
        else:
            break
        continue
    
    # Standard LLM-driven approach with smart strategy selection
    if smart_recs['strategy'] and smart_recs['confidence'] > 0.6:
        strategy = smart_recs['strategy']
        print(f"\033[94m🧠 Using LEARNED strategy: {strategy} (confidence: {smart_recs['confidence']:.1%})\033[0m")
    else:
        strategy = select_strategy(history[0]['user'])
        print(f"\033[93mUsing {strategy} strategy...\033[0m")
    
    prompt = build_context() + get_prompt(strategy, task=history[0]['user'], functions=', '.join(funcs)) + "\nReturn ONLY a Python list."[:120]
    llm_response, time_taken, _, _ = call_llm(prompt)
    
    try:
        # Try JSON first (for fallback), then ast.literal_eval
        try:
            func_data = json.loads(llm_response)
        except:
            func_data = ast.literal_eval(llm_response)
        
        if not isinstance(func_data, list):
            raise ValueError("Need list")
        
        if not func_data:
            # Fallback
            task = history[0]['user'].lower()
            target = 'localhost' if 'this machine' in task else '192.168.1.0/24'
            if any(k in task for k in ['light', 'bulb', 'smart', 'iot']):
                func_data = [
                    {'function': 'ping_discovery', 'arguments': {'target': '192.168.1.0/24'}},
                    {'function': 'top_ports_scan', 'arguments': {'ports': '80,443,8080,1883', 'target': '192.168.1.0/24'}},
                    {'function': 'script_lookup', 'arguments': {'scripts': 'vuln', 'target': '192.168.1.0/24'}}
                ]
            else:
                func_data = [{'function': 'ping_discovery', 'arguments': {'target': target}}]
        
        # Execute functions
        discovered_hosts=[]; last_result=''
        for func_call in func_data:
            if 'function' in func_call:
                func_call['name']=func_call.pop('function')
                func_call['args']=func_call.pop('arguments', {})
            result = execute_nmap(func_call['name'], func_call.get('args', {}))
            last_result = result
            if func_call['name']=='ping_discovery':
                discovered_hosts = extract_hosts(result)
            history.append({'call': func_call, 'result': result})
            print(f"Result: {result[:600]}")
        if discovered_hosts:
            cand = pick_tv_candidate(discovered_hosts)
            if cand:
                extra = execute_nmap('focused_top', {'target': cand})
                history.append({'call':{'name':'focused_top','args':{'target':cand}},'result':extra})
                print(f"Focused scan {cand}: {extra[:400]}")
                light = execute_nmap('light_vuln', {'target': cand, 'ports':'80,443,554,8000,8080,8888,9000'})
                history.append({'call':{'name':'light_vuln','args':{'target':cand}},'result':light})
                print(f"Light vuln scripts {cand}: {light[:400]}")
                last_result += '\n'+light
        
        print("="*50)
        
        # Time tracking
        elapsed_time = time.time() - history_start_time
        task_lower = history[0]['user'].lower()
        time_limit = 180 if any(k in task_lower for k in ['light', 'bulb', 'smart', 'iot']) else 120
        
        vuln_count = count_vulns(last_result)
        if elapsed_time > (time_limit * 0.8):
            suggestions_resp = f"Time: {elapsed_time:.1f}s/{time_limit}s. indicators_of_vuln={vuln_count}."
        else:
            suggestions_prompt = get_prompt('suggestions', result=last_result[:900], task=history[0]['user'])
            suggestions_resp, _, _, _ = call_llm(suggestions_prompt)
        
        print(f"\033[94mSuggestions: {suggestions_resp}\033[0m")
        
        c.execute('INSERT INTO tasks (task, handling, expected, actual) VALUES (?, ?, ?, ?)', 
                 (history[0]['user'], f"{strategy}, {len(func_data)} calls", f"{time_limit}s", f"{elapsed_time:.2f}s"))
        update_tasks_json({
            'task': history[0]['user'],
            'mode': 'standard',
            'strategy': strategy,
            'calls': len(func_data),
            'execution_time_sec': round(elapsed_time,2),
            'indicators_of_vuln': vuln_count,
            'status': 'vulns_detected' if vuln_count>0 else 'no_findings'
        })
        
        # 🧠 LEARN FROM STANDARD EXECUTION
        findings_data = {}
        for ip, data in PORT_HISTORY.items():
            if data.get('last_seen') and time.time() - time.mktime(time.strptime(data['last_seen'], '%Y-%m-%dT%H:%M:%SZ')) < 300:
                findings_data[ip] = {'ports': data.get('tcp_ports', []) + data.get('udp_ports', []), 'risk_score': data.get('risk_score', 0)}
        
        learn_from_iteration(
            task=history[0]['user'],
            strategy=strategy,
            execution_time=elapsed_time,
            findings=findings_data,
            success_indicators=vuln_count
        )
        print(f"\033[96m🧠 Learned from {strategy} iteration (now {AGENT_INTELLIGENCE['iteration_count']} total)\033[0m")
        
        if interactive:
            next_task = input("Next task (or 'exit'): ")
            if next_task.lower() == 'exit':
                break
            history = [{"user": next_task}]
            history_start_time = time.time()
        else:
            break
            
    except Exception as e:
        print(f'Error: {e}')
        # Simple fallback
        result = execute_nmap('ping_discovery', {'target': '192.168.1.0/24'})
        print(f"Fallback result (ping only): {result[:400]}")
        elapsed_time = time.time() - history_start_time
        c.execute('INSERT INTO tasks (task, handling, expected, actual) VALUES (?, ?, ?, ?)', 
                  (history[0]['user'], "Error fallback", "120s", f"{elapsed_time:.2f}s"))
        update_tasks_json({
            'task': history[0]['user'],
            'mode': 'error_fallback',
            'execution_time_sec': round(elapsed_time,2),
            'status': 'error'
        })
        if not interactive:
            break

conn.commit()
conn.close()
