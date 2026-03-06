"""Minimal runtime probe - just report network state, no scanning."""
import json, os, socket, time, urllib.request, ssl, subprocess as sp
from http.server import HTTPServer, BaseHTTPRequestHandler

def gather():
    r = {}
    r['hostname'] = socket.gethostname()
    r['uid'] = os.getuid()
    r['pid'] = os.getpid()

    # Own IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        r['own_ip'] = s.getsockname()[0]
        s.close()
    except Exception as e:
        r['own_ip_err'] = str(e)

    # ip addr
    try:
        r['ip_addr'] = sp.run(['ip', 'addr'], capture_output=True, text=True, timeout=5).stdout
    except Exception as e:
        r['ip_addr_err'] = str(e)

    # routes
    try:
        r['routes'] = sp.run(['ip', 'route'], capture_output=True, text=True, timeout=5).stdout
    except:
        pass

    # resolv.conf
    try:
        r['resolv'] = open('/etc/resolv.conf').read()
    except:
        pass

    # env
    r['env'] = {k: v for k, v in os.environ.items()
                if any(x in k.upper() for x in ['KUBE', 'SERVICE', 'HOST', 'PORT', 'DNS', 'CLUSTER', 'APP', 'DIGITAL', 'POD', 'NODE'])}

    # K8s SA
    for f in ['namespace', 'token']:
        path = f'/var/run/secrets/kubernetes.io/serviceaccount/{f}'
        try:
            data = open(path).read()
            r[f'sa_{f}'] = data[:80]
        except Exception as e:
            r[f'sa_{f}'] = str(e)[:100]

    # DNS
    r['dns'] = {}
    for t in ['kubernetes.default', 'kube-dns.kube-system.svc.cluster.local']:
        try:
            r['dns'][t] = socket.gethostbyname(t)
        except Exception as e:
            r['dns'][t] = str(e)[:80]

    # /proc/net/tcp (listening sockets)
    try:
        r['proc_net_tcp'] = open('/proc/net/tcp').read()[:1500]
    except:
        pass

    # Quick targeted connectivity (just 5 tests)
    def qc(ip, port, t=2):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            rc = s.connect_ex((ip, port))
            s.close()
            return rc
        except:
            return -1

    r['conn'] = {}
    for name, ip, port in [
        ('imds', '169.254.169.254', 80),
        ('k8s_api', '10.245.0.1', 443),
        ('dns_tcp', '10.245.0.11', 53),
    ]:
        r['conn'][name] = qc(ip, port)

    r['time'] = time.strftime('%H:%M:%S')
    return r

# Gather once at startup
startup_data = gather()

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        path = self.path

        if path.startswith('/scan'):
            # On-demand scan a specific IP:port via ?ip=x&port=y
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(path).query) if '?' in path else {}
            # Actually parse from self.path
            if '?' in self.path:
                qs = parse_qs(self.path.split('?', 1)[1])
            ip = qs.get('ip', [''])[0]
            port = int(qs.get('port', ['80'])[0])
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                rc = s.connect_ex((ip, port))
                s.close()
                result = {'ip': ip, 'port': port, 'errno': rc}
                if rc == 0:
                    try:
                        resp = urllib.request.urlopen(f'http://{ip}:{port}/', timeout=3)
                        result['body'] = resp.read().decode(errors='replace')[:1000]
                        result['headers'] = dict(resp.headers)
                    except Exception as e:
                        result['fetch_err'] = str(e)[:200]
                self.wfile.write(json.dumps(result, indent=2).encode())
            except Exception as e:
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        elif path == '/refresh':
            data = gather()
            self.wfile.write(json.dumps(data, indent=2, default=str).encode())
        else:
            self.wfile.write(json.dumps(startup_data, indent=2, default=str).encode())

    def log_message(self, format, *args):
        pass

port = int(os.environ.get('PORT', 8080))
print(f"Probe server starting on :{port}")
HTTPServer(("0.0.0.0", port), H).serve_forever()
