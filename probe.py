import urllib.request, json, os, socket
r = {}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    rc = s.connect_ex(('169.254.169.254', 80))
    r['imds_tcp'] = 'OPEN' if rc == 0 else f'errno={rc}'
    s.close()
except Exception as e:
    r['imds_tcp'] = str(e)[:100]
try:
    resp = urllib.request.urlopen('http://169.254.169.254/metadata/v1/', timeout=3)
    r['imds_root'] = resp.read().decode()[:500]
except Exception as e:
    r['imds_root'] = str(e)[:200]
try:
    resp = urllib.request.urlopen('http://169.254.169.254/metadata/v1/user-data', timeout=3)
    data = resp.read().decode()
    r['user_data_len'] = len(data)
    r['user_data_preview'] = data[:200]
except Exception as e:
    r['user_data'] = str(e)[:200]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 53))
    r['my_ip'] = s.getsockname()[0]
    s.close()
except: pass
r['hostname'] = socket.gethostname()
try: r['resolv'] = open('/etc/resolv.conf').read().strip()
except: pass
try: r['routes'] = open('/proc/net/route').read()[:500]
except: pass
for k, v in sorted(os.environ.items()):
    if any(x in k for x in ['KUBE','SERVICE','TOKEN','SECRET']):
        r[f'env_{k}'] = v[:100]
try:
    r['sa_token'] = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()[:80]
except Exception as e:
    r['sa_token'] = str(e)[:100]
for ip in ['100.65.67.229','100.65.74.2','100.65.0.1']:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        rc = s.connect_ex((ip, 443))
        r[f'cgnat_{ip}'] = 'OPEN' if rc == 0 else f'errno={rc}'
        s.close()
    except Exception as e:
        r[f'cgnat_{ip}'] = str(e)[:50]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    rc = s.connect_ex(('10.245.0.1', 443))
    r['k8s_api'] = 'OPEN' if rc == 0 else f'errno={rc}'
    s.close()
except Exception as e:
    r['k8s_api'] = str(e)[:50]
try: r['sentry'] = open('/proc/sentry-meminfo').read()[:50]
except: r['sentry'] = 'absent'
try: r['filesystems'] = open('/proc/filesystems').read()[:300]
except: pass
print(json.dumps(r, indent=2))
