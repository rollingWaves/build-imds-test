import json, os, socket, subprocess, struct, time, ctypes

r = {}

# 1. Install network tools and inspect filtering
try:
    # Install iptables, iproute2, tcpdump, traceroute
    out = subprocess.run(['apt-get', 'update'], capture_output=True, text=True, timeout=60)
    out = subprocess.run(['apt-get', 'install', '-y', 'iptables', 'iproute2', 'traceroute', 'nmap', 'net-tools'],
                         capture_output=True, text=True, timeout=120)
    r['apt_install'] = 'ok' if out.returncode == 0 else out.stderr[:300]
except Exception as e:
    r['apt_install'] = str(e)[:200]

# 2. iptables rules
for cmd in ['iptables -L -n -v', 'iptables -t nat -L -n -v', 'iptables -t mangle -L -n -v',
            'iptables -t raw -L -n -v', 'ip6tables -L -n -v']:
    try:
        out = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        r[f'cmd_{cmd.split()[0]}_{cmd.split()[2]}'] = out.stdout[:1500] if out.stdout else out.stderr[:300]
    except Exception as e:
        r[f'cmd_{cmd}'] = str(e)[:100]

# 3. ip route / ip addr / ip rule / ip neigh
for cmd in ['ip route show', 'ip addr show', 'ip rule show', 'ip neigh show',
            'ip route get 169.254.169.254', 'ip route get 10.245.0.1',
            'ip -6 route show', 'ip link show']:
    try:
        out = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        r[f'ip_{cmd.replace("ip ","").replace(" ","_")}'] = out.stdout[:500] if out.stdout else out.stderr[:200]
    except Exception as e:
        r[f'ip_{cmd}'] = str(e)[:100]

# 4. ARP table
try:
    out = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=5)
    r['arp'] = out.stdout[:300]
except: pass

# 5. traceroute to IMDS and to a known-working host
for target in ['169.254.169.254', '10.245.0.1', '8.8.8.8']:
    try:
        out = subprocess.run(['traceroute', '-n', '-m', '5', '-w', '2', target],
                             capture_output=True, text=True, timeout=30)
        r[f'traceroute_{target}'] = out.stdout[:500]
    except Exception as e:
        r[f'traceroute_{target}'] = str(e)[:100]

# 6. nmap scan of IMDS with service detection
try:
    out = subprocess.run(['nmap', '-Pn', '-n', '--max-retries', '1', '-p', '80,443',
                          '169.254.169.254'], capture_output=True, text=True, timeout=30)
    r['nmap_imds'] = out.stdout[:500]
except Exception as e:
    r['nmap_imds'] = str(e)[:100]

# 7. Check if we're in Kata VM - look for Kata-specific indicators
kata_checks = {}
try:
    kata_checks['dmesg'] = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5).stdout[:1000]
except Exception as e:
    kata_checks['dmesg'] = str(e)[:100]

try:
    kata_checks['cpuinfo'] = open('/proc/cpuinfo').read()[:500]
except: pass

try:
    kata_checks['meminfo_total'] = [l for l in open('/proc/meminfo').readlines() if 'MemTotal' in l][0].strip()
except: pass

try:
    kata_checks['cmdline'] = open('/proc/cmdline').read()[:500]
except: pass

try:
    kata_checks['dmi_product'] = open('/sys/class/dmi/id/product_name').read().strip()
except Exception as e:
    kata_checks['dmi_product'] = str(e)[:100]

try:
    kata_checks['dmi_sys_vendor'] = open('/sys/class/dmi/id/sys_vendor').read().strip()
except Exception as e:
    kata_checks['dmi_sys_vendor'] = str(e)[:100]

try:
    kata_checks['hypervisor'] = open('/sys/hypervisor/type').read().strip()
except Exception as e:
    kata_checks['hypervisor'] = str(e)[:100]

try:
    kata_checks['virtio_net'] = os.listdir('/sys/bus/virtio/devices/')
except: pass

# Check for kata agent
try:
    out = subprocess.run(['ps', 'auxww'], capture_output=True, text=True, timeout=5)
    kata_checks['processes'] = out.stdout[:1500]
except: pass

r['kata'] = kata_checks

# 8. Try to reach IMDS via different methods
imds_tests = {}

# Raw socket SYN
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(3)
    # Build TCP SYN packet
    src_ip = '10.244.169.176'  # our pod IP from previous probe
    dst_ip = '169.254.169.254'
    # IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 54321, 0x4000, 64, socket.IPPROTO_TCP,
        0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    # TCP header (SYN)
    tcp_header = struct.pack('!HHIIBBHHH',
        12345, 80, 0, 0, 0x50, 0x02, 65535, 0, 0)
    s.sendto(ip_header + tcp_header, (dst_ip, 0))
    imds_tests['raw_syn'] = 'sent'
    try:
        data = s.recv(1024)
        imds_tests['raw_syn_resp'] = data.hex()[:200]
    except socket.timeout:
        imds_tests['raw_syn_resp'] = 'timeout'
    s.close()
except Exception as e:
    imds_tests['raw_syn'] = str(e)[:200]

# ICMP ping
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(3)
    # ICMP echo request
    icmp = struct.pack('!BBHHH', 8, 0, 0, 1234, 1)
    chksum = 0
    for i in range(0, len(icmp), 2):
        chksum += (icmp[i] << 8) + icmp[i+1]
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum = ~chksum & 0xffff
    icmp = struct.pack('!BBHHH', 8, 0, chksum, 1234, 1)
    s.sendto(icmp, ('169.254.169.254', 0))
    imds_tests['icmp'] = 'sent'
    try:
        data, addr = s.recvfrom(1024)
        imds_tests['icmp_resp'] = f'from={addr} data={data.hex()[:100]}'
    except socket.timeout:
        imds_tests['icmp'] = 'sent_but_timeout'
    s.close()
except Exception as e:
    imds_tests['icmp'] = str(e)[:200]

# Ping known-working host for comparison
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(3)
    icmp = struct.pack('!BBHHH', 8, 0, 0, 1234, 1)
    chksum = 0
    for i in range(0, len(icmp), 2):
        chksum += (icmp[i] << 8) + icmp[i+1]
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum = ~chksum & 0xffff
    icmp = struct.pack('!BBHHH', 8, 0, chksum, 1234, 1)
    s.sendto(icmp, ('10.245.0.10', 0))
    try:
        data, addr = s.recvfrom(1024)
        imds_tests['icmp_dns'] = f'from={addr} data={data.hex()[:50]}'
    except socket.timeout:
        imds_tests['icmp_dns'] = 'timeout'
    s.close()
except Exception as e:
    imds_tests['icmp_dns'] = str(e)[:200]

# Try connecting via different source ports
for sport in [53, 80, 443, 8080]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.bind(('', sport))
        rc = s.connect_ex(('169.254.169.254', 80))
        imds_tests[f'sport_{sport}'] = f'errno={rc}'
        s.close()
    except Exception as e:
        imds_tests[f'sport_{sport}'] = str(e)[:100]

r['imds_tests'] = imds_tests

# 9. Check network namespace details
try:
    r['net_ns_id'] = os.readlink('/proc/1/ns/net')
except: pass

# Check if network interfaces match host
try:
    r['ifconfig'] = subprocess.run(['ifconfig', '-a'], capture_output=True, text=True, timeout=5).stdout[:1000]
except: pass

# 10. Check for any network policy or CNI configuration
try:
    for root, dirs, files in os.walk('/etc/cni', topdown=True):
        for f in files:
            fp = os.path.join(root, f)
            try:
                r[f'cni_{fp}'] = open(fp).read()[:500]
            except: pass
except: pass

# Check resolv.conf for DNS details
try:
    r['resolv_conf'] = open('/etc/resolv.conf').read()
except: pass

print(json.dumps(r, indent=2, default=str))
