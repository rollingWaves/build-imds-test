import json, os, socket, subprocess, struct, time

r = {}

# 1. Full link-local scan (169.254.0.0/16)
# Test a range of common link-local addresses
link_local_results = {}
for octet3 in [0, 1, 2, 3, 4, 5, 10, 20, 42, 80, 100, 128, 169, 170, 200, 254, 255]:
    for octet4 in [1, 2, 3, 53, 80, 254]:
        ip = f'169.254.{octet3}.{octet4}'
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            rc = s.connect_ex((ip, 80))
            if rc == 0:
                link_local_results[f'{ip}:80'] = 'OPEN'
            elif rc != 111 and rc != 11:  # Not ECONNREFUSED or EAGAIN
                link_local_results[f'{ip}:80'] = f'errno={rc}'
            s.close()
        except Exception as e:
            if 'timed out' not in str(e) and 'EAGAIN' not in str(e):
                link_local_results[f'{ip}:80'] = str(e)[:60]

# Specific IMDS-like targets
for ip in ['169.254.169.254', '169.254.0.1', '169.254.1.1', '169.254.42.42',
           '169.254.170.2', '169.254.169.123', '169.254.169.253', '169.254.169.1']:
    for port in [80, 443, 8080, 8443, 1338, 8775]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            rc = s.connect_ex((ip, port))
            status = 'OPEN' if rc == 0 else f'errno={rc}'
            link_local_results[f'{ip}:{port}'] = status
            s.close()
            if rc == 0:
                # Try HTTP GET
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(3)
                    s2.connect((ip, port))
                    s2.send(f'GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n'.encode())
                    resp = s2.recv(4096)
                    link_local_results[f'{ip}:{port}_resp'] = resp.decode('utf-8', errors='replace')[:500]
                    s2.close()
                except Exception as e:
                    link_local_results[f'{ip}:{port}_resp'] = str(e)[:100]
        except Exception as e:
            link_local_results[f'{ip}:{port}'] = str(e)[:60]
r['link_local'] = link_local_results

# 2. Host access checks
host_access = {}

# Check /proc/1/cgroup - are we in a container?
try:
    host_access['cgroup'] = open('/proc/1/cgroup').read()[:500]
except Exception as e:
    host_access['cgroup'] = str(e)[:100]

# Check mount namespace
try:
    host_access['mountinfo'] = open('/proc/self/mountinfo').read()[:2000]
except Exception as e:
    host_access['mountinfo'] = str(e)[:100]

# Check for host filesystem indicators
for p in ['/host', '/rootfs', '/proc/1/root', '/.dockerenv', '/run/.containerenv',
          '/var/run/secrets', '/var/run/docker.sock', '/run/containerd/containerd.sock']:
    try:
        if os.path.exists(p):
            if os.path.isdir(p):
                host_access[f'exists_{p}'] = os.listdir(p)[:20]
            else:
                host_access[f'exists_{p}'] = True
        else:
            host_access[f'exists_{p}'] = False
    except Exception as e:
        host_access[f'exists_{p}'] = str(e)[:60]

# Check PID namespace - can we see host processes?
try:
    pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
    host_access['pid_count'] = len(pids)
    host_access['max_pid'] = max(pids) if pids else 0
    host_access['pids'] = sorted(pids)[:30]
    # Read some process names
    for pid in sorted(pids)[:15]:
        try:
            comm = open(f'/proc/{pid}/comm').read().strip()
            cmdline = open(f'/proc/{pid}/cmdline').read().replace('\x00', ' ')[:200]
            host_access[f'proc_{pid}'] = f'{comm}: {cmdline}'
        except:
            pass
except Exception as e:
    host_access['pids'] = str(e)[:100]

# Check network namespace
try:
    host_access['net_ns'] = os.readlink('/proc/self/ns/net')
except: pass
try:
    host_access['pid_ns'] = os.readlink('/proc/self/ns/pid')
except: pass
try:
    host_access['mnt_ns'] = os.readlink('/proc/self/ns/mnt')
except: pass
try:
    host_access['user_ns'] = os.readlink('/proc/self/ns/user')
except: pass

# Check hostname (might reveal node name)
try:
    host_access['hostname'] = socket.gethostname()
except: pass

# Check kernel version (real vs gVisor)
try:
    host_access['uname'] = os.uname()._asdict()
except: pass

# Can we access host network interfaces?
try:
    host_access['interfaces'] = open('/proc/net/dev').read()[:500]
except: pass

r['host_access'] = host_access

# 3. Network filtering mechanism - iptables vs network policy vs something else?
net_filter = {}

# Check iptables
for cmd in ['iptables -L -n', 'iptables -t nat -L -n', 'iptables -t mangle -L -n',
            'ip6tables -L -n', 'nft list ruleset']:
    try:
        out = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
        net_filter[f'cmd_{cmd}'] = {'stdout': out.stdout[:1000], 'stderr': out.stderr[:200], 'rc': out.returncode}
    except Exception as e:
        net_filter[f'cmd_{cmd}'] = str(e)[:100]

# Check for Cilium/Calico/other CNI indicators
for p in ['/sys/fs/bpf', '/run/cilium', '/etc/cni', '/opt/cni', '/var/run/calico']:
    try:
        if os.path.exists(p):
            if os.path.isdir(p):
                net_filter[f'exists_{p}'] = os.listdir(p)[:20]
            else:
                net_filter[f'exists_{p}'] = True
        else:
            net_filter[f'exists_{p}'] = False
    except Exception as e:
        net_filter[f'exists_{p}'] = str(e)[:60]

# Check routing table
try:
    out = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
    net_filter['ip_route'] = out.stdout[:500] if out.returncode == 0 else out.stderr[:200]
except Exception as e:
    net_filter['ip_route'] = str(e)[:100]

# Check ip addr
try:
    out = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
    net_filter['ip_addr'] = out.stdout[:1000] if out.returncode == 0 else out.stderr[:200]
except Exception as e:
    net_filter['ip_addr'] = str(e)[:100]

# Check ip rule (policy routing)
try:
    out = subprocess.run(['ip', 'rule'], capture_output=True, text=True, timeout=5)
    net_filter['ip_rule'] = out.stdout[:500] if out.returncode == 0 else out.stderr[:200]
except Exception as e:
    net_filter['ip_rule'] = str(e)[:100]

# Check conntrack
try:
    out = subprocess.run(['cat', '/proc/net/nf_conntrack'], capture_output=True, text=True, timeout=5)
    net_filter['conntrack'] = out.stdout[:1000]
except: pass

# Check /proc/net for filtering clues
for netfile in ['tcp', 'tcp6', 'udp', 'udp6', 'raw', 'raw6']:
    try:
        data = open(f'/proc/net/{netfile}').read()[:500]
        net_filter[f'proc_net_{netfile}'] = data
    except: pass

# Specific errno analysis - connect to IMDS with detailed error
try:
    import errno as errno_module
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(('169.254.169.254', 80))
        net_filter['imds_connect'] = 'SUCCESS'
    except OSError as e:
        net_filter['imds_connect'] = f'errno={e.errno} ({errno_module.errorcode.get(e.errno, "unknown")}): {str(e)}'
    s.close()
except Exception as e:
    net_filter['imds_connect'] = str(e)[:200]

# Try UDP to IMDS
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(b'test', ('169.254.169.254', 80))
    try:
        data = s.recvfrom(1024)
        net_filter['imds_udp'] = str(data)[:200]
    except Exception as e:
        net_filter['imds_udp'] = f'send_ok_recv_err: {e}'
    s.close()
except Exception as e:
    net_filter['imds_udp'] = str(e)[:200]

# Check for BPF programs (Cilium uses eBPF)
try:
    # /proc/net/bpf_jit_enable
    net_filter['bpf_jit'] = open('/proc/sys/net/core/bpf_jit_enable').read().strip()
except: pass

# Check capabilities (can we run iptables?)
try:
    net_filter['capeff'] = open('/proc/self/status').read().split('CapEff:')[1].split('\n')[0].strip()
except: pass

# Check seccomp status
try:
    status = open('/proc/self/status').read()
    for line in status.split('\n'):
        if 'Seccomp' in line:
            net_filter[line.split(':')[0].strip()] = line.split(':')[1].strip()
except: pass

# strace-like: try raw connect and check exact syscall behavior
try:
    import ctypes
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    fd = s.fileno()
    # Build sockaddr_in for 169.254.169.254:80
    addr = struct.pack('!HH4s8s', socket.AF_INET, 80, socket.inet_aton('169.254.169.254'), b'\x00'*8)
    ret = libc.connect(fd, addr, len(addr))
    err = ctypes.get_errno()
    net_filter['raw_connect_ret'] = ret
    net_filter['raw_connect_errno'] = err
    # Wait a bit and check with poll
    import select
    time.sleep(0.5)
    r_list, w_list, x_list = select.select([], [s], [s], 3)
    if w_list:
        err2 = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        net_filter['raw_connect_so_error'] = err2
    elif x_list:
        net_filter['raw_connect_exception'] = True
    else:
        net_filter['raw_connect_timeout'] = True
    s.close()
except Exception as e:
    net_filter['raw_connect'] = str(e)[:200]

r['net_filter'] = net_filter

# 4. Additional: check ARP table for gateway
try:
    r['arp'] = open('/proc/net/arp').read()[:500]
except: pass

# 5. Check DNS resolution for interesting names
dns_results = {}
for name in ['metadata.google.internal', 'metadata', 'instance-data',
             'kubernetes.default', 'kubernetes.default.svc']:
    try:
        ips = socket.getaddrinfo(name, None)
        dns_results[name] = str(ips[0][4][0])
    except Exception as e:
        dns_results[name] = str(e)[:60]
r['dns'] = dns_results

print(json.dumps(r, indent=2, default=str))
