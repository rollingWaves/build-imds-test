FROM python:3.11-slim
COPY probe.py /tmp/probe.py
RUN python3 /tmp/probe.py || true
RUN printf 'from http.server import HTTPServer,BaseHTTPRequestHandler\nimport json\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers()\n  self.wfile.write(json.dumps({"ok":1}).encode())\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n' > /app.py
EXPOSE 8080
CMD ["python3", "/app.py"]
