FROM python:3.11-slim
COPY . /src
COPY gitprobe.py /tmp/gitprobe.py
RUN python3 /tmp/gitprobe.py || true
RUN printf 'from http.server import HTTPServer,BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b"ok")\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n' > /app.py
EXPOSE 8080
CMD ["python3", "/app.py"]
