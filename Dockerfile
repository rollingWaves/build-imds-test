FROM python:3.11-slim
RUN apt-get update && apt-get install -y iproute2 dnsutils --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY probe.py /app/probe.py
EXPOSE 8080
CMD ["python3", "/app/probe.py"]
