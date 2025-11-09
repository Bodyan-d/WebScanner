# ./sqlmap/Dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*


RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
WORKDIR /opt/sqlmap


RUN ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && chmod +x /opt/sqlmap/sqlmap.py

ENTRYPOINT ["python3", "/opt/sqlmap/sqlmap.py"]
CMD ["--help"]
