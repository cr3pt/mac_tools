FROM python:3.11-slim
RUN apt-get update && apt-get install -y yara libyara-dev gcc git curl qemu-utils tshark tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python","-m","mac_tools.cli.deploy"]
