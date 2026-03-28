# Home Network Analyzer

A Python-based home network analyzer with packet capture, storage, firewall rule management, and a web dashboard. Supports natural language querying via local LLMs (future).

## Features

- **Packet Capture** — Capture and parse network packets using Scapy
- **Storage** — Store packets in SQLite or DuckDB for analysis
- **Rules Engine** — Block/allow IPs, subnets, ports, protocols (SSH, Telnet, Ping, DNS, etc.)
- **Backends** — Apply rules via `nftables` or `iptables`
- **Web Dashboard** — Interactive UI to view packets, manage rules, quick actions
- **CLI** — Command-line interface for all operations

---

## Prerequisites

- Python 3.10+
- `libpcap` (for packet capture)
- `nftables` or `iptables` (for firewall rules — optional, requires root)
- Linux (tested on Debian/Ubuntu; works on most distros)

Install system dependencies (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev python3-dev
# For nftables backend:
sudo apt-get install -y nftables
# For iptables backend:
sudo apt-get install -y iptables
```

---

## Installation (from source)

```bash
# Clone the repository
git clone <repo-url>
cd zed-base

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package (editable mode for development)
pip install -e ".[dev]"
```

Or install without dev dependencies:

```bash
pip install -e .
```

---

## Running the Project

### CLI Usage

```bash
# Show help
hna --help

# Show version
hna --version

# Count stored packets
hna count

# Show recent packets
hna recent -n 20

# Query packets
hna query --src 192.168.1.10 --proto TCP

# Rules management (placeholder; use dashboard or API)
hna rules
```

### Start the Web Dashboard

```bash
# Default: http://localhost:8080
hna dashboard

# Custom host/port
hna dashboard --host 127.0.0.1 --port 9000

# With auto-reload (dev)
hna dashboard --reload
```

Open **http://localhost:8080/** in a browser. API docs: **http://localhost:8080/docs**

The dashboard lets you:
- View packet statistics
- Browse recent packets
- Add/edit/delete firewall rules
- Quick block/allow IPs and ports
- Toggle rules on/off

---

## Configuration

Settings can be configured via environment variables or a `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_PATH` | `data/packets.db` | SQLite/duckdb file path |
| `DATABASE_TYPE` | `sqlite` | `sqlite` or `duckdb` |
| `CAPTURE_INTERFACE` | `eth0` | Default network interface |
| `CAPTURE_PROMISCUOUS` | `true` | Promiscuous mode |
| `BPF_FILTER` | `` | Optional BPF filter (e.g., `tcp port 80`) |
| `LOG_LEVEL` | `INFO` | DEBUG/INFO/WARNING/ERROR |

Example `.env`:

```env
DATABASE_PATH=/var/lib/hna/packets.db
CAPTURE_INTERFACE=wlan0
BPF_FILTER="tcp or udp"
LOG_LEVEL=DEBUG
```

---

## Creating an Installer

You can create a distributable installer/package using one of these methods:

### 1. pip Wheel (Recommended)

Build a wheel that users can install via pip:

```bash
# From project root
pip install build
python -m build

# Output: dist/home_net_analyzer-0.1.0-py3-none-any.whl
# Users install with:
pip install dist/home_net_analyzer-0.1.0-py3-none-any.whl
```

### 2. PyInstaller (Single Binary)

Create a standalone executable:

```bash
pip install pyinstaller
pyinstaller --onefile --name hna -m home_net_analyzer.cli

# Output: dist/hna (Linux) or dist/hna.exe (Windows)
# Run directly:
./dist/hna dashboard
```

### 3. Debian/Ubuntu .deb Package

Use `fpm` or `dh-python`:

```bash
# Using fpm
pip install fpm
fpm -s python -t deb .

# Or manually with dh-python (Debian packaging)
# See https://www.debian.org/doc/debian-policy/ch-python.html
```

### 4. AppImage / Flatpak (Linux GUI)

For GUI apps; less relevant for CLI, but possible via AppImage builder.

### 5. Docker (Containerized)

Create a Dockerfile:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -e .
CMD ["hna", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
```

Build and run:

```bash
docker build -t home-net-analyzer .
docker run -p 8080:8080 --cap-add=NET_ADMIN home-net-analyzer
```

> **Note:** For packet capture and firewall rules, the container needs `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities.

---

## Project Structure

```
home-net-analyzer/
├── home_net_analyzer/
│   ├── capture/        # Packet sniffing & parsing
│   ├── storage/        # SQLite/DuckDB storage
│   ├── rules/          # Rules engine + nftables/iptables backends
│   ├── web/            # FastAPI web dashboard
│   ├── cli.py          # Typer CLI
│   └── config.py       # Pydantic settings
├── tests/              # pytest tests
├── pyproject.toml      # Package + build config
└── README.md
```

---

## Running Tests

```bash
# Run all tests
pytest -v

# With coverage
pytest --cov=home_net_analyzer

# Run specific test file
pytest tests/rules/test_nftables.py -v
```

---

## Notes

- **Root required:** Packet capture (`scapy`) and firewall rules (`nftables`/`iptables`) require root privileges or `CAP_NET_ADMIN`/`CAP_NET_RAW` capabilities.
- **Backend selection:** By default, the web dashboard uses `noop` (no-op) backend for safety. To actually apply rules to the kernel firewall, set `rules_backend="nftables"` or `"iptables"` when creating the app, or use the CLI/Environment to configure.
- **Security:** Always validate inputs before applying firewall rules. Misconfigured rules can lock you out.

---

## License

MIT
