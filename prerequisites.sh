#!/bin/bash
#
# Prerequisites Script for VLAN Emulator (Home Network Analyzer)
# Installs system-level dependencies required to run the project.
#
# Usage:
#   chmod +x prerequisites.sh
#   sudo ./prerequisites.sh
#
# This script is designed for Debian/Ubuntu. Adapt commands for other distros.

set -e

echo "=========================================="
echo "VLAN Emulator - Prerequisites Installer"
echo "=========================================="
echo

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
else
    echo "ERROR: Unsupported package manager. Please install dependencies manually."
    exit 1
fi

echo "[INFO] Detected package manager: $PKG_MANAGER"
echo

# Core system dependencies
echo ">>> Installing core system dependencies..."
case $PKG_MANAGER in
    apt)
        apt-get update
        apt-get install -y \
            python3 \
            python3-pip \
            python3-venv \
            libpcap-dev \
            libffi-dev \
            build-essential
        ;;
    yum|dnf)
        $PKG_MANAGER install -y \
            python3 \
            python3-pip \
            libpcap-devel \
            libffi-devel \
            gcc \
            make
        ;;
    pacman)
        pacman -Sy --noconfirm \
            python \
            python-pip \
            libpcap \
            libffi \
            base-devel
        ;;
esac
echo "[OK] Core dependencies installed."
echo

# Optional: Firewall backends (requires root, for actual rule application)
echo ">>> Installing optional firewall backends (for rules engine)..."
echo "    Note: These are optional. The UI defaults to 'noop' backend for safety."
echo "    Install only if you want to actually apply firewall rules to the kernel."

if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install -y nftables iptables || true
elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
    $PKG_MANAGER install -y nftables iptables || true
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy --noconfirm nftables iptables || true
fi
echo "[OK] Firewall backends checked (may already exist)."
echo

# Optional: GUI/desktop dependencies for Flet
echo ">>> Installing optional desktop/GUI libraries (for Flet desktop app)..."
echo "    Note: Flet uses Flutter under the hood. On Linux, GTK/WebKit may be needed."

if [ "$PKG_MANAGER" = "apt" ]; then
    apt-get install -y \
        libgtk-3-0 \
        libwebkit2gtk-4.0-37 \
        libnotify4 \
        libnss3 \
        libxss1 \
        libxtst6 \
        xdg-utils || true
elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
    $PKG_MANAGER install -y \
        gtk3 \
        webkit2gtk3 \
        libnotify \
        nss \
        libXScrnSaver \
        xdg-utils || true
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy --noconfirm \
        gtk3 \
        webkit2gtk \
        libnotify \
        nss \
        xdg-utils || true
fi
echo "[OK] Desktop libraries checked."
echo

# Python virtual environment recommendation
echo ">>> Checking Python version..."
PYTHON_VER=$(python3 --version 2>/dev/null || echo "not found")
echo "    $PYTHON_VER"
echo

echo "=========================================="
echo "Prerequisites installation complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "  1. Create a virtual environment:"
echo "       python3 -m venv venv"
echo "       source venv/bin/activate"
echo
echo "  2. Install Python dependencies:"
echo "       pip install -e ."
echo
echo "  3. (Optional) Install dev dependencies:"
echo "       pip install -e '.[dev]'"
echo
echo "  4. Run the CLI:"
echo "       hna --help"
echo
echo "  5. Run the desktop GUI (once implemented):"
echo "       hna desktop"
echo
echo "Note: For packet capture and firewall rules, run as root or"
echo "with CAP_NET_ADMIN / CAP_NET_RAW capabilities."
echo
