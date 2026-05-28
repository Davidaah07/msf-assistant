#!/bin/bash
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   MSF-Assistant v3 — Instalador Kali     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
if [ "$EUID" -ne 0 ]; then
  echo "[!] Necesitas ejecutar con sudo."
  echo "    → sudo bash instalar.sh"
  exit 1
fi
echo "[*] Instalando Flask..."
pip3 install flask --break-system-packages -q
echo "[*] Comprobando herramientas..."
which netdiscover > /dev/null 2>&1 || apt-get install -y netdiscover -q
which nmap > /dev/null 2>&1 || apt-get install -y nmap -q
echo ""
echo "[OK] Todo listo. Iniciando en http://localhost:5000"
echo "     Pulsa Ctrl+C para detener."
echo ""
python3 app.py
