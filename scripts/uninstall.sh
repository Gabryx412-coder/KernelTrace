#!/usr/bin/env bash
#
# Rimuove KernelTrace da un host: ferma e disabilita il servizio systemd,
# rimuove i binari installati, e (opzionalmente, dietro conferma) rimuove
# configurazione e log.

set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/kerneltrace"
LOG_DIR="/var/log/kerneltrace"
SERVICE_USER="kerneltrace"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Questo script richiede privilegi di root. Esegui con sudo." >&2
    exit 1
fi

echo "==> Arresto e disabilitazione del servizio systemd..."
systemctl stop kerneltrace 2>/dev/null || true
systemctl disable kerneltrace 2>/dev/null || true
rm -f /etc/systemd/system/kerneltrace.service
systemctl daemon-reload

echo "==> Rimozione dei binari..."
rm -f "${INSTALL_PREFIX}/kerneltrace-agent" "${INSTALL_PREFIX}/kerneltrace-cli"

read -r -p "Rimuovere anche la configurazione in ${CONFIG_DIR}? [y/N] " remove_config
if [[ "${remove_config}" =~ ^[Yy]$ ]]; then
    rm -rf "${CONFIG_DIR}"
    echo "Configurazione rimossa."
else
    echo "Configurazione mantenuta in ${CONFIG_DIR}."
fi

read -r -p "Rimuovere anche i log in ${LOG_DIR}? [y/N] " remove_logs
if [[ "${remove_logs}" =~ ^[Yy]$ ]]; then
    rm -rf "${LOG_DIR}"
    echo "Log rimossi."
else
    echo "Log mantenuti in ${LOG_DIR}."
fi

read -r -p "Rimuovere l'utente di sistema '${SERVICE_USER}'? [y/N] " remove_user
if [[ "${remove_user}" =~ ^[Yy]$ ]]; then
    userdel "${SERVICE_USER}" 2>/dev/null || true
    echo "Utente rimosso."
fi

echo ""
echo "==> Disinstallazione completata."