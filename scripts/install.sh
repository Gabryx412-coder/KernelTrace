#!/usr/bin/env bash
#
# Script di installazione di KernelTrace su un host Linux. Compila (o
# scarica un binario release precompilato, se disponibile per
# l'architettura corrente) e installa i binari, la configurazione di
# esempio, e l'unit systemd.

set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
CONFIG_DIR="/etc/kerneltrace"
LOG_DIR="/var/log/kerneltrace"
SERVICE_USER="kerneltrace"

REPO_URL="https://github.com/Gabryx412-coder/KernelTrace"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Questo script richiede privilegi di root (necessari per installare" >&2
    echo "il servizio systemd e configurare le capability). Esegui con sudo." >&2
    exit 1
fi

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
    *)
        echo "Architettura non supportata: ${ARCH}" >&2
        echo "Compila da sorgente seguendo docs/development/building.md" >&2
        exit 1
        ;;
esac

echo "==> Creazione utente di sistema '${SERVICE_USER}' (se non esistente)..."
if ! id -u "${SERVICE_USER}" &> /dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "==> Verifica presenza di un binario compilato locale..."
if [[ -f "target/release/kerneltrace-agent" && -f "target/release/kerneltrace-cli" ]]; then
    echo "Trovati binari compilati localmente in target/release/, uso quelli."
    cp target/release/kerneltrace-agent "${INSTALL_PREFIX}/"
    cp target/release/kerneltrace-cli "${INSTALL_PREFIX}/"
else
    echo "Nessun binario locale trovato. Scarico l'ultima release per ${TARGET}..."
    LATEST_URL="${REPO_URL}/releases/latest/download/kerneltrace-${TARGET}.tar.gz"
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    if ! curl -fsSL "${LATEST_URL}" -o "${TMP_DIR}/kerneltrace.tar.gz"; then
        echo "Download della release fallito. Compila da sorgente:" >&2
        echo "  vedi docs/development/building.md" >&2
        exit 1
    fi

    tar -xzf "${TMP_DIR}/kerneltrace.tar.gz" -C "${TMP_DIR}"
    cp "${TMP_DIR}/kerneltrace-agent" "${INSTALL_PREFIX}/"
    cp "${TMP_DIR}/kerneltrace-cli" "${INSTALL_PREFIX}/"
fi

chmod +x "${INSTALL_PREFIX}/kerneltrace-agent" "${INSTALL_PREFIX}/kerneltrace-cli"

echo "==> Creazione directory di configurazione e log..."
mkdir -p "${CONFIG_DIR}" "${LOG_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"

if [[ ! -f "${CONFIG_DIR}/kerneltrace.yaml" ]]; then
    echo "==> Copia della configurazione di esempio..."
    cp config/kerneltrace.example.yaml "${CONFIG_DIR}/kerneltrace.yaml"
else
    echo "==> Configurazione esistente trovata in ${CONFIG_DIR}/kerneltrace.yaml, non sovrascritta."
fi

echo "==> Installazione dell'unit systemd..."
cp deployment/systemd/kerneltrace.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "==> Installazione completata."
echo "Prossimi passi:"
echo "  1. Modifica ${CONFIG_DIR}/kerneltrace.yaml secondo le tue necessità"
echo "  2. sudo systemctl enable --now kerneltrace"
echo "  3. kerneltrace-cli status"