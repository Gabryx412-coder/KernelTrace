#!/usr/bin/env bash
#
# Genera vmlinux.h per il kernel corrente, necessario per la tecnica
# CO-RE (Compile Once - Run Everywhere) usata dai programmi eBPF di
# KernelTrace. Il file generato contiene i layout delle struct del
# kernel in esecuzione, permettendo ad aya-ebpf di generare accessi ai
# campi rilocabili a runtime dal verifier BPF.

set -euo pipefail

OUTPUT_PATH="${1:-vmlinux.h}"
BTF_PATH="/sys/kernel/btf/vmlinux"

if [[ ! -f "${BTF_PATH}" ]]; then
    echo "ERROR: ${BTF_PATH} not found." >&2
    echo "Il kernel corrente non espone informazioni BTF, requisito per CO-RE." >&2
    echo "Verifica che il kernel sia stato compilato con CONFIG_DEBUG_INFO_BTF=y" >&2
    echo "(la maggior parte delle distribuzioni moderne lo abilita di default" >&2
    echo "su kernel >= 5.8)." >&2
    exit 1
fi

if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool non trovato nel PATH." >&2
    echo "Installa il pacchetto linux-tools-\$(uname -r) sulla tua distribuzione," >&2
    echo "ad esempio: sudo apt-get install linux-tools-\$(uname -r)" >&2
    exit 1
fi

echo "Generazione di ${OUTPUT_PATH} da ${BTF_PATH} (kernel $(uname -r))..."
bpftool btf dump file "${BTF_PATH}" format c > "${OUTPUT_PATH}"

echo "vmlinux.h generato con successo: ${OUTPUT_PATH} ($(wc -l < "${OUTPUT_PATH}") righe)"