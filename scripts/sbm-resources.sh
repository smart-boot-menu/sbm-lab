#!/bin/bash
# Ask the shared per-user ledger for guest RAM before starting QEMU.
# Source this file, or run it:
#   sbm-resources.sh reserve WORKLOAD MEMORY_MIB CPUS REPO
#   sbm-resources.sh attach ID PID
#   sbm-resources.sh release ID
#   sbm-resources.sh run WORKLOAD MEMORY_MIB CPUS REPO TIMEOUT_SECS -- command...

sbm_lab_bin() {
    if [ -n "${SBM_LAB_BIN:-}" ] && [ -x "$SBM_LAB_BIN" ]; then
        printf '%s\n' "$SBM_LAB_BIN"
        return 0
    fi
    if command -v sbm-lab >/dev/null 2>&1; then
        command -v sbm-lab
        return 0
    fi
    local src here cand
    src=${BASH_SOURCE[0]:-$0}
    here=$(CDPATH= cd -- "$(dirname "$src")" && pwd)
    for cand in "$here/../target/release/sbm-lab" "$here/../target/debug/sbm-lab"; do
        if [ -x "$cand" ]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    echo "sbm-lab is not built; run cargo build --release -p sbm-lab in the sbm-lab repo" >&2
    return 1
}

sbm_reserve() {
    local workload=$1 memory=$2 cpus=$3 repo=$4
    local bin
    bin=$(sbm_lab_bin) || return 1
    "$bin" resources reserve --workload "$workload" --memory "$memory" --cpus "$cpus" --repo "$repo"
}

sbm_attach() {
    local id=$1 pid=$2
    local bin
    bin=$(sbm_lab_bin) || return 1
    "$bin" resources attach --id "$id" --pid "$pid"
}

sbm_release() {
    local id=$1
    local bin
    bin=$(sbm_lab_bin) || return 1
    if "$bin" resources release --id "$id"; then
        return 0
    fi
    # The owner shell may already have exited. --forget drops the record and
    # does not signal the process.
    "$bin" resources release --id "$id" --forget
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    cmd=${1:?usage: sbm-resources.sh reserve|attach|release|run}
    shift
    case "$cmd" in
        reserve) sbm_reserve "$@" ;;
        attach) sbm_attach "$@" ;;
        release) sbm_release "$@" ;;
        run)
            workload=$1
            memory=$2
            cpus=$3
            repo=$4
            timeout=$5
            shift 5
            [ "${1:-}" = "--" ] && shift
            bin=$(sbm_lab_bin)
            exec "$bin" resources run \
                --workload "$workload" \
                --memory "$memory" \
                --cpus "$cpus" \
                --repo "$repo" \
                --timeout "$timeout" \
                -- "$@"
            ;;
        *)
            echo "usage: sbm-resources.sh reserve|attach|release|run" >&2
            exit 2
            ;;
    esac
fi
