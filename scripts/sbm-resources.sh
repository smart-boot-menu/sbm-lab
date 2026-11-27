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

# `hold=$(sbm_reserve ...)` runs in a subshell. `$$` stays the sourcing shell.
# A direct `sbm-resources.sh reserve` process exits immediately, so its parent
# is the owner that will attach later.
sbm_owner_pid() {
    if [ -n "${SBM_OWNER_PID:-}" ]; then
        printf '%s\n' "$SBM_OWNER_PID"
        return 0
    fi
    if [ "${BASH_SOURCE[0]}" = "$0" ]; then
        printf '%s\n' "$PPID"
    else
        printf '%s\n' "$$"
    fi
}

sbm_reserve() {
    local workload=$1 memory=$2 cpus=$3 repo=$4
    local bin owner
    local extra=()
    bin=$(sbm_lab_bin) || return 1
    owner=$(sbm_owner_pid)
    if [ "${SBM_DETACHED:-0}" = "1" ]; then
        extra+=(--detached)
    fi
    SBM_OWNER_PID="$owner" "$bin" resources reserve \
        --workload "$workload" --memory "$memory" --cpus "$cpus" --repo "$repo" \
        --owner "$owner" "${extra[@]}"
}

sbm_attach() {
    local id=$1 pid=$2
    local bin owner
    bin=$(sbm_lab_bin) || return 1
    owner=$(sbm_owner_pid)
    SBM_OWNER_PID="$owner" "$bin" resources attach --id "$id" --pid "$pid"
}

sbm_release() {
    local id=$1
    local bin owner err
    bin=$(sbm_lab_bin) || return 1
    owner=$(sbm_owner_pid)
    if err=$(SBM_OWNER_PID="$owner" "$bin" resources release --id "$id" 2>&1); then
        return 0
    fi
    printf '%s\n' "$err" >&2
    case "$err" in
        *"does not kill"*|*"owned by"*)
            return 1
            ;;
    esac
    # The record can outlive a shell that exited before attach. --forget still
    # does not signal a process.
    SBM_OWNER_PID="$owner" "$bin" resources release --id "$id" --forget
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
