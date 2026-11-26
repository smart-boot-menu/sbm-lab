# Shared QEMU admission

Cooperating Smart Boot Menu checkouts share one ledger. A reservation is a file under the per-user runtime directory. Admission holds `admit.lock` with `flock` for the check and the write, so two agents cannot reserve the same remaining memory. Nothing in this path is a resident daemon.

```bash
sbm-lab resources status
sbm-lab resources doctor
sbm-lab resources reserve --workload efi --memory 1024 --cpus 1 --repo "$PWD"
sbm-lab resources attach --id ID --pid PID
sbm-lab resources release --id ID
sbm-lab resources run --workload linux --memory 2048 --cpus 2 --timeout 75 -- qemu-system-aarch64 ...
```

Other repositories can call `scripts/sbm-resources.sh` the same way (`reserve`, `attach`, `release`, `run`).

On macOS the directory is `~/Library/Application Support/sbm-lab`. Elsewhere it is `$XDG_STATE_HOME/sbm-lab`, or `~/.local/state/sbm-lab`. `SBM_LAB_RUNTIME` overrides it. `SBM_VM_MAX_CONCURRENT` defaults to 2. `SBM_VM_MAX_HEAVY` defaults to 1.

`reserve` prints an id and records an owner pid. Shell helpers pass that shell's `$$` with `--owner` and `SBM_OWNER_PID`. `hold=$(sbm_reserve ...)` runs in a subshell that exits before `attach`, and `$$` is still the shell that sourced the helper. A helper started as its own process records its parent, because that process exits as soon as `reserve` returns. `attach` stores the QEMU pid and the `ps -o lstart=` value for that pid. `release` removes the record. It does not send a signal. `--forget` removes the record while that process is still running, and still does not send a signal. The helper does not use `--forget` when release says the QEMU pid is still running or that a live owner holds the record. `run` and `sbm-lab run` kill only the pid they started, and only when that pid still has the recorded start time. They do that when the run returns, times out, or is dropped. SIGINT and SIGTERM kill that same pid and then re-raise. On Linux the child is also marked `PR_SET_PDEATHSIG` so it exits if this process is killed without running its Drop.

A reservation is deleted on the next admission when the owner and the QEMU pid are both dead, or when a recorded start time no longer matches the live pid. A dead owner with a live QEMU pid that still has the recorded start time is kept and reported as orphaned. That process is not killed.

## Budget

`hw.memsize` on this Mac is 17179869184 bytes (16384 MiB). While `qemu-system-aarch64 -name sbm-builder -m 8192 -smp 4` was running on 2026-11-26, `kern.memorystatus_vm_pressure_level` was 2 and `vm.swapusage` was 1968 MiB used of 3072 MiB. RSS at one sample was about 990 MiB. `sbm-core/scripts/host-resources.sh` records the useful measurement: the guest was idle near 533 MiB and the process still charged about 15 GB of physical footprint. RSS is not the admission number. Each reserved MiB counts as 2 MiB of host RAM.

The host floor is 6144 MiB when physical RAM is at least 15360 MiB, otherwise half of physical RAM. 15360 MiB is the 16 GiB class: `hw.memsize` on this Mac is 16384 MiB, and Linux `MemTotal` for that class of machine is lower. Warning pressure adds 1024 MiB. Swap used past half of the swap file adds 2048 MiB. Critical pressure refuses every new reservation. Unknown pressure does not. Guest budget is `(physical - floor) / 2`.

On Linux the physical number is `MemTotal`. A cgroup `memory.max`, or v1 `memory.limit_in_bytes`, caps it when the limit is smaller. `max` and other unlimited sentinels do not. Pressure is `MemAvailable / MemTotal`: under 10 percent is critical, under 20 percent is warning. Meminfo with no `MemAvailable` line is unknown pressure.

| Host state | Guest budget |
| --- | --- |
| 16384 MiB, normal pressure, little swap | 5120 MiB |
| 15999 MiB, normal pressure, little swap | 4927 MiB |
| 16384 MiB, warning pressure, swap 1968/3072 | 3584 MiB |
| critical pressure | 0 |

An existing QEMU process counts even when it has no reservation. Only a command whose executable basename starts with `qemu-system-` counts, so `sbm-lab resources run -- qemu-system-...` does not count itself. `ps -axww` is used so the command line is not truncated. `-m 4G,slots=2` and `-m size=4G` are 4096 MiB. `-smp cores=4` is 4 vCPU. An 8192 MiB guest is already over the 5120 MiB budget, so a new reservation is refused. The ledger does not stop that process.

## Workloads

The sizes are the ones these guests already used, capped so a caller cannot raise them by passing a larger `--memory`.

| Workload | Default | vCPU | Maximum | Heavy |
| --- | --- | --- | --- | --- |
| `efi` | 1024 MiB | 1 | 1024 MiB | no |
| `linux` | 2048 MiB | 2 | 2048 MiB | no |
| `graphical` | 4096 MiB | 2 | 4096 MiB | yes |
| `build` | 4096 MiB | 4 | 6144 MiB | yes |
| `ram` | 6144 MiB | 2 | 8192 MiB | yes |

`linux-dev` completed at 4096 MiB and 4 vCPU. Menu and Secure Boot runs completed at 1024 MiB. Heavy workloads admit one at a time even when the memory math would allow two. `ram` is the explicit larger profile. It still has to fit the budget, so on this 16 GiB Mac it does not.

`sbm-lab run` maps a build-VM profile to `build`, a virtio-gpu or `--graphical` profile to `graphical`, and every other profile to `efi`. A profile that asks for 2048 MiB of EFI RAM is launched at 1024 MiB and 1 vCPU.

## Launchers

These started QEMU on their own and did not see `SBM_LAB_MAX_MEMORY_MIB` or `var/runs/.slot-N`. They now reserve first:

| Launcher | Workload |
| --- | --- |
| `sbm-lab run` / `test` | from the profile |
| `sbm-uefi/crates/xtask/src/qemu.rs` | `efi`, 1024 MiB, 1 vCPU |
| `sbm-core/scripts/boot-smoke.sh` | `graphical`, the `--memory` argument, 2 vCPU |
| `sbm-core/scripts/start-builder.sh` | `build`, default 4096 MiB |
| `sbm-catalog/tools/boot-installer.sh` | `linux`, 2048 MiB, 2 vCPU |
| `sbm-as/scripts/uboot-efi-poc.sh` | `efi`, 1024 MiB, 1 vCPU |

`install` does not launch QEMU. A command typed at a shell still bypasses the reservation. `resources status` lists it, charges its `-m` size, and leaves it running.
