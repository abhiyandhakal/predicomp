# VM Lab (QEMU/KVM + Arch) for `predicomp`

Use this VM lab when you want reproducible measurements for:

- eBPF probes (`proc_create`, `page_fault`, `swap_probe`, `proc_lifecycle`)
- `mem-arena` experiments
- DAMON-backed `interactive_burst --arena-autoloops`

This avoids host-machine noise and keeps kernel/userspace dependencies controlled.

## Approach

- QEMU + KVM (repo-owned scripts, no `virt-install` required)
- Arch Linux guest
- pinned guest kernel package version (document after first install)
- 9p/virtio shared mount for the host repo
- user-mode NAT with SSH forward (`127.0.0.1:2222` by default)

## Host Prerequisites

Run:

```bash
./vm/scripts/check_host.sh
```

Expected host tools/features:

- `qemu-system-x86_64`
- `qemu-img`
- `/dev/kvm`

## Files

- `vm/config/default.env`: VM settings (RAM, vCPU, disk, repo path, SSH port)
- `vm/scripts/create_disk.sh`: create qcow2 disk image
- `vm/scripts/run_arch_install_iso.sh`: boot Arch installer ISO
- `vm/scripts/run_vm.sh`: boot the installed VM with 9p repo share
- `vm/scripts/ssh_into_vm.sh`: convenience SSH wrapper
- `vm/guest/setup_arch_guest.sh`: install guest packages and enable SSH
- `vm/guest/mount_repo_9p.sh`: mount shared repo in guest
- `vm/guest/validate_predicomp_env.sh`: validate BTF/DAMON/eBPF prerequisites in guest

## Configure the VM

Edit `vm/config/default.env` and set at least:

- `VM_ISO_PATH=/absolute/path/to/archlinux-<version>-x86_64.iso`
- `VM_REPO_HOST_PATH=/home/abhiyan/research/predicomp` (or your actual repo path)

Optional tuning:

- `VM_RAM_MB` (default `8192`)
- `VM_VCPUS` (default `4`)
- `VM_SSH_FWD_PORT` (default `2222`)
- `VM_GUEST_USER` (default `abhiyan`)

## Create Disk

```bash
./vm/scripts/create_disk.sh
```

This creates `vm/images/predicomp-arch-lab.qcow2` by default.

## Boot Arch Installer (initial install)

Headless (serial console):

```bash
./vm/scripts/run_arch_install_iso.sh
```

If you prefer a graphical installer session:

```bash
./vm/scripts/run_arch_install_iso.sh --vnc
```

### Guest install checklist (manual first pass)

Inside the Arch installer VM:

1. Partition and format the virtio disk (`/dev/vda`)
2. Install base system + kernel (`linux`, `linux-headers`, `linux-firmware`)
3. Install `openssh`, `sudo`, `base-devel` (or use the helper later)
4. Create a user (optional) and enable `sshd`
5. Reboot and boot with `./vm/scripts/run_vm.sh`

This repo intentionally keeps the first pass manual/semi-guided so you can confirm disk layout and kernel choice.

## Boot Installed VM

```bash
./vm/scripts/run_vm.sh
```

It prints an SSH hint, e.g.:

```bash
ssh -p 2222 abhiyan@127.0.0.1
```

Daemonize mode (background QEMU):

```bash
./vm/scripts/run_vm.sh --daemonize
```

## Guest Bootstrap (packages + SSH)

After SSHing into the guest and mounting the repo (or cloning it), run:

```bash
cd /mnt/predicomp
./vm/guest/setup_arch_guest.sh
```

This installs the package set in `vm/config/guest-packages.txt` and enables `sshd`.

### Kernel version pinning (recommended)

Record exact package versions after a successful setup:

```bash
pacman -Q linux linux-headers clang llvm bpf libbpf lz4 gcc make | tee /mnt/predicomp/vm/config/guest-packages.txt
```

Then optionally pin the guest kernel packages in `/etc/pacman.conf`:

```ini
IgnorePkg = linux linux-headers
```

## Mount the Host Repo via 9p (inside guest)

```bash
cd /mnt/predicomp
./vm/guest/mount_repo_9p.sh
```

Defaults:

- mount tag: `predicomp_repo`
- mount point: `/mnt/predicomp`

You can override both:

```bash
./vm/guest/mount_repo_9p.sh predicomp_repo /mnt/predicomp
```

## Validate Guest Environment for `predicomp`

```bash
cd /mnt/predicomp
./vm/guest/validate_predicomp_env.sh
```

Checks include:

- `clang`, `bpftool` (from Arch package `bpf`), `make`, `lz4`
- `/sys/kernel/btf/vmlinux`
- `/sys/kernel/mm/damon/admin`
- tracefs/debugfs visibility

## Build and Run Experiments (inside guest)

### Build everything

```bash
cd /mnt/predicomp
make all
```

### Canonical current experiment (DAMON-backed autoloops)

Run as root in the guest (DAMON sysfs admin + eBPF experiments usually require root):

```bash
sudo ./workloads/bin/interactive_burst \
  --duration-sec 20 \
  --region-mb 256 \
  --active-ms 100 \
  --idle-ms 400 \
  --use-mem-arena \
  --arena-cap-mb 128 \
  --arena-autoloops
```

## Pragmatic Isolation Notes

Recommended guest profile for now:

- headless VM (no GUI session)
- fixed vCPU count and RAM
- minimal background services
- no swap for mem-arena-focused runs (unless testing swap behavior)
- run experiments one-at-a-time inside the guest

Deeper isolation (CPU pinning, IRQ tuning, governor tuning) can be added later.

## Troubleshooting

### `mem_arena_loops_start failed` in `interactive_burst --arena-autoloops`

This usually means the DAMON sysfs admin helper could not configure your guest kernel's DAMON interface.

Check:

- run as root inside guest
- `/sys/kernel/mm/damon/admin` exists
- another DAMON user is not already active (`nr_kdamonds` should be `0` before the run)
- guest kernel/sysfs layout matches the helper assumptions

### `/sys/kernel/debug/tracing/trace_pipe` missing

Mount debugfs inside the guest:

```bash
sudo mount -t debugfs debugfs /sys/kernel/debug
```

Or use modern tracefs path if available (`/sys/kernel/tracing`).

### `make all` fails on BPF tools

Install/verify:

- `clang`
- `llvm`
- `bpftool` (Arch package: `bpf`)
- `libbpf`
- `linux-headers`

## Next Steps (after first successful VM run)

1. Add stricter guest isolation profile (CPU governor + service reduction)
2. Pin exact kernel versions in `vm/config/default.env`
3. Optionally clone repo inside guest for benchmark runs, use 9p only for artifact export
