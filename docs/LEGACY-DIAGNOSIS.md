# Legacy disk diagnosis and recovery — 26 October 2026

The original Debian 7 disk did not boot normally. An offline inspection found
a valid primary Linux partition, kernel and initramfs, but neither `/boot/grub`
nor `/usr/sbin/grub-install`. A forced read-only filesystem check returned 0.
This supports a missing bootloader installation; it does not establish why the
original installer stopped before completing that step.

GRUB was subsequently installed in a separate qcow2 overlay using packages from
the existing Debian 7.11 netinst ISO, with no guest networking. The overlay then
booted through GRUB to a serial login. Labs 01–03 completed as user `lab` (UID
1000); see [baseline results](BASELINE-RESULTS.md). The original disk's SHA-256
was unchanged before and after recovery:

```text
3e9ff4e04fa657d1f30d0bdffd977d48cbc37b6ade12a908a9defc156792263a
```

## Repeat the offline inspection

Stop any VM using the disk. From the repository root, use a fresh output path:

```bash
python3 scripts/inspect-legacy-disk.py images/legacy.qcow2 tmp/legacy-inspection
```

Requires Python 3.8+, `qemu-img`, `debugfs` and `e2fsck`. No root, mount, guest
execution or network access is needed. The inspector supports standalone,
unencrypted qcow2 disks with a DOS MBR and a primary Linux ext filesystem. It
does not traverse extended partitions or support GPT. Partition 1 is the
default; select another primary partition with `--partition 2` if appropriate.

The script creates a raw disk copy, verifies it against the source with
`qemu-img compare`, extracts the selected partition and verifies its copied bytes
by hashing. It runs `e2fsck -f -n` and read-only `debugfs` requests against the
extracted copy. It records tool versions, commands, stdout/stderr, return codes,
partition metadata and source hashes before/after inspection. Existing output
paths are refused. Failure leaves partial evidence without `COMPLETE`.

`COMPLETE` means the inspection finished. Filesystem errors with checker status
4 remain findings in the report; they do not turn an inspection into a healthy
VM. `debugfs` lookup failures can return status 0, so review its stderr.
`SHA256SUMS` covers every artifact except itself and `COMPLETE`:

```bash
cd tmp/legacy-inspection
sha256sum -c SHA256SUMS
```

The output retains two potentially large sparse files. Allow up to twice the
disk's virtual size in free space. The committed
[inspection snapshot](evidence/legacy-disk-inspection-2026-10-26.json) contains
the complete report with host repository paths normalized to `$REPO`; the full
local capture is under ignored `tmp/legacy-review/source-inspection/`.

## Recovery procedure used

All writes below were inside a separate overlay. The original disk was never
mounted or booted writable. This is recovery of the existing installation,
not validation of a fresh unattended install.

1. Extract the kernel and initramfs from the verified partition copy:

   ```bash
   debugfs -R 'dump /boot/vmlinuz-3.2.0-4-686-pae tmp/legacy-vmlinuz' tmp/legacy-inspection/root.ext
   debugfs -R 'dump /boot/initrd.img-3.2.0-4-686-pae tmp/legacy-initrd.img' tmp/legacy-inspection/root.ext
   ```

2. Create an overlay at a new path and boot it with the extracted kernel. For
   this disk the root partition is `/dev/sda1`. The `init=/bin/bash` recovery
   shell is restricted to this disposable guest; there is no network device.

   ```bash
   qemu-img create -f qcow2 -F qcow2 -b "$PWD/images/legacy.qcow2" tmp/legacy-recovery.qcow2
   qemu-system-i386 -enable-kvm -m 512 \
     -drive file=tmp/legacy-recovery.qcow2,format=qcow2 \
     -cdrom downloads/debian-7.11.0-i386-netinst.iso \
     -kernel tmp/legacy-vmlinuz -initrd tmp/legacy-initrd.img \
     -append 'root=/dev/sda1 ro console=ttyS0 init=/bin/bash' \
     -nographic -net none
   ```

   Omit `-enable-kvm` on hosts without KVM access. Never reuse an existing
   overlay path with `qemu-img create`.

3. In the **guest recovery shell**, remount `/` writable and mount the ISO
   read-only at `/mnt`. Install the ISO's i386 packages `libfuse2`, `libbz2-1.0`,
   `libpng12-0`, `libfreetype6`, `libasprintf0c2`, `gettext-base`, `ucf`,
   `grub-common`, `grub2-common`, `grub-pc-bin` and `grub-pc`. Set
   `DEBIAN_FRONTEND=noninteractive` and preseed `grub-pc/install_devices` as
   `/dev/sda`, then finish with `dpkg --configure -a`. The successful GRUB
   packages were version `1.99-27+deb7u3`. The complete package-install log and
   resulting package manifest are in the
   [baseline snapshot](evidence/legacy-baseline-2026-10-26.json).
4. Configure GRUB's serial terminal at 115200 baud, add
   `console=tty0 console=ttyS0,115200n8` to `GRUB_CMDLINE_LINUX`, run
   `update-grub`, and enable a serial getty in `/etc/inittab`. Set the documented
   disposable root password (`toor`) and create user `lab` with a disabled
   password for unprivileged runs via `su`. These account changes were confined
   to the overlay; the original installation did not accept the documented root
   password.
5. Sync, remount `/` read-only and power off. Boot the overlay again with
   `-boot c`, without `-kernel`, `-initrd`, `-append` or the installer ISO.
   Verify the GRUB menu, normal init, serial login and `/proc/cmdline`.

The first package-install attempt reported missing dependencies; after installing
those from the same ISO, configuration completed and `dpkg --audit` was empty.
The first normal boot reached login but rejected the documented password; that
password was then explicitly set in a second recovery session. The final normal
boot and baseline capture completed, followed by a normal `shutdown -h now`.

## Local recovered image

After shutdown the overlay was flattened to the standalone, ignored
`images/legacy-recovered-20261026.qcow2`. `qemu-img compare` confirmed identical
virtual disk contents. Its hash is recorded in the baseline snapshot.
On this checkout, review it without persistent writes or networking:

```bash
LEGACY_DISK="$PWD/images/legacy-recovered-20261026.qcow2" \
  SNAPSHOT=1 OFFLINE=1 HEADLESS=1 ./scripts/run-legacy-vm.sh
```

Use the serial login (`root` / `toor`) and shut down from inside the guest.
SSH and GDB are absent from this recovered image. `OFFLINE=1` disables the
guest network device and SSH forwarding; `SNAPSHOT=1` discards session writes.
Copy any new evidence out before ending a snapshot session.

For a separate fresh installation, keep the original disk and choose a new path:

```bash
LEGACY_DISK="$PWD/images/legacy-fresh.qcow2" ./scripts/setup-legacy-vm.sh
```

The setup script refuses existing files, directories and symlinks before
downloading anything. A future clean baseline must pass normal disk boot,
login, a clean package audit, recorded toolchain versions, unprivileged lab
builds, full capture checksums and a second boot. SSH must be verified separately
if it is used as the evidence transport. The recovery above does not establish
that the unattended installer now satisfies those criteria.
