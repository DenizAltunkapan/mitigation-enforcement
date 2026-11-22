"""Exercise baseline collection with real host tools; never boot a VM."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "capture-baseline.sh"


class CaptureBaselineTests(unittest.TestCase):
    def run_capture(self, *args):
        env = os.environ.copy()
        # Do not inherit an unrelated build experiment from the developer shell.
        for key in ("CC", "CFLAGS", "LDFLAGS"):
            env.pop(key, None)
        return subprocess.run(
            ["bash", str(SCRIPT), *map(str, args)],
            cwd="/tmp", env=env, capture_output=True, text=True, timeout=60,
        )

    def test_rejects_bad_arguments_without_creating_results(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            for args in [(), ("modern",), ("typo", output)]:
                result = self.run_capture(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(output.exists())

    def test_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "do-not-overwrite"
            marker.write_text("original evidence")
            result = self.run_capture("host", directory)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(marker.read_text(), "original evidence")
            self.assertEqual(list(Path(directory).iterdir()), [marker])

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("gcc", "make", "readelf", "objdump")),
        "requires host compiler and binutils",
    )
    def test_collects_all_labs_and_verifiable_evidence(self):
        with tempfile.TemporaryDirectory(prefix="baseline review ") as directory:
            output = Path(directory) / "host results"
            result = self.run_capture("host", output)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertTrue((output / "COMPLETE").is_file())
            environment = (output / "environment.txt").read_text()
            for expected in ("environment_label=host", "architecture=", "CFLAGS=", "--- libc ---", "--- ASLR ---"):
                self.assertIn(expected, environment)
            labs = sorted(path for path in output.iterdir() if path.is_dir())
            self.assertEqual(len(labs), 3)
            self.assertEqual(len(list(output.glob("*/*.run-*.txt"))), 15)
            self.assertEqual(len(list(output.glob("*/*.disassembly.txt"))), 5)
            hardened = output / "03-binary-mitigation-baseline" / "mitigation_hardened.readelf.txt"
            for expected in ("__stack_chk_fail", "GNU_RELRO", "BIND_NOW", "GNU_STACK"):
                self.assertIn(expected, hardened.read_text())
            for manifest in [output / "SHA256SUMS", *output.glob("*/SHA256SUMS")]:
                for line in manifest.read_text().splitlines():
                    digest, name = line.split("  ", 1)
                    artifact = manifest.parent / name
                    self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), digest)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("gcc", "make", "readelf", "objdump")),
        "requires host compiler and binutils",
    )
    def test_failed_build_has_no_completion_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failed"
            env = os.environ.copy()
            env["CC"] = "gcc"
            env["CFLAGS"] = "-fthis-flag-is-intentionally-invalid"
            env.pop("LDFLAGS", None)
            result = subprocess.run(
                ["bash", str(SCRIPT), "host", str(output)],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "COMPLETE").exists())
            self.assertTrue((output / "environment.txt").exists())
            build_log = output / "01-process-memory-layout" / "build.txt"
            self.assertIn("-fthis-flag-is-intentionally-invalid", build_log.read_text())


class VmLauncherTests(unittest.TestCase):
    def test_forwarded_ssh_binds_only_to_loopback(self):
        for kind, executable, port in [
            ("legacy", "qemu-system-i386", 2222),
            ("modern", "qemu-system-x86_64", 2223),
        ]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "scripts").mkdir()
                (root / "images").mkdir()
                launcher = root / "scripts" / ("run-" + kind + "-vm.sh")
                shutil.copyfile(ROOT / "scripts" / launcher.name, launcher)
                (root / "images" / (kind + ".qcow2")).touch()
                (root / "images" / "modern-seed.iso").touch()
                stub = root / executable
                stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$QEMU_ARGS"\n')
                stub.chmod(0o755)
                args_file = root / "args.txt"
                env = dict(os.environ, HEADLESS="1", QEMU_ARGS=str(args_file))
                env["PATH"] = str(root) + os.pathsep + env["PATH"]
                for snapshot, offline in (("0", "0"), ("1", "0"), ("1", "1"),
                                          ("invalid", "0"), ("0", "invalid")):
                    with self.subTest(snapshot=snapshot, offline=offline):
                        env["SNAPSHOT"] = snapshot
                        env["OFFLINE"] = offline
                        env.pop("LEGACY_DISK", None)
                        disk = root / "images" / (kind + ".qcow2")
                        if kind == "legacy" and snapshot == "1":
                            disk = root / "images" / "separate-rebuild.qcow2"
                            disk.touch()
                            env["LEGACY_DISK"] = str(disk)
                        args_file.unlink(missing_ok=True)
                        result = subprocess.run(
                            ["bash", str(launcher)], env=env,
                            capture_output=True, text=True, timeout=10,
                        )
                        if "invalid" in (snapshot, offline):
                            self.assertEqual(result.returncode, 2)
                            self.assertFalse(args_file.exists())
                            continue
                        self.assertEqual(result.returncode, 0, result.stderr)
                        args = args_file.read_text().splitlines()
                        if offline == "1":
                            self.assertIn("none", args)
                            self.assertFalse(any("hostfwd" in arg or arg.startswith("nic") for arg in args))
                        else:
                            self.assertIn("user,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22", args)
                        self.assertIn("-nographic", args)
                        self.assertEqual("-snapshot" in args, snapshot == "1")
                        self.assertTrue(any(arg.startswith("file=" + str(disk) + ",") for arg in args))

    def test_legacy_setup_preserves_existing_paths_before_downloading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = root / "existing.qcow2"
            disk.write_bytes(b"preserve this disk")
            link = root / "dangling.qcow2"
            link.symlink_to(root / "missing")
            for target in (disk, link, root):
                result = subprocess.run(
                    ["bash", str(ROOT / "scripts/setup-legacy-vm.sh")],
                    env=dict(os.environ, LEGACY_DISK=str(target)),
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Choose a new LEGACY_DISK path", result.stderr)
            self.assertEqual(disk.read_bytes(), b"preserve this disk")
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())


if __name__ == "__main__":
    unittest.main()
