"""Offline inspection of synthetic disks; no VM, mount, root or downloads."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/inspect-legacy-disk.py"
spec = importlib.util.spec_from_file_location("disk_inspector", SCRIPT)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


def mbr(kind=0x83, start=2048, sectors=16384):
    data = bytearray(512)
    data[450] = kind
    struct.pack_into("<II", data, 454, start, sectors)
    data[510:] = b"\x55\xaa"
    return data


class PartitionTests(unittest.TestCase):
    def test_primary_partition_bounds_and_unsupported_layouts(self):
        self.assertEqual(inspector.partitions(mbr(), 32 * 1024 * 1024)[0]["start_sector"], 2048)
        for data in (bytes(512), mbr(kind=0xee), mbr(start=0), mbr(sectors=0), mbr(sectors=100000)):
            with self.subTest(data=data[:16]), self.assertRaises(ValueError):
                inspector.partitions(data, 32 * 1024 * 1024)

    def test_sparse_extraction_preserves_bytes_and_rejects_truncated_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            data = b"skip" + bytes(inspector.BLOCK) + b"nonzero" + bytes(512)
            raw.write_bytes(data)
            output = root / "part"
            inspector.extract_partition(raw, output, 4, len(data) - 4)
            self.assertEqual(output.read_bytes(), data[4:])
            with self.assertRaises(FileExistsError):
                inspector.extract_partition(raw, output, 4, 1)
            with self.assertRaises(ValueError):
                inspector.extract_partition(raw, root / "truncated", 4, len(data))


@unittest.skipUnless(all(shutil.which(tool) for tool in
                        ("qemu-img", "mke2fs", "e2fsck", "debugfs")), "requires QEMU and e2fsprogs")
class DiskInspectionTests(unittest.TestCase):
    def run_inspection(self, disk, output):
        return subprocess.run([sys.executable, str(SCRIPT), str(disk), str(output)],
                              capture_output=True, text=True, timeout=90)

    def test_real_image_preserves_source_and_records_readonly_findings(self):
        with tempfile.TemporaryDirectory(prefix="legacy inspection ") as directory:
            root = Path(directory)
            part = root / "part.ext"
            part.touch()
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", str(part), "8192"],
                           check=True, capture_output=True)
            raw = root / "disk.raw"
            with raw.open("wb") as target:
                target.truncate(32 * 1024 * 1024)
                target.write(mbr())
                target.seek(2048 * 512)
                target.write(part.read_bytes())
            disk = root / "disk.qcow2"
            subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(disk)],
                           check=True, capture_output=True)
            before = inspector.digest(disk)
            output = root / "inspection"
            result = self.run_inspection(disk, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(inspector.digest(disk), before)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["source_sha256_before"], report["source_sha256_after"])
            self.assertEqual(report["filesystem_check_returncode"], 0)
            self.assertTrue(any("File not found" in item["stderr"] for item in report["commands"]))
            self.assertTrue((output / "COMPLETE").exists())
            actual = set()
            for line in (output / "SHA256SUMS").read_text().splitlines():
                value, name = line.split("  ", 1)
                self.assertEqual(inspector.digest(output / name), value)
                actual.add(name)
            self.assertEqual(actual, {p.name for p in output.iterdir()} - {"SHA256SUMS", "COMPLETE"})
            self.assertNotEqual(self.run_inspection(disk, output).returncode, 0)
            self.assertEqual(inspector.digest(disk), before)

    def test_invalid_disk_retains_partial_report_without_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            disk = root / "invalid.qcow2"
            disk.write_bytes(b"not a qcow2 disk")
            output = root / "failed"
            self.assertNotEqual(self.run_inspection(disk, output).returncode, 0)
            self.assertTrue((output / "report.json").exists())
            self.assertFalse((output / "COMPLETE").exists())
            self.assertEqual(disk.read_bytes(), b"not a qcow2 disk")
            link = root / "link"
            link.symlink_to(root / "missing")
            self.assertNotEqual(self.run_inspection(disk, link).returncode, 0)
            self.assertTrue(link.is_symlink())
            self.assertFalse((root / "missing").exists())
