#!/usr/bin/env python3
"""Exercise the native runtime chart's Kubernetes floor with real Helm."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


CHART = Path(__file__).resolve().parent.parent / "charts/native-plugin-runtime"
VALUES = [
    "--set=enabled=true",
    "--set-string=trust.mode=development-untrusted",
    "--set-string=plugin.id=dev.stellwerk.native-probe",
    "--set-string=plugin.version=1.0.0",
    "--set-string=package.reference=registry.invalid/native-probe@sha256:" + "a" * 64,
    "--set-string=package.manifestSHA256=" + "a" * 64,
    "--set-string=images.runtime=registry.invalid/runtime@sha256:" + "b" * 64,
    "--set-string=images.oras=registry.invalid/oras@sha256:" + "c" * 64,
]


def render(chart: Path, version: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "native-probe", str(chart), f"--kube-version={version}",
         *VALUES, *args],
        capture_output=True, text=True, timeout=20, check=False,
    )


class KubernetesVersionTests(unittest.TestCase):
    def test_chart_metadata_refuses_129_even_without_prestop(self):
        metadata = subprocess.run(
            ["helm", "show", "chart", str(CHART)],
            capture_output=True, text=True, timeout=20, check=True,
        )
        self.assertIn("kubeVersion: '>=1.30.0'", metadata.stdout)
        for args in ((), ("--set=preStopDelaySeconds=0",)):
            with self.subTest(args=args):
                denied = render(CHART, "1.29.0", *args)
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("kubeVersion", denied.stderr)

    def test_template_guard_refuses_129_without_metadata(self):
        with tempfile.TemporaryDirectory(prefix="runtime-chart-floor-") as directory:
            chart = Path(directory) / "native-plugin-runtime"
            shutil.copytree(CHART, chart)
            metadata = chart / "Chart.yaml"
            metadata.write_text(
                metadata.read_text(encoding="utf-8").replace('kubeVersion: ">=1.30.0"\n', ""),
                encoding="utf-8",
            )
            for args in ((), ("--set=preStopDelaySeconds=0",)):
                with self.subTest(args=args):
                    denied = render(chart, "1.29.0", *args)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertIn("native-plugin-runtime requires Kubernetes 1.30 or newer", denied.stderr)

    def test_130_and_135_render_identical_pod_specs(self):
        for args in ((), ("--set=preStopDelaySeconds=0",)):
            with self.subTest(args=args):
                minimum = render(CHART, "1.30.0", *args)
                later = render(CHART, "1.35.0", *args)
                self.assertEqual(minimum.returncode, 0, minimum.stderr)
                self.assertEqual(later.returncode, 0, later.stderr)
                self.assertIn("kind: Deployment", minimum.stdout)
                self.assertEqual(minimum.stdout, later.stdout)


if __name__ == "__main__":
    unittest.main()
