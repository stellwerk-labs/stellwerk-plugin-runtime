#!/usr/bin/env python3
"""Check OCI chart metadata against Helm's real serialized chart output."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts/native-plugin-runtime"
CONVERTER = ROOT / "scripts/chart-config.py"


def convert(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(CONVERTER)], input=source, capture_output=True,
        text=True, timeout=20, check=False,
    )


class ChartConfigTests(unittest.TestCase):
    def test_real_helm_archive_preserves_minimum_and_existing_metadata(self):
        with tempfile.TemporaryDirectory(prefix="runtime-chart-config-") as directory:
            packaged = subprocess.run(
                ["helm", "package", str(CHART), "--destination", directory],
                capture_output=True, text=True, timeout=20, check=True,
            )
            self.assertIn("native-plugin-runtime-0.1.0.tgz", packaged.stdout)
            archive = Path(directory) / "native-plugin-runtime-0.1.0.tgz"
            shown = subprocess.run(
                ["helm", "show", "chart", str(archive)],
                capture_output=True, text=True, timeout=20, check=True,
            )
            converted = convert(shown.stdout)
            self.assertEqual(converted.returncode, 0, converted.stderr)
            self.assertEqual(json.loads(converted.stdout), {
                "apiVersion": "v2",
                "name": "native-plugin-runtime",
                "description": "Generic isolated runtime for a pre-verified Stellwerk native plugin package",
                "type": "application",
                "version": "0.1.0",
                "appVersion": "0.1.0",
                "kubeVersion": ">=1.30.0",
            })

    def test_helm_single_quote_escaping(self):
        converted = convert("description: 'operator''s package'\n")
        self.assertEqual(converted.returncode, 0, converted.stderr)
        self.assertEqual(json.loads(converted.stdout), {"description": "operator's package"})

    def test_malformed_or_nested_metadata_is_refused(self):
        for source in (
            "description: '\n",
            "kubeVersion: '>=1.30.0\n",
            "kubeVersion: '>=1.30'0'\n",
            'appVersion: "unterminated\n',
            "annotations:\n  chart: nested\n",
            "annotations: {chart: nested}\n",
            "maintainers: [operator]\n",
            "description: |\n",
            "description: !!str tagged\n",
            "description: &anchored value\n",
            "description: *alias\n",
            "version: 0.1.0\nversion: 0.1.1\n",
        ):
            with self.subTest(source=source):
                converted = convert(source)
                self.assertNotEqual(converted.returncode, 0)
                self.assertIn("invalid Helm chart metadata", converted.stderr)


if __name__ == "__main__":
    unittest.main()
