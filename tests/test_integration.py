"""Integration test — full pipeline."""

import unittest
import tempfile
import shutil
from pathlib import Path

from xdr_simulator.main import run_simulation


class TestFullPipeline(unittest.TestCase):
    """Test the complete XDR simulation pipeline."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = str(Path(self.test_dir) / "data")
        self.log_dir = str(Path(self.test_dir) / "logs")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_pipeline(self):
        """Run full simulation with reduced event count."""
        results = run_simulation(
            events_per_day=2000,
            attack_probability=0.15,
            output_dir=self.output_dir,
            log_dir=self.log_dir,
            verbose=False,
        )

        # Check results
        self.assertGreater(results["total_events"], 1000)
        self.assertGreater(results["parsed_events"], 1000)
        self.assertIsInstance(results["incidents"], int)
        self.assertGreater(results["execution_time_seconds"], 0)

        # Check output files exist
        output_path = Path(self.output_dir)
        self.assertTrue(output_path.exists())

        # Should have at least the main report
        json_files = list(output_path.glob("*.json"))
        self.assertGreater(len(json_files), 0)

    def test_pipeline_detects_incidents(self):
        """With attack scenarios enabled, should detect incidents."""
        results = run_simulation(
            events_per_day=3000,
            attack_probability=0.20,
            output_dir=self.output_dir,
            log_dir=self.log_dir,
            verbose=False,
        )

        # Should detect at least one incident with attack scenario
        self.assertGreater(results["incidents"], 0)

        # Check that incident types are valid
        valid_types = {"ssh_brute_force", "abnormal_access", "privilege_escalation"}
        for t in results["incident_types"]:
            self.assertIn(t, valid_types)


if __name__ == "__main__":
    unittest.main()
