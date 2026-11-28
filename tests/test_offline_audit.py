import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fwmap.offline_audit import render_handoff, summarize


class OfflineAuditTests(unittest.TestCase):
    def test_done_with_and_without_findings(self):
        for findings in ([], [{"evidence": ["record-1"]}, {}]):
            with self.subTest(findings=findings):
                result = summarize({
                    "trace": [
                        {"action": "review", "source": "model"},
                        {"action": "done", "source": "heuristic"},
                    ],
                    "findings": findings,
                    "stats": {"rejects": 0},
                }, budget=2)
                self.assertEqual(result["status"], "recorded_done")
                self.assertEqual((result["model"], result["heuristic"]), (1, 1))
                self.assertEqual(result["findings"], len(findings))
                self.assertEqual(result["cited"], bool(findings))
                if findings:
                    self.assertIn("1 条发现缺少证据引用", render_handoff(result))

    def test_legacy_record_without_terminal_status_or_attribution(self):
        record = {"trace": [{"action": "review"}, {"action": "review", "source": "other"}]}
        result = summarize(record)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["unknown_source"], 2)
        self.assertIsNone(result["findings"])
        self.assertIsNone(result["rejects"])
        self.assertEqual(summarize(record, budget=2)["status"], "budget_reached")
        self.assertEqual(summarize(record, budget=3)["status"], "unknown")

    def test_rejects_inconsistent_or_invalid_records(self):
        for record, budget in (
            ({}, None),
            ({"trace": [{}]}, None),
            ({"trace": [{"action": "done"}, {"action": "review"}]}, None),
            ({"trace": [{"action": "review"}]}, 0),
            ({"trace": [], "findings": ["invalid"]}, None),
        ):
            with self.subTest(record=record, budget=budget), self.assertRaises(ValueError):
                summarize(record, budget)

    def test_command_writes_unfinished_report_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            record = Path(temp) / "plan.json"
            output = Path(temp) / "handoff.md"
            record.write_text(json.dumps({"trace": [{"action": "review"}]}), encoding="utf-8")
            command = [
                sys.executable, "-m", "fwmap.offline_audit", str(record),
                "--budget", "1", "--output", str(output),
            ]
            first = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(first.returncode, 1, first.stderr)
            report = output.read_text(encoding="utf-8")
            self.assertIn("缺少结束标记", report)
            second = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(second.returncode, 2, second.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), report)


if __name__ == "__main__":
    unittest.main()
