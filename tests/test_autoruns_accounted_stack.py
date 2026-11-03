"""Autoruns accounting and residual stack VQL parity."""
import json
import subprocess
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.hunt import live
from tests.autoruns_vql_oracles import autoruns_accounting_vql

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


class AutorunsAccountingParityTest(unittest.TestCase):
    @unittest.skipUnless(BINARY.exists(), "Configured Velociraptor unavailable")
    def test_native_vql_parity_unicode_categories_blank_and_matching(self):
        def row(image, launch="", signer="", category="Logon"):
            return {"Image Path": image, "Launch String": launch, "Signer": signer, "Category": category}
        source_rows = [row(r"C:\exact.exe"), row(r"C:\exact.exe", category="Services"),
                       row(r"C:\regex7.exe", "run7"), row(r"C:\regex7.exe", "wrong"),
                       row(""), row("", "launch-only"), row(" "),
                       row(r"C:\Users\Alice\app.exe", category="Services"),
                       row(r"%USERPROFILE%\app.exe", category="Logon")]
        source_rows += [row("C:\\" + value, signer=value) for value in
                        ("Straße", "STRASSE", "CAFÉ", "café", "é", "e\u0301", "İ", "i", "日本語😀", "<&>\u2028")]
        env = {}
        selected, _ = live.autoruns_selected_hash_where([autoruns.trusted_key_payload(
            image_path=r"C:\exact.exe", launch_string="", signer="")], env=env)
        where = f"NOT ({selected})"
        with mock.patch.object(live, "source_vql", return_value="TestRows"):
            queries = [autoruns_accounting_vql(where), live.autoruns_residual_stack_vql(where)]
        for rows in (source_rows, list(reversed(source_rows)), [], [row(""), row("")],
                     [row(r"C:\exact.exe")]):
            outputs = []
            for query in queries:
                command = [str(BINARY), "query", "--format=jsonl"]
                for name, value in {**env, "Rows": json.dumps(rows)}.items():
                    command += ["--env", f"{name}={value}"]
                run = subprocess.run(command + [
                    "LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows))\n" + query],
                    text=True, capture_output=True, check=True, timeout=30)
                self.assertEqual(run.stderr, "")
                outputs.append([json.loads(line) for line in run.stdout.splitlines()])
            counts = outputs[0][0] if outputs[0] else dict(SourceRows=0, ResidualRows=0, PopulatedRows=0)
            self.assertEqual(counts["SourceRows"], len(rows))
            self.assertEqual(sum(item["Total"] for item in outputs[1]), counts["PopulatedRows"])
            identities = [live.autoruns_residual_identity(item) for item in outputs[1]]
            self.assertEqual(len(identities), len(set(identities)))


if __name__ == "__main__":
    unittest.main()
