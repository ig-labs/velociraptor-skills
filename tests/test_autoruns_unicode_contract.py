"""Cross-runtime identity parity and conservative trust-version handling."""
import base64
import gzip
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.artifacts import policy as artifact_policy
from vraptor.autoruns import pipeline as autoruns
from vraptor.autoruns import golden as autoruns_golden
from vraptor.analyze import host as collection_analysis
from vraptor.hunt import live

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
VALUES = ['Straße', 'STRASSE', 'café', 'CAFÉ', 'İ', 'ı', 'I', 'Σ', 'σ', 'ς',
          'e\u0301', 'é', '\u1c89', '\U00010d50', '日本語', '😀', '\u2028', '\u2029',
          '<&>', '"quoted" /flag', '\tline\n', 'K', 'ſ', '', 'S-1-5-21-1-2-3-1001',
          '%LOCALAPPDATA%\\App.exe', '%APPDATA%\\App.exe', '%USERPROFILE%\\App.exe',
          'C:\\Users\\Alice\\App.exe', 'C:\\Documents and Settings\\Bob\\App.exe',
          '\\SystemRoot\\System32\\App.exe', '%SystemRoot%\\App.exe', '%WinDir%\\App.exe',
          None, '\x00\x01\x7f', 'C:\\Uſers\\Alice\\App.exe', '%UſerProfile%\\App.exe']


class UnicodeContractTest(unittest.TestCase):
    @unittest.skipUnless(BINARY.exists(), 'Local Velociraptor unavailable')
    def test_python_vql_payload_category_and_hash_parity(self):
        rows = [{'Image Path': value, 'Launch String': value, 'Signer': value,
                 'Category': value} for value in VALUES]
        vql = ('SELECT ' + autoruns.user_path_vql('`Image Path`') + ' AS ImagePath, '
               + autoruns.user_path_vql('`Launch String`') + ' AS LaunchString, '
               + autoruns.ascii_lower_vql('Signer') + ' AS Signer, '
               + autoruns.ascii_lower_vql('Category') + ' AS Category, '
               + autoruns.trusted_key_vql() + ' AS HashKey '
               + 'FROM foreach(row=parse_json_array(data=Rows))')
        result = subprocess.run([str(BINARY), 'query', '--format=jsonl',
                                 '--env', 'Rows=' + json.dumps(rows), vql],
                                text=True, capture_output=True, check=True, timeout=30)
        server = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(server), len(rows), result.stderr)
        for raw, actual in zip(rows, server):
            with self.subTest(value=raw['Image Path']):
                expected = autoruns.trusted_record(image_path=raw['Image Path'],
                    launch_string=raw['Launch String'], signer=raw['Signer'], category=raw['Category'])
                self.assertEqual(actual['HashKey'], expected['hash_key'])
                self.assertEqual(actual['ImagePath'], expected['image_path'])
                self.assertEqual(actual['LaunchString'], expected['launch_string'])
                self.assertEqual(actual['Signer'], expected['signer'])
                self.assertEqual(actual['Category'], expected['category'])
                self.assertEqual(autoruns.normalize_user_path(actual['ImagePath']), actual['ImagePath'])

    def test_host_does_not_suppress_distinct_unicode_identity(self):
        for trusted, observed in [('strasse', 'straße'), ('σ', 'ς'), ('i', 'İ'),
                                  ('é', 'e\u0301'), ('café', 'CAFÉ')]:
            with self.subTest(trusted=trusted, observed=observed):
                key = autoruns.trusted_key(image_path='c:\\tools\\'+trusted,
                                          launch_string='', signer='')
                rows = [{'ImagePath': 'c:\\tools\\'+observed,
                         'LaunchString': '', 'Signer': '', 'Category': 'Logon'}]
                residual, counts = collection_analysis.reduce_autoruns_with_golden_db(
                    rows, database=Path('unused'), keys={key}, base_metadata={})
                self.assertEqual(len(residual), 1)
                self.assertEqual(counts['known_good_filtered_rows'], 0)

    def test_selected_server_values_are_never_recanonicalized(self):
        for value in VALUES:
            with self.subTest(value=value):
                env = {}
                live.autoruns_selected_hash_where([
                    {'ImagePath': value, 'LaunchString': value, 'Signer': value}], env=env)
                payload = json.loads(gzip.decompress(base64.b64decode(env['AutorunsSelectedHashesGzipBase64'])))
                self.assertEqual(payload[0]['ImagePath'], value or '')
                self.assertEqual(payload[0]['Signer'], value or '')

    def test_bundled_policy_uses_shared_identities(self):
        profiles = artifact_policy.load_artifact_policy().profiles
        for name in ['IG.Windows.Sysinternals.Autoruns', 'Windows.Sysinternals.Autoruns']:
            with self.subTest(artifact=name):
                _, signature = live.stack_for_role(profiles[name], 'signature')
                self.assertEqual(signature['server_dimensions'], [autoruns.trusted_key_vql()])
                _, family = live.stack_for_role(profiles[name], 'family_signature')
                self.assertEqual(family['server_dimensions'], [
                    autoruns.user_path_vql('`Entry Location`'), autoruns.ascii_lower_vql('Entry'),
                    autoruns.user_path_vql('`Image Path`'), autoruns.user_path_vql('`Launch String`'),
                    autoruns.ascii_lower_vql('Signer')])


    def test_legacy_database_is_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)/'legacy.sqlite'
            conn = sqlite3.connect(database)
            conn.executescript(autoruns_golden.SCHEMA_SQL)
            metadata = {**autoruns_golden.REQUIRED_METADATA, 'canonicalization_version': '3'}
            conn.executemany('INSERT INTO metadata(key,value) VALUES (?,?)', metadata.items())
            conn.commit(); conn.close()
            original = database.read_bytes()
            with self.assertRaisesRegex(RuntimeError, 'reviewed original rows'):
                autoruns_golden.live_lookup_payload(database)
            with self.assertRaisesRegex(RuntimeError, 'reviewed original rows'):
                autoruns_golden.lookup_hashes(database, ['a' * 40])
            self.assertEqual(database.read_bytes(), original)

    def test_identity_version_changes_analysis_watermark(self):
        args = dict(profile_hash='profile', filters=[], known_bad=[])
        current = live.analysis_input_hash(**args)
        with mock.patch.object(autoruns, 'CANONICALIZATION_VERSION', 3):
            self.assertNotEqual(current, live.analysis_input_hash(**args))

    def test_missing_or_legacy_candidate_contract_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidates.csv'
            for metadata in [{}, {'CanonicalizationVersion': 3}]:
                with self.subTest(metadata=metadata):
                    path.write_text(live.render_csv_with_metadata(
                        metadata=metadata, fieldnames=live.AUTORUNS_POTENTIAL_GOLDEN_FIELDS,
                        rows=[]))
                    original = path.read_bytes()
                    with self.assertRaisesRegex(RuntimeError, 'Rerun analysis against original evidence'):
                        autoruns_golden.validate_candidate_subset(path, path, live=live)
                    self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
