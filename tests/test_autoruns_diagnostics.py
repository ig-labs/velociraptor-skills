"""Synthetic accounting and fail-closed drill-down regression tests."""
import base64
import gzip
import json
import subprocess
import unittest
from pathlib import Path

from vraptor.paths import resolve_velociraptor_binary
from unittest import mock

from vraptor.autoruns import pipeline as autoruns
from vraptor.hunt import live
from vraptor.logging import operations as operation_log

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))


class AutorunsDiagnosticsTest(unittest.TestCase):
    def test_missing_identity_counts_are_not_row_counts(self):
        selected = [{'ImagePath': f'c:\\app{i}.exe', 'LaunchString': '', 'Signer': ''}
                    for i in range(23)]
        rows = [{**item, '_AutorunsIdentity': item, 'HashKey': autoruns.trusted_key(
            image_path=item['ImagePath'], launch_string='', signer='')}
                for item in selected[:22]]
        api = mock.Mock()
        api.query_batches.return_value = iter([rows])
        with mock.patch.object(live.operation_log, 'emit') as emit:
            with self.assertRaisesRegex(RuntimeError, '1 missing'):
                live.review_autoruns_suspicious_context_streaming(
                    api, hunt_id='H.test', artifact='Windows.Sysinternals.Autoruns',
                    profile={}, suspicious_rows=selected, state={})
        failure = next(call.kwargs for call in emit.call_args_list
                       if call.args == ('autoruns_drilldown_failed',))
        self.assertEqual(failure['missing_identities'], 1)
        self.assertEqual(failure['matched_identities'], 22)
        self.assertEqual(failure['error_code'], 'autoruns_missing_identity')
        self.assertNotIn('app22', str(emit.call_args_list))
        self.assertEqual(api.query_batches.call_count, 1)

    @unittest.skipUnless(BINARY.exists(), 'Local Velociraptor binary unavailable')
    def test_combined_golden_counts_match_three_original_scans(self):
        rows = [{'Image Path': r'c:\app.exe', 'Launch String': '', 'Signer': '', 'Category': 'Logon'},
                {'Image Path': r'c:\app.exe', 'Launch String': '', 'Signer': '', 'Category': 'Services'},
                {'Image Path': r'c:\unknown.exe', 'Launch String': '', 'Signer': '', 'Category': 'Services'},
                {'Image Path': '', 'Launch String': '', 'Signer': '', 'Category': 'Logon'}]
        key = autoruns.trusted_key(image_path=r'c:\app.exe', launch_string='', signer='')
        encoded = base64.b64encode(gzip.compress(json.dumps([key]).encode())).decode()
        env = {}
        where = live.autoruns_golden_where('Windows.Sysinternals.Autoruns',
                configuration={'enabled': True, 'lookup_gzip_base64': encoded}, env=env)
        prefix = 'LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows))\n'
        with mock.patch.object(live, 'source_vql', return_value='TestRows'):
            queries = [live.count_vql(''), live.count_vql(where),
                       live.count_vql(live.combine_where(where, '(`Image Path` OR `Launch String`)')),
                       live.autoruns_accounting_vql(where)]
        results = []
        for query in queries:
            result = subprocess.run([str(BINARY), 'query', '--format=jsonl',
                '--env', 'Rows=' + json.dumps(rows), '--env',
                'AutorunsGoldenLookupGzipBase64=' + encoded, prefix + query],
                capture_output=True, text=True, check=True, timeout=20)
            results.append(json.loads(result.stdout))
        # The two app.exe rows share the trusted identity across categories;
        # unknown.exe and the blank identity remain in the general residual.
        self.assertEqual([item['RowCount'] for item in results[:3]], [4, 2, 1])
        self.assertEqual(results[3], {'SourceRows': 4, 'ResidualRows': 2, 'PopulatedRows': 1})

    @unittest.skipUnless(BINARY.exists(), 'Local Velociraptor binary unavailable')
    def test_accounting_vql_executes_one_source_scan(self):
        rows = [{'Image Path': 'a', 'Launch String': '', 'Keep': False},
                {'Image Path': 'b', 'Launch String': '', 'Keep': True},
                {'Image Path': '', 'Launch String': '', 'Keep': True},
                {'Image Path': '', 'Launch String': 'cmd /c x', 'Keep': True}]
        with mock.patch.object(live, 'source_vql', return_value='TestRows'):
            query = live.autoruns_accounting_vql('Keep')
        prefix = ('LET TestRows = SELECT * FROM foreach(row=parse_json_array(data=Rows))\n')
        result = subprocess.run([str(BINARY), 'query', '--format=jsonl',
                                 '--env', 'Rows=' + json.dumps(rows), prefix + query],
                                capture_output=True, text=True, check=True, timeout=20)
        self.assertEqual(json.loads(result.stdout),
                         {'SourceRows': 4, 'ResidualRows': 3, 'PopulatedRows': 2})
        self.assertEqual(query.count('FROM TestRows'), 1)

    @unittest.skipUnless(BINARY.exists(), 'Local Velociraptor binary unavailable')
    def test_normalized_identity_roundtrip(self):
        values = [r'C:\Users\Alice\App\a.exe', r'%APPDATA%\App\a.exe',
                  r'\SystemRoot\System32\a.exe', r'C:\App\Straße.exe',
                  r'C:\App\a&b.exe', r'"C:\App\x.exe" /flag', '']
        for value in values:
            with self.subTest(value=value):
                result = subprocess.run([str(BINARY), 'query', '--format=jsonl',
                    '--env', 'Value=' + value,
                    'SELECT ' + autoruns.user_path_vql('Value') + ' AS Normalized FROM scope()'],
                    capture_output=True, text=True, check=True, timeout=20)
                normalized = json.loads(result.stdout)['Normalized']
                env = {}
                live.autoruns_selected_hash_where(
                    [{'ImagePath': normalized, 'LaunchString': '', 'Signer': ''}],
                    env=env)
                sent = json.loads(gzip.decompress(base64.b64decode(
                    env['AutorunsSelectedHashesGzipBase64'])))
                self.assertEqual(sent[0]['ImagePath'], normalized)
                # The selected-key memoization and original-row key must agree.
                where, _ = live.autoruns_selected_hash_where(
                    sent, env=env)
                vql = (live.autoruns_golden_query_preamble(where)
                       + ' SELECT ' + where + ' AS Matched FROM foreach(row=['
                       + 'dict(`Image Path`=Value, `Launch String`="", Signer="")])')
                result = subprocess.run([str(BINARY), 'query', '--format=jsonl',
                    '--env', 'Value=' + value, '--env',
                    'AutorunsSelectedHashesGzipBase64=' + env['AutorunsSelectedHashesGzipBase64'], vql],
                    capture_output=True, text=True, check=True, timeout=20)
                self.assertTrue(json.loads(result.stdout)['Matched'])

class AutorunsLogTimingTest(unittest.TestCase):
    def test_timing_exposes_consumer_pause_only_at_debug(self):
        import tempfile
        import time
        from types import SimpleNamespace
        from vraptor.api import VeloApiClient
        for level in ('info', 'debug'):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'progress.log'
                client = VeloApiClient(Path(directory) / 'api.yaml')
                client._stub = mock.Mock()
                client._stub.Query.return_value = [
                    SimpleNamespace(Response='[{"x":1}]', log='', part=0)]
                with operation_log.OperationLogger('query', options=operation_log.LogOptions(
                        explicit_path=path, level=level)) as logger:
                    stream = client.query_batches('SELECT * FROM scope()')
                    next(stream)
                    time.sleep(0.02)
                    list(stream)
                    logger.finalize(status='complete', exit_code=0)
                text = path.read_text()
                if level == 'debug':
                    import re
                    self.assertGreaterEqual(float(re.search(r'consumer_pause_ms=([\d.]+)', text)[1]), 15)
                    self.assertIn('first_batch_ms=', text)
                    self.assertIn('query_id=q-0001', text)
                else:
                    self.assertNotIn('consumer_pause_ms', text)
                    self.assertNotIn('first_batch_ms', text)

    def test_missing_identity_diagnostics_are_debug_only_and_bounded(self):
        import tempfile
        for level in ('info', 'debug'):
            with self.subTest(level=level), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'progress.log'
                selected = [{'ImagePath': f'c:\\private\\app{i}.exe',
                             'LaunchString': '', 'Signer': ''} for i in range(23)]
                api = mock.Mock()
                api.query_batches.return_value = iter([])
                with operation_log.OperationLogger('test', options=operation_log.LogOptions(
                        explicit_path=path, level=level)) as logger:
                    with self.assertRaisesRegex(RuntimeError, '23 missing'):
                        live.review_autoruns_suspicious_context_streaming(
                            api, hunt_id='H.test', artifact='Windows.Sysinternals.Autoruns',
                            profile={}, suspicious_rows=selected, state={})
                    logger.finalize(status='failed', exit_code=1)
                text = path.read_text()
                self.assertIn('error_code=autoruns_missing_identity', text)
                self.assertIn('missing_identities=23', text)
                self.assertNotIn('private', text)
                self.assertEqual(text.count('identity_reference='), 10 if level == 'debug' else 0)


if __name__ == '__main__':
    unittest.main()
