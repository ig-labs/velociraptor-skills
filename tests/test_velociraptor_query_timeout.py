"""CLI and transport coverage for the optional live-analysis query ceiling."""
import contextlib
import io
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from vraptor.hunt import command as hunt_workflow
from vraptor.analyze import command as collection_analysis_cli
from vraptor.api import VeloApiClient


class QueryTimeoutTest(unittest.TestCase):
    def test_parser_accepts_default_zero_and_positive_timeout(self):
        base = ['analyze', '--id', 'IR1', '--hunt-id', 'H.test']
        for extra, expected in (([], 0), (['--query-timeout-seconds', '0'], 0),
                                (['--query-timeout-seconds', '1800'], 1800)):
            with self.subTest(extra=extra):
                args = hunt_workflow.parse_args(base + extra)
                self.assertEqual(args.query_timeout_seconds, expected)

    def test_parser_rejects_negative_fractional_and_snapshot_timeout(self):
        for args in (
            ['--hunt-id', 'H.test', '--query-timeout-seconds', '-1'],
            ['--hunt-id', 'H.test', '--query-timeout-seconds', '1.5'],
            ['--snapshot', 'snapshot.json', '--query-timeout-seconds', '0'],
        ):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    hunt_workflow.parse_args(['analyze', '--id', 'IR1'] + args)

    def test_ceiling_reaches_server_and_grpc_for_all_query_entrypoints(self):
        for cap, explicit, expected in ((0, 0, 0), (1800, 0, 1800),
                                        (1800, 30, 30), (30, 1800, 30)):
            for method in ('query', 'query_batches', 'query_batches_with_metadata'):
                with self.subTest(cap=cap, explicit=explicit, method=method):
                    client = VeloApiClient(Path('unused.yaml'), query_timeout_seconds=cap)
                    client._stub = mock.Mock()
                    client._stub.Query.return_value = iter([
                        SimpleNamespace(Response=json.dumps([{'ok': True}]), log='', part=0)])
                    list(getattr(client, method)('SELECT * FROM scope()', timeout=explicit))
                    call = client._stub.Query.call_args
                    self.assertEqual(call.args[0].timeout, expected)
                    self.assertEqual(call.kwargs.get('timeout', 0), expected)

    def test_analyze_forwards_ceiling_to_its_client(self):
        import tempfile
        args = hunt_workflow.parse_args([
            'analyze', '--id', 'IR1', '--hunt-id', 'H.test',
            '--query-timeout-seconds', '1800'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api_path = root / 'api.yaml'
            api_path.write_text('fixture')
            with (
                mock.patch.object(hunt_workflow, 'resolve_api_client', return_value=api_path),
                mock.patch.object(hunt_workflow, 'resolved_hunts_root', return_value=root),
                mock.patch.object(hunt_workflow, 'resolve_case_root', return_value=root),
                mock.patch.object(hunt_workflow, 'VeloApiClient', side_effect=RuntimeError('stop-before-connect')) as client,
            ):
                with self.assertRaisesRegex(RuntimeError, 'stop-before-connect'):
                    hunt_workflow.command_analyze(args)
            self.assertEqual(client.call_args.kwargs['query_timeout_seconds'], 1800)

    def test_default_client_remains_unlimited(self):
        client = VeloApiClient(Path('unused.yaml'))
        self.assertEqual(client.query_timeout_seconds, 0)
        for invalid in (-1, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                VeloApiClient(Path('unused.yaml'), query_timeout_seconds=invalid)


class HostQueryTimeoutTest(unittest.TestCase):
    def test_host_parser_keeps_query_and_collection_timeouts_separate(self):
        base = ['--id', 'IR1', '--client-id', 'C.test']
        parser = collection_analysis_cli.build_parser()
        defaults = parser.parse_args(base)
        self.assertEqual(defaults.query_timeout_seconds, 0)
        args = parser.parse_args(base + [
            '--query-timeout-seconds', '1800', '--flow-timeout-seconds', '120',
            '--poll-timeout-seconds', '3600', '--timeout-seconds', '60'])
        self.assertEqual(args.query_timeout_seconds, 1800)
        self.assertEqual(args.flow_timeout_seconds, 120)
        self.assertEqual(args.poll_timeout_seconds, 3600)
        self.assertEqual(args.timeout_seconds, 60)
        saved = parser.parse_args(base + ['--request-id', 'saved', '--query-timeout-seconds', '90'])
        self.assertFalse(collection_analysis_cli._target_arguments_present(saved))
        for invalid in ('-1', '1.5'):
            with self.subTest(invalid=invalid), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(base + ['--query-timeout-seconds', invalid])

    def test_host_command_passes_configured_client_to_analysis(self):
        import asyncio
        import tempfile
        for cap in (0, 1800):
            with self.subTest(cap=cap), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                context = SimpleNamespace(
                    engagement_id='IR1', server_profile='test', case_root=root,
                    api_client=root / 'api.yaml', state_path=root / 'engagement.json')
                with (
                    mock.patch.object(collection_analysis_cli.engagement_context, 'resolve', return_value=context),
                    mock.patch.object(collection_analysis_cli.operation_log, 'bind_case'),
                    mock.patch.object(collection_analysis_cli.collection, 'CASE_ROOT', root),
                    mock.patch.object(collection_analysis_cli, 'VeloApiClient') as client,
                    mock.patch.object(collection_analysis_cli, 'run_analysis_async', new_callable=mock.AsyncMock,
                                      return_value={'status': 'complete'}) as analyze,
                    mock.patch.object(collection_analysis_cli.analysis_cli_output, 'emit_final_result'),
                ):
                    result = asyncio.run(collection_analysis_cli.async_main([
                        '--id', 'IR1', '--client-id', 'C.test', '--no-progress',
                        '--query-timeout-seconds', str(cap)]))
                    self.assertEqual(result, 0)
                    self.assertEqual(client.call_args.kwargs['query_timeout_seconds'], cap)
                    self.assertIs(analyze.call_args.args[0], client.return_value.__enter__.return_value)


if __name__ == '__main__':
    unittest.main()
