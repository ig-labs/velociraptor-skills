from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock

from vraptor.agent.codex_app_server import CodexAppServerClient
from vraptor.agent.codex_app_server import acquire_shared_codex_client
from vraptor.agent.codex_app_server import release_shared_codex_client


class FakeStdin:
    def __init__(self, stdout: asyncio.StreamReader):
        self.stdout = stdout
        self.messages = []

    def write(self, value: bytes) -> None:
        message = json.loads(value)
        self.messages.append(message)
        if message.get("method") == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"userAgent": "test"},
            }
            self.stdout.feed_data(json.dumps(response).encode() + b"\n")

    async def drain(self) -> None:
        return None


class FakeProcess:
    def __init__(self, *, returncode=None, protocol=False):
        self.returncode = returncode
        self.stdout = asyncio.StreamReader() if protocol else None
        self.stderr = asyncio.StreamReader() if protocol else None
        self.stdin = FakeStdin(self.stdout) if protocol else None
        if self.stderr is not None:
            self.stderr.feed_eof()

    async def wait(self) -> int:
        while self.returncode is None:
            await asyncio.sleep(0)
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 0
        if self.stdout is not None:
            self.stdout.feed_eof()

    def kill(self) -> None:
        self.terminate()


class CodexAppServerClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_notification_projection_drops_prompt_and_tool_payloads(self):
        client = CodexAppServerClient(connect_timeout=1)
        queue = client.subscribe("thread-1")

        client._publish_notification(
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {
                        "id": "turn-1",
                        "status": "completed",
                        "items": [
                            {
                                "type": "userMessage",
                                "id": "user-1",
                                "content": [{"text": "raw evidence"}],
                            },
                            {
                                "type": "reasoning",
                                "id": "reasoning-1",
                                "summary": ["private reasoning"],
                            },
                            {
                                "type": "commandExecution",
                                "id": "command-1",
                                "command": "sensitive command",
                            },
                            {
                                "type": "agentMessage",
                                "id": "message-1",
                                "phase": "final_answer",
                                "text": "safe output",
                            },
                        ],
                    },
                },
            }
        )

        projected = await queue.get()
        serialized = json.dumps(projected)
        self.assertNotIn("raw evidence", serialized)
        self.assertNotIn("private reasoning", serialized)
        self.assertNotIn("sensitive command", serialized)
        self.assertIn("safe output", serialized)
        self.assertIn("commandExecution", serialized)

    async def test_package_manager_install_falls_back_to_direct_app_server(self):
        daemon = FakeProcess(returncode=1)
        app_server = FakeProcess(protocol=True)
        with (
            mock.patch(
                "vraptor.agent.codex_app_server.shutil.which",
                return_value="/test/codex",
            ),
            mock.patch(
                "vraptor.agent.codex_app_server.asyncio.create_subprocess_exec",
                new=mock.AsyncMock(side_effect=[daemon, app_server]),
            ) as create_process,
        ):
            client = CodexAppServerClient(connect_timeout=1)
            await client.start()
            await client.close()

        self.assertEqual(
            create_process.call_args_list[1].args,
            ("/test/codex", "app-server"),
        )
        initialize = app_server.stdin.messages[0]
        self.assertTrue(initialize["params"]["capabilities"]["experimentalApi"])
        self.assertEqual(app_server.stdin.messages[1]["method"], "initialized")

    async def test_managed_install_uses_daemon_proxy(self):
        daemon = FakeProcess(returncode=0)
        proxy = FakeProcess(protocol=True)
        with (
            mock.patch(
                "vraptor.agent.codex_app_server.shutil.which",
                return_value="/test/codex",
            ),
            mock.patch(
                "vraptor.agent.codex_app_server.asyncio.create_subprocess_exec",
                new=mock.AsyncMock(side_effect=[daemon, proxy]),
            ) as create_process,
        ):
            client = CodexAppServerClient(connect_timeout=1)
            await client.start()
            await client.close()

        self.assertEqual(
            create_process.call_args_list[1].args,
            ("/test/codex", "app-server", "proxy"),
        )

    async def test_runners_share_one_client_until_last_release(self):
        first = await acquire_shared_codex_client(connect_timeout=1)
        second = await acquire_shared_codex_client(connect_timeout=1)
        self.assertIs(first, second)
        with mock.patch.object(first, "close", new=mock.AsyncMock()) as close:
            await release_shared_codex_client(first)
            close.assert_not_awaited()
            await release_shared_codex_client(second)
            close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
