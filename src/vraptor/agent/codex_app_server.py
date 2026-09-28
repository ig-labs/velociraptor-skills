"""Bounded JSON-RPC client for the local Codex app-server daemon.

The client never reads Codex credential files. Authentication remains owned by
the installed Codex process; this module prefers its daemon/proxy and falls back
to one version-matched direct app-server process when no managed daemon exists.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import weakref
from dataclasses import dataclass
from typing import Any, Mapping


_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
_EVENT_QUEUE_SIZE = 256
_SHARED_CLIENTS: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, "_SharedClient"
] = weakref.WeakKeyDictionary()


class CodexAppServerError(RuntimeError):
    """Safe JSON-RPC failure without provider response content."""

    def __init__(self, code: int, message: str = "Codex app-server request failed"):
        super().__init__(message)
        self.code = code


@dataclass
class _SharedClient:
    client: "CodexAppServerClient"
    references: int = 0


class CodexAppServerClient:
    """One multiplexed connection to the shared local app-server daemon."""

    def __init__(self, *, connect_timeout: float = 10.0):
        self.connect_timeout = connect_timeout
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._start_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._next_id = 1
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._closed = False
        self._initialized = False

    async def start(self) -> None:
        if self._initialized:
            return
        async with self._start_lock:
            if self._initialized:
                return
            if self._closed:
                raise CodexAppServerError(-32000, "Codex app-server client is closed")
            executable = shutil.which("codex")
            if not executable:
                raise CodexAppServerError(
                    -32000, "Codex executable is required for codex_app_server transport"
                )
            daemon = await asyncio.create_subprocess_exec(
                executable,
                "app-server",
                "daemon",
                "start",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                daemon_code = await asyncio.wait_for(
                    daemon.wait(), timeout=self.connect_timeout
                )
            except TimeoutError as exc:
                daemon.kill()
                await daemon.wait()
                raise CodexAppServerError(
                    -32000, "Timed out starting Codex app-server daemon"
                ) from exc
            app_server_args = (
                ("app-server", "proxy")
                if daemon_code == 0
                else ("app-server",)
            )
            process = await asyncio.create_subprocess_exec(
                executable,
                *app_server_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=_MAX_MESSAGE_BYTES + 1,
            )
            self._process = process
            self._reader_task = asyncio.create_task(self._read_messages())
            self._stderr_task = asyncio.create_task(self._discard_stderr())
            try:
                await asyncio.wait_for(
                    self.request(
                        "initialize",
                        {
                            "clientInfo": {
                                "name": "ai_skills_analyst",
                                "title": "AI Skills Analyst Harness",
                                "version": "1",
                            },
                            "capabilities": {"experimentalApi": True},
                        },
                        start=False,
                    ),
                    timeout=self.connect_timeout,
                )
                await self.notify("initialized", {}, start=False)
                self._initialized = True
            except BaseException:
                await self.close()
                raise

    async def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        start: bool = True,
    ) -> Any:
        if start:
            await self.start()
        process = self._process
        if process is None or process.stdin is None:
            raise CodexAppServerError(-32000, "Codex app-server is unavailable")
        request_id = self._next_id
        self._next_id += 1
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self._send(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
            return await future
        finally:
            self._pending.pop(request_id, None)

    async def notify(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        start: bool = True,
    ) -> None:
        if start:
            await self.start()
        await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def subscribe(self, thread_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=_EVENT_QUEUE_SIZE
        )
        self._subscribers.setdefault(thread_id, set()).add(queue)
        return queue

    def unsubscribe(
        self, thread_id: str, queue: asyncio.Queue[dict[str, Any]]
    ) -> None:
        subscribers = self._subscribers.get(thread_id)
        if subscribers is None:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(thread_id, None)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._initialized = False
        process = self._process
        self._process = None
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except TimeoutError:
                process.kill()
                await process.wait()
        current = asyncio.current_task()
        for task in (self._reader_task, self._stderr_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        for task in (self._reader_task, self._stderr_task):
            if task is not None and task is not current:
                try:
                    await task
                except (asyncio.CancelledError, CodexAppServerError):
                    pass
        self._fail_pending(
            CodexAppServerError(-32000, "Codex app-server connection closed")
        )
        self._subscribers.clear()

    async def _send(self, payload: Mapping[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None or process.returncode is not None:
            raise CodexAppServerError(-32000, "Codex app-server is unavailable")
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > _MAX_MESSAGE_BYTES:
            raise CodexAppServerError(-32602, "Codex app-server message is too large")
        async with self._write_lock:
            process.stdin.write(encoded)
            try:
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise CodexAppServerError(
                    -32000, "Codex app-server connection closed"
                ) from exc

    async def _read_messages(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    raise CodexAppServerError(
                        -32000, "Codex app-server connection closed"
                    )
                if len(line) > _MAX_MESSAGE_BYTES:
                    raise CodexAppServerError(
                        -32000, "Codex app-server message exceeded the safety bound"
                    )
                try:
                    message = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CodexAppServerError(
                        -32700, "Codex app-server returned invalid JSON"
                    ) from exc
                if not isinstance(message, dict):
                    continue
                if "method" in message and "id" in message:
                    await self._reject_server_request(message)
                elif "method" in message:
                    self._publish_notification(message)
                elif "id" in message:
                    self._resolve_response(message)
        except asyncio.CancelledError:
            raise
        except CodexAppServerError as exc:
            self._fail_pending(exc)
            self._publish_connection_failure()

    async def _discard_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        try:
            while await process.stderr.read(8192):
                pass
        except asyncio.CancelledError:
            raise

    def _resolve_response(self, message: Mapping[str, Any]) -> None:
        request_id = message.get("id")
        if not isinstance(request_id, int):
            return
        future = self._pending.get(request_id)
        if future is None or future.done():
            return
        error = message.get("error")
        if isinstance(error, Mapping):
            code = error.get("code")
            future.set_exception(
                CodexAppServerError(
                    int(code) if isinstance(code, (int, float)) else -32000
                )
            )
        else:
            future.set_result(message.get("result"))

    async def _reject_server_request(self, message: Mapping[str, Any]) -> None:
        await self._send(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {
                    "code": -32601,
                    "message": "Analyst harness rejects interactive requests",
                },
            }
        )
        params = message.get("params")
        if isinstance(params, Mapping):
            thread_id = params.get("threadId")
            if isinstance(thread_id, str):
                self._publish(
                    thread_id,
                    {
                        "method": "client/request/rejected",
                        "params": {
                            "threadId": thread_id,
                            "turnId": params.get("turnId"),
                            "requestMethod": str(message.get("method", "")),
                        },
                    },
                )

    def _publish_notification(self, message: Mapping[str, Any]) -> None:
        params = message.get("params")
        if not isinstance(params, Mapping):
            return
        thread_id = params.get("threadId")
        if not isinstance(thread_id, str):
            return
        method = str(message.get("method", ""))
        if method not in {
            "item/started",
            "item/completed",
            "thread/tokenUsage/updated",
            "turn/completed",
        }:
            return
        safe_params: dict[str, Any] = {"threadId": thread_id}
        turn_id = params.get("turnId")
        if isinstance(turn_id, str):
            safe_params["turnId"] = turn_id
        if method in {"item/started", "item/completed"}:
            safe_params["item"] = _safe_item(params.get("item"))
        elif method == "thread/tokenUsage/updated":
            safe_params["tokenUsage"] = params.get("tokenUsage", {})
        elif method == "turn/completed":
            turn = params.get("turn")
            if isinstance(turn, Mapping):
                error = turn.get("error")
                safe_error = (
                    {"codexErrorInfo": error.get("codexErrorInfo")}
                    if isinstance(error, Mapping)
                    else None
                )
                safe_params["turn"] = {
                    "id": turn.get("id"),
                    "status": turn.get("status"),
                    "error": safe_error,
                    "items": [
                        safe_item
                        for item in turn.get("items", []) or []
                        if (safe_item := _safe_item(item)).get("type")
                        in {"agentMessage", *CODEX_PROHIBITED_ITEM_TYPES}
                    ],
                }
        self._publish(thread_id, {"method": method, "params": safe_params})

    def _publish(self, thread_id: str, message: dict[str, Any]) -> None:
        for queue in tuple(self._subscribers.get(thread_id, ())):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                failure = {
                    "method": "client/queue/overflow",
                    "params": {"threadId": thread_id},
                }
                while not queue.empty():
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                queue.put_nowait(failure)

    def _publish_connection_failure(self) -> None:
        for thread_id in tuple(self._subscribers):
            self._publish(
                thread_id,
                {
                    "method": "client/connection/closed",
                    "params": {"threadId": thread_id},
                },
            )

    def _fail_pending(self, error: CodexAppServerError) -> None:
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)


CODEX_PROHIBITED_ITEM_TYPES = frozenset(
    {
        "collabAgentToolCall",
        "commandExecution",
        "dynamicToolCall",
        "fileChange",
        "imageGeneration",
        "imageView",
        "mcpToolCall",
        "sleep",
        "subAgentActivity",
        "webSearch",
    }
)


def _safe_item(value: object) -> dict[str, Any]:
    """Retain only item identity and final assistant text from notifications."""

    if not isinstance(value, Mapping):
        return {}
    item_type = str(value.get("type", ""))
    item = {"type": item_type, "id": str(value.get("id", ""))}
    if item_type == "agentMessage":
        item["phase"] = str(value.get("phase", ""))
        item["text"] = str(value.get("text", ""))
    return item


async def acquire_shared_codex_client(
    *, connect_timeout: float
) -> CodexAppServerClient:
    """Acquire the one proxy connection shared by runners on this event loop."""

    loop = asyncio.get_running_loop()
    shared = _SHARED_CLIENTS.get(loop)
    if shared is None:
        shared = _SharedClient(CodexAppServerClient(connect_timeout=connect_timeout))
        _SHARED_CLIENTS[loop] = shared
    shared.references += 1
    return shared.client


async def release_shared_codex_client(client: CodexAppServerClient) -> None:
    loop = asyncio.get_running_loop()
    shared = _SHARED_CLIENTS.get(loop)
    if shared is None or shared.client is not client:
        return
    shared.references = max(0, shared.references - 1)
    if shared.references:
        return
    _SHARED_CLIENTS.pop(loop, None)
    await client.close()


async def invalidate_shared_codex_client(client: CodexAppServerClient) -> None:
    """Discard a failed shared connection so a retry creates a fresh proxy."""

    loop = asyncio.get_running_loop()
    shared = _SHARED_CLIENTS.get(loop)
    if shared is not None and shared.client is client:
        _SHARED_CLIENTS.pop(loop, None)
    await client.close()
