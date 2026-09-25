"""Bounded multi-lane asyncio scheduler for transient DFIR analysis work."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import threading
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar


WorkItem = TypeVar("WorkItem")
WorkResult = TypeVar("WorkResult")


@dataclass(frozen=True)
class AnalysisLane(Generic[WorkItem]):
    lane_id: str
    items: Iterable[WorkItem]
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SchedulerStatus:
    produced: int = 0
    queued: int = 0
    active: int = 0
    completed: int = 0
    failed: int = 0
    abandoned: int = 0
    source_count: int = 0
    exhausted_source_count: int = 0
    production_credit_limit: int = 0
    production_credits_in_use: int = 0
    production_weight_limit: int = 0
    production_weight_in_use: int = 0
    work_queue_depth: int = 0
    result_queue_depth: int = 0
    stop_requested: bool = False

    @property
    def source_exhausted(self) -> bool:
        return self.source_count == self.exhausted_source_count


@dataclass(frozen=True)
class ScheduledResult(Generic[WorkItem, WorkResult]):
    sequence: int
    lane_id: str
    item: WorkItem
    result: WorkResult


@dataclass(frozen=True)
class _Envelope(Generic[WorkItem]):
    sequence: int
    lane_id: str
    item: WorkItem


@dataclass(frozen=True)
class _LaneDone:
    lane_id: str
    exhausted: bool


_WORKER_STOP = object()
_DISPATCHER_STOP = object()


@dataclass(frozen=True)
class _DynamicEnvelope(Generic[WorkItem, WorkResult]):
    sequence: int
    lane_id: str
    item: WorkItem
    execute: Callable[[WorkItem], Awaitable[WorkResult]]
    future: asyncio.Future[WorkResult]
    weight: int


def _single_exception(error: BaseException) -> BaseException:
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    return error


def _result_failed(result: object) -> bool:
    if (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[1], Mapping)
    ):
        status = str(result[1].get("status") or "")
    elif isinstance(result, Mapping):
        status = str(result.get("status") or "")
    else:
        status = str(getattr(result, "status", "") or "")
    return status.lower() in {"cancelled", "failed", "timeout"}


class AsyncAnalysisScheduler(Generic[WorkItem, WorkResult]):
    """Run synchronous evidence producers through bounded async model workers."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        prefetch: int = 1,
        lane_queue_size: int = 1,
        result_queue_size: int | None = None,
        on_status_change: Callable[[SchedulerStatus], None] | None = None,
    ) -> None:
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero")
        if prefetch < 0:
            raise ValueError("prefetch must be zero or greater")
        if lane_queue_size <= 0:
            raise ValueError("lane_queue_size must be greater than zero")
        if result_queue_size is not None and result_queue_size <= 0:
            raise ValueError("result_queue_size must be greater than zero")
        self.max_concurrency = max_concurrency
        self.prefetch = prefetch
        self.lane_queue_size = lane_queue_size
        self.result_queue_size = result_queue_size or max_concurrency
        self.on_status_change = on_status_change
        self._status = SchedulerStatus(
            production_credit_limit=max_concurrency + prefetch,
        )
        self._last_reported: SchedulerStatus | None = None

    @property
    def status(self) -> SchedulerStatus:
        return self._status

    def _update(self, **changes: Any) -> None:
        payload = {
            field_name: getattr(self._status, field_name)
            for field_name in self._status.__dataclass_fields__
        }
        payload.update(changes)
        self._status = SchedulerStatus(**payload)
        if self._status == self._last_reported:
            return
        self._last_reported = self._status
        if self.on_status_change is not None:
            self.on_status_change(self._status)

    async def run(
        self,
        lanes: Iterable[AnalysisLane[WorkItem]],
        *,
        execute: Callable[[WorkItem], Awaitable[WorkResult]],
        on_result: Callable[[ScheduledResult[WorkItem, WorkResult]], Any] | None = None,
        stop_when: Callable[[WorkResult], bool] | None = None,
        exception_result: Callable[[WorkItem, BaseException], WorkResult] | None = None,
        retain_results: bool = True,
    ) -> list[ScheduledResult[WorkItem, WorkResult]]:
        lane_list = list(lanes)
        lane_ids = [lane.lane_id for lane in lane_list]
        if len(lane_ids) != len(set(lane_ids)):
            raise ValueError("analysis lane ids must be unique")
        if not lane_list:
            self._update(source_count=0, exhausted_source_count=0)
            return []

        loop = asyncio.get_running_loop()
        stop_async = asyncio.Event()
        stop_thread = threading.Event()
        credits = asyncio.Semaphore(self.max_concurrency + self.prefetch)
        lane_queues = {
            lane.lane_id: asyncio.Queue(maxsize=self.lane_queue_size)
            for lane in lane_list
        }
        ready_lanes: asyncio.Queue[str | _LaneDone] = asyncio.Queue()
        work_queue: asyncio.Queue[_Envelope[WorkItem] | object] = asyncio.Queue(
            maxsize=max(1, self.prefetch)
        )
        result_queue: asyncio.Queue[
            ScheduledResult[WorkItem, WorkResult] | object
        ] = asyncio.Queue(maxsize=self.result_queue_size)
        sequence = 0
        sequence_lock = threading.Lock()
        producer_context = contextvars.copy_context()
        self._update(source_count=len(lane_list))

        def next_sequence() -> int:
            nonlocal sequence
            with sequence_lock:
                value = sequence
                sequence += 1
                return value

        def wait_threadsafe(
            future: concurrent.futures.Future[Any],
            *,
            respect_stop: bool = True,
        ) -> Any:
            while True:
                try:
                    return future.result(timeout=0.1)
                except concurrent.futures.TimeoutError:
                    if respect_stop and stop_thread.is_set():
                        future.cancel()
                        raise RuntimeError("analysis producer stopped")

        def release_credit() -> None:
            credits.release()
            self._update(
                production_credits_in_use=max(
                    0, self._status.production_credits_in_use - 1
                )
            )

        async def acquire_credit() -> None:
            await credits.acquire()
            self._update(
                production_credits_in_use=self._status.production_credits_in_use + 1
            )

        async def enqueue_envelope(envelope: _Envelope[WorkItem]) -> None:
            await lane_queues[envelope.lane_id].put(envelope)
            self._update(
                produced=self._status.produced + 1,
                queued=self._status.queued + 1,
            )
            await ready_lanes.put(envelope.lane_id)

        def producer(lane: AnalysisLane[WorkItem]) -> None:
            iterator = iter(lane.items)
            exhausted = False
            try:
                while not stop_thread.is_set():
                    acquired = False
                    try:
                        wait_threadsafe(
                            asyncio.run_coroutine_threadsafe(acquire_credit(), loop)
                        )
                        acquired = True
                        if stop_thread.is_set():
                            raise RuntimeError("analysis producer stopped")
                        try:
                            item = next(iterator)
                        except StopIteration:
                            exhausted = True
                            loop.call_soon_threadsafe(release_credit)
                            acquired = False
                            break
                        envelope = _Envelope(next_sequence(), lane.lane_id, item)
                        wait_threadsafe(
                            asyncio.run_coroutine_threadsafe(
                                enqueue_envelope(envelope), loop
                            ),
                            respect_stop=False,
                        )
                        acquired = False
                    except RuntimeError:
                        if acquired:
                            loop.call_soon_threadsafe(release_credit)
                        if stop_thread.is_set():
                            break
                        raise
            finally:
                close = getattr(iterator, "close", None)
                if callable(close):
                    close()
                try:
                    wait_threadsafe(
                        asyncio.run_coroutine_threadsafe(
                            ready_lanes.put(_LaneDone(lane.lane_id, exhausted)), loop
                        ),
                        respect_stop=False,
                    )
                except RuntimeError:
                    pass

        async def dispatcher() -> None:
            done_lanes: set[str] = set()
            while len(done_lanes) < len(lane_list):
                notice = await ready_lanes.get()
                try:
                    if isinstance(notice, _LaneDone):
                        done_lanes.add(notice.lane_id)
                        self._update(
                            exhausted_source_count=(
                                self._status.exhausted_source_count
                                + int(notice.exhausted)
                            )
                        )
                        continue
                    if stop_async.is_set():
                        envelope = await lane_queues[notice].get()
                        lane_queues[notice].task_done()
                        self._update(
                            abandoned=self._status.abandoned + 1,
                            queued=max(0, self._status.queued - 1),
                            production_credits_in_use=max(
                                0, self._status.production_credits_in_use - 1
                            ),
                        )
                        credits.release()
                        continue
                    envelope = await lane_queues[notice].get()
                    lane_queues[notice].task_done()
                    await work_queue.put(envelope)
                    self._update(work_queue_depth=work_queue.qsize())
                finally:
                    ready_lanes.task_done()
            for _ in range(self.max_concurrency):
                await work_queue.put(_WORKER_STOP)

        async def worker() -> None:
            while True:
                value = await work_queue.get()
                try:
                    self._update(work_queue_depth=work_queue.qsize())
                    if value is _WORKER_STOP:
                        return
                    envelope = value
                    self._update(
                        queued=max(0, self._status.queued - 1),
                        active=self._status.active + 1,
                    )
                    try:
                        result = await execute(envelope.item)
                    except asyncio.CancelledError:
                        raise
                    except BaseException as exc:
                        if exception_result is None:
                            raise
                        result = exception_result(envelope.item, exc)
                    await result_queue.put(
                        ScheduledResult(
                            sequence=envelope.sequence,
                            lane_id=envelope.lane_id,
                            item=envelope.item,
                            result=result,
                        )
                    )
                    self._update(result_queue_depth=result_queue.qsize())
                finally:
                    work_queue.task_done()

        async def finish_worker() -> None:
            try:
                await worker()
            finally:
                await result_queue.put(_WORKER_STOP)

        async def run_producer(lane: AnalysisLane[WorkItem]) -> None:
            await asyncio.to_thread(producer_context.copy().run, producer, lane)

        collected: list[ScheduledResult[WorkItem, WorkResult]] = []
        worker_done = 0
        try:
            async with asyncio.TaskGroup() as group:
                for lane in lane_list:
                    group.create_task(run_producer(lane))
                group.create_task(dispatcher())
                for _ in range(self.max_concurrency):
                    group.create_task(finish_worker())

                while worker_done < self.max_concurrency:
                    value = await result_queue.get()
                    try:
                        self._update(result_queue_depth=result_queue.qsize())
                        if value is _WORKER_STOP:
                            worker_done += 1
                            continue
                        scheduled = value
                        self._update(
                            active=max(0, self._status.active - 1),
                            completed=self._status.completed + 1,
                            failed=(
                                self._status.failed
                                + int(_result_failed(scheduled.result))
                            ),
                            production_credits_in_use=max(
                                0, self._status.production_credits_in_use - 1
                            ),
                        )
                        credits.release()
                        if retain_results:
                            collected.append(scheduled)
                        if on_result is not None:
                            callback_result = on_result(scheduled)
                            if asyncio.iscoroutine(callback_result):
                                await callback_result
                        if stop_when is not None and stop_when(scheduled.result):
                            stop_async.set()
                            stop_thread.set()
                            self._update(stop_requested=True)
                    finally:
                        result_queue.task_done()
        except BaseExceptionGroup as exc:
            raise _single_exception(exc)
        finally:
            stop_async.set()
            stop_thread.set()

        self._update(
            active=0,
            queued=0,
            work_queue_depth=0,
            result_queue_depth=0,
        )
        return collected


class DynamicAnalysisQueue(Generic[WorkItem, WorkResult]):
    """One scope-wide async worker queue with dynamically registered lanes."""

    def __init__(
        self,
        *,
        max_concurrency: int,
        prefetch: int = 1,
        lane_queue_size: int = 1,
        on_status_change: Callable[[SchedulerStatus], None] | None = None,
        max_inflight_weight: int | None = None,
    ) -> None:
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero")
        if prefetch < 0:
            raise ValueError("prefetch must be zero or greater")
        if lane_queue_size <= 0:
            raise ValueError("lane_queue_size must be greater than zero")
        if max_inflight_weight is not None and max_inflight_weight <= 0:
            raise ValueError("max_inflight_weight must be greater than zero")
        self.max_concurrency = max_concurrency
        self.prefetch = prefetch
        self.lane_queue_size = lane_queue_size
        self.on_status_change = on_status_change
        self.max_inflight_weight = max_inflight_weight
        self._status = SchedulerStatus(
            production_credit_limit=max_concurrency + prefetch,
            production_weight_limit=int(max_inflight_weight or 0),
        )
        self._last_reported: SchedulerStatus | None = None
        self._credits = asyncio.Semaphore(max_concurrency + prefetch)
        self._weight_condition = asyncio.Condition()
        self._weight_in_use = 0
        self._lane_queues: dict[
            str, asyncio.Queue[_DynamicEnvelope[WorkItem, WorkResult]]
        ] = {}
        self._ready_lanes: asyncio.Queue[str | object] = asyncio.Queue()
        self._work_queue: asyncio.Queue[
            _DynamicEnvelope[WorkItem, WorkResult] | object
        ] = asyncio.Queue(maxsize=max(1, prefetch))
        self._tasks: list[asyncio.Task[Any]] = []
        self._pending = 0
        self._pending_condition = asyncio.Condition()
        self._sequence = 0
        self._started = False
        self._closing = False

    @property
    def status(self) -> SchedulerStatus:
        return self._status

    def _update(self, **changes: Any) -> None:
        payload = {
            field_name: getattr(self._status, field_name)
            for field_name in self._status.__dataclass_fields__
        }
        payload.update(changes)
        self._status = SchedulerStatus(**payload)
        if self._status == self._last_reported:
            return
        self._last_reported = self._status
        if self.on_status_change is not None:
            self.on_status_change(self._status)

    async def start(self) -> None:
        if self._started:
            return
        if self._closing:
            raise RuntimeError("analysis queue is closing")
        self._started = True
        self._tasks = [
            asyncio.create_task(self._dispatcher(), name="analysis-dispatcher"),
            *[
                asyncio.create_task(
                    self._worker(),
                    name=f"analysis-worker-{index + 1}",
                )
                for index in range(self.max_concurrency)
            ],
        ]

    async def submit(
        self,
        lane_id: str,
        item: WorkItem,
        *,
        execute: Callable[[WorkItem], Awaitable[WorkResult]],
        weight: int = 1,
    ) -> WorkResult:
        future = await self.enqueue(lane_id, item, execute=execute, weight=weight)
        try:
            return await future
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def enqueue(
        self,
        lane_id: str,
        item: WorkItem,
        *,
        execute: Callable[[WorkItem], Awaitable[WorkResult]],
        weight: int = 1,
    ) -> asyncio.Future[WorkResult]:
        """Acquire production credit and enqueue work without awaiting its result."""
        if not lane_id.strip():
            raise ValueError("analysis lane id cannot be empty")
        await self.start()
        if self._closing:
            raise RuntimeError("analysis queue is closing")
        await self._credits.acquire()
        resolved_weight = max(1, int(weight))
        try:
            if self.max_inflight_weight is not None:
                async with self._weight_condition:
                    await self._weight_condition.wait_for(
                        lambda: self._weight_in_use == 0
                        or self._weight_in_use + resolved_weight
                        <= self.max_inflight_weight
                    )
                    self._weight_in_use += resolved_weight
        except BaseException:
            self._credits.release()
            raise
        if self._closing:
            self._credits.release()
            if self.max_inflight_weight is not None:
                async with self._weight_condition:
                    self._weight_in_use = max(
                        0, self._weight_in_use - resolved_weight
                    )
                    self._weight_condition.notify_all()
            raise RuntimeError("analysis queue is closing")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[WorkResult] = loop.create_future()
        envelope = _DynamicEnvelope(
            sequence=self._sequence,
            lane_id=lane_id,
            item=item,
            execute=execute,
            future=future,
            weight=resolved_weight,
        )
        self._sequence += 1
        lane_queue = self._lane_queues.setdefault(
            lane_id,
            asyncio.Queue(maxsize=self.lane_queue_size),
        )
        async with self._pending_condition:
            self._pending += 1
        self._update(
            produced=self._status.produced + 1,
            queued=self._status.queued + 1,
            source_count=len(self._lane_queues),
            production_credits_in_use=(
                self._status.production_credits_in_use + 1
            ),
            production_weight_in_use=self._weight_in_use,
        )
        try:
            await lane_queue.put(envelope)
            await self._ready_lanes.put(lane_id)
            return future
        except BaseException:
            async with self._pending_condition:
                self._pending -= 1
                self._pending_condition.notify_all()
            self._credits.release()
            if self.max_inflight_weight is not None:
                async with self._weight_condition:
                    self._weight_in_use = max(0, self._weight_in_use - resolved_weight)
                    self._weight_condition.notify_all()
            self._update(
                queued=max(0, self._status.queued - 1),
                abandoned=self._status.abandoned + 1,
                production_credits_in_use=max(
                    0, self._status.production_credits_in_use - 1
                ),
                production_weight_in_use=self._weight_in_use,
            )
            raise

    async def join(self) -> None:
        """Wait until every accepted item reaches a terminal worker result."""
        async with self._pending_condition:
            await self._pending_condition.wait_for(lambda: self._pending == 0)

    def request_stop(self) -> None:
        self._update(stop_requested=True)

    def mark_sources_exhausted(self) -> None:
        self._update(exhausted_source_count=len(self._lane_queues))

    async def _dispatcher(self) -> None:
        while True:
            notice = await self._ready_lanes.get()
            try:
                if notice is _DISPATCHER_STOP:
                    return
                lane_id = str(notice)
                envelope = await self._lane_queues[lane_id].get()
                self._lane_queues[lane_id].task_done()
                await self._work_queue.put(envelope)
                self._update(work_queue_depth=self._work_queue.qsize())
            finally:
                self._ready_lanes.task_done()

    async def _worker(self) -> None:
        while True:
            value = await self._work_queue.get()
            try:
                self._update(work_queue_depth=self._work_queue.qsize())
                if value is _WORKER_STOP:
                    return
                envelope = value
                if envelope.future.cancelled():
                    self._credits.release()
                    if self.max_inflight_weight is not None:
                        async with self._weight_condition:
                            self._weight_in_use = max(
                                0, self._weight_in_use - envelope.weight
                            )
                            self._weight_condition.notify_all()
                    self._update(
                        queued=max(0, self._status.queued - 1),
                        abandoned=self._status.abandoned + 1,
                        production_credits_in_use=max(
                            0, self._status.production_credits_in_use - 1
                        ),
                        production_weight_in_use=self._weight_in_use,
                    )
                    async with self._pending_condition:
                        self._pending -= 1
                        self._pending_condition.notify_all()
                    continue
                self._update(
                    queued=max(0, self._status.queued - 1),
                    active=self._status.active + 1,
                )
                failed = False
                try:
                    result = await envelope.execute(envelope.item)
                except asyncio.CancelledError:
                    failed = True
                    if not envelope.future.done():
                        envelope.future.cancel()
                except Exception as exc:
                    failed = True
                    if not envelope.future.done():
                        # Consumers may clear exception frames (e.g. unittest).
                        # Do not expose this still-running worker's frame, which
                        # Python 3.12 can close while it waits for the next item.
                        # Retain the executor's traceback and exception identity.
                        if exc.__traceback__ is not None:
                            exc = exc.with_traceback(exc.__traceback__.tb_next)
                        envelope.future.set_exception(exc)
                else:
                    failed = _result_failed(result)
                    if not envelope.future.done():
                        envelope.future.set_result(result)
                finally:
                    self._credits.release()
                    if self.max_inflight_weight is not None:
                        async with self._weight_condition:
                            self._weight_in_use = max(
                                0, self._weight_in_use - envelope.weight
                            )
                            self._weight_condition.notify_all()
                    self._update(
                        active=max(0, self._status.active - 1),
                        completed=self._status.completed + 1,
                        failed=self._status.failed + int(failed),
                        production_credits_in_use=max(
                            0, self._status.production_credits_in_use - 1
                        ),
                        production_weight_in_use=self._weight_in_use,
                    )
                    async with self._pending_condition:
                        self._pending -= 1
                        self._pending_condition.notify_all()
            finally:
                self._work_queue.task_done()

    async def close(self) -> None:
        if self._closing:
            if self._tasks:
                await asyncio.gather(*self._tasks)
            return
        self._closing = True
        if not self._started:
            return
        await self.join()
        await self._ready_lanes.put(_DISPATCHER_STOP)
        await self._tasks[0]
        for _ in range(self.max_concurrency):
            await self._work_queue.put(_WORKER_STOP)
        await asyncio.gather(*self._tasks[1:])
        self._update(
            active=0,
            queued=0,
            exhausted_source_count=len(self._lane_queues),
            work_queue_depth=0,
            result_queue_depth=0,
        )

    async def __aenter__(self) -> "DynamicAnalysisQueue[WorkItem, WorkResult]":
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()
