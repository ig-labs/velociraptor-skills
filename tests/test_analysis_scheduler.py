from __future__ import annotations

import asyncio
import threading
import unittest

from vraptor.analyze.scheduler import AnalysisLane
from vraptor.analyze.scheduler import AsyncAnalysisScheduler
from vraptor.analyze.scheduler import DynamicAnalysisQueue


class AsyncAnalysisSchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_multiple_lanes_with_bounded_concurrency(self):
        active = 0
        maximum_active = 0
        lock = asyncio.Lock()
        statuses = []

        async def execute(item: int) -> dict[str, object]:
            nonlocal active, maximum_active
            async with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.001)
            async with lock:
                active -= 1
            return {"status": "accepted", "value": item}

        scheduler = AsyncAnalysisScheduler[int, dict[str, object]](
            max_concurrency=2,
            on_status_change=statuses.append,
        )
        results = await scheduler.run(
            [
                AnalysisLane("execution", range(3)),
                AnalysisLane("network", range(3, 6)),
            ],
            execute=execute,
        )

        self.assertEqual(sorted(result.result["value"] for result in results), list(range(6)))
        self.assertLessEqual(maximum_active, 2)
        self.assertEqual(scheduler.status.produced, 6)
        self.assertEqual(scheduler.status.completed, 6)
        self.assertEqual(scheduler.status.failed, 0)
        self.assertEqual(scheduler.status.abandoned, 0)
        self.assertEqual(scheduler.status.production_credits_in_use, 0)
        self.assertTrue(scheduler.status.source_exhausted)
        self.assertTrue(statuses)

    async def test_production_credits_bound_constructed_work(self):
        constructed: list[int] = []
        release = asyncio.Event()

        def items():
            for value in range(20):
                constructed.append(value)
                yield value

        async def execute(item: int) -> dict[str, object]:
            await release.wait()
            return {"status": "accepted", "value": item}

        scheduler = AsyncAnalysisScheduler[int, dict[str, object]](
            max_concurrency=2,
            prefetch=1,
        )
        task = asyncio.create_task(
            scheduler.run([AnalysisLane("execution", items())], execute=execute)
        )
        for _ in range(100):
            if scheduler.status.active == 2:
                break
            await asyncio.sleep(0.001)
        self.assertEqual(scheduler.status.active, 2)
        self.assertLessEqual(len(constructed), 3)
        self.assertLessEqual(scheduler.status.production_credits_in_use, 3)
        release.set()
        await task

    async def test_terminal_failure_stops_production_without_losing_accounting(self):
        release_failure = asyncio.Event()

        async def execute(item: int) -> dict[str, object]:
            if item == 0:
                release_failure.set()
                return {"status": "failed", "value": item}
            await asyncio.sleep(0.001)
            return {"status": "accepted", "value": item}

        scheduler = AsyncAnalysisScheduler[int, dict[str, object]](
            max_concurrency=2,
            prefetch=1,
        )
        results = await scheduler.run(
            [AnalysisLane("execution", range(100))],
            execute=execute,
            stop_when=lambda result: result["status"] == "failed",
        )

        self.assertTrue(release_failure.is_set())
        self.assertTrue(scheduler.status.stop_requested)
        self.assertEqual(scheduler.status.failed, 1)
        self.assertEqual(
            scheduler.status.produced,
            scheduler.status.completed + scheduler.status.abandoned,
        )
        self.assertEqual(scheduler.status.production_credits_in_use, 0)
        self.assertTrue(any(result.result["status"] == "failed" for result in results))

    async def test_each_source_iterator_stays_on_one_thread(self):
        threads: dict[str, set[int]] = {"execution": set(), "network": set()}

        def items(lane_id: str):
            for value in range(3):
                threads[lane_id].add(threading.get_ident())
                yield value

        async def execute(item: int) -> dict[str, object]:
            return {"status": "accepted", "value": item}

        scheduler = AsyncAnalysisScheduler[int, dict[str, object]](max_concurrency=2)
        await scheduler.run(
            [
                AnalysisLane("execution", items("execution")),
                AnalysisLane("network", items("network")),
            ],
            execute=execute,
        )

        self.assertEqual(len(threads["execution"]), 1)
        self.assertEqual(len(threads["network"]), 1)

    async def test_dynamic_artifact_lanes_share_one_global_credit_limit(self):
        release = asyncio.Event()
        active = 0
        maximum_active = 0

        async def execute(item: int) -> dict[str, object]:
            nonlocal active, maximum_active
            active += 1
            maximum_active = max(maximum_active, active)
            await release.wait()
            active -= 1
            return {"status": "accepted", "value": item}

        queue = DynamicAnalysisQueue[int, dict[str, object]](
            max_concurrency=2,
            prefetch=1,
            lane_queue_size=1,
        )
        submissions = [
            asyncio.create_task(
                queue.submit(
                    "execution" if item % 2 == 0 else "network",
                    item,
                    execute=execute,
                )
            )
            for item in range(10)
        ]
        for _ in range(100):
            if queue.status.active == 2:
                break
            await asyncio.sleep(0.001)

        self.assertEqual(queue.status.active, 2)
        self.assertLessEqual(queue.status.production_credits_in_use, 3)
        self.assertEqual(queue.status.source_count, 2)
        release.set()
        results = await asyncio.gather(*submissions)
        await queue.close()

        self.assertEqual(sorted(result["value"] for result in results), list(range(10)))
        self.assertLessEqual(maximum_active, 2)
        self.assertEqual(queue.status.completed, 10)
        self.assertEqual(queue.status.production_credits_in_use, 0)
        self.assertTrue(queue.status.source_exhausted)

    async def test_dynamic_queue_propagates_worker_error_and_still_closes(self):
        async def execute(_item: int) -> dict[str, object]:
            raise ValueError("invalid analysis work")

        queue = DynamicAnalysisQueue[int, dict[str, object]](max_concurrency=1)
        with self.assertRaisesRegex(ValueError, "invalid analysis work"):
            await queue.submit("execution", 1, execute=execute)

        async def successful(item: int) -> dict[str, object]:
            return {"status": "accepted", "value": item}

        result = await asyncio.wait_for(
            queue.submit("execution", 2, execute=successful), timeout=2,
        )
        self.assertEqual(result["value"], 2)
        await queue.close()

        self.assertEqual(queue.status.completed, 2)
        self.assertEqual(queue.status.failed, 1)
        self.assertEqual(queue.status.production_credits_in_use, 0)

    async def test_dynamic_queue_cancelled_queued_future_is_abandoned(self):
        release = asyncio.Event()
        executed: list[int] = []

        async def execute(item: int) -> dict[str, object]:
            executed.append(item)
            if item == 1:
                await release.wait()
            return {"status": "accepted", "value": item}

        queue = DynamicAnalysisQueue[int, dict[str, object]](
            max_concurrency=1,
            prefetch=1,
            max_inflight_weight=10,
        )
        first = asyncio.create_task(
            queue.submit("one", 1, execute=execute, weight=4)
        )
        for _ in range(100):
            if queue.status.active == 1:
                break
            await asyncio.sleep(0.001)
        cancelled = await queue.enqueue("two", 2, execute=execute, weight=5)
        cancelled.cancel()
        release.set()
        await first
        await queue.close()

        self.assertEqual(executed, [1])
        self.assertEqual(queue.status.abandoned, 1)
        self.assertEqual(queue.status.production_credits_in_use, 0)
        self.assertEqual(queue.status.production_weight_in_use, 0)

    async def test_dynamic_queue_bounds_inflight_weight(self):
        release = asyncio.Event()

        async def execute(item: int) -> dict[str, object]:
            await release.wait()
            return {"status": "accepted", "value": item}

        queue = DynamicAnalysisQueue[int, dict[str, object]](
            max_concurrency=2,
            prefetch=1,
            max_inflight_weight=10,
        )
        first = asyncio.create_task(
            queue.submit("one", 1, execute=execute, weight=7)
        )
        second = asyncio.create_task(
            queue.submit("two", 2, execute=execute, weight=7)
        )
        for _ in range(100):
            if queue.status.active == 1:
                break
            await asyncio.sleep(0.001)
        self.assertEqual(queue.status.active, 1)
        self.assertEqual(queue.status.production_weight_in_use, 7)
        release.set()
        await asyncio.gather(first, second)
        await queue.close()
        self.assertEqual(queue.status.production_weight_in_use, 0)


if __name__ == "__main__":
    unittest.main()
