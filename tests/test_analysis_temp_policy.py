import tempfile
import unittest
from pathlib import Path

from vraptor.common import atomic_io
from vraptor.autoruns import golden as autoruns_golden


class AnalysisTempPolicyTest(unittest.TestCase):
    def test_atomic_writes_stage_beside_destination_and_clean_up(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / "analysis" / "state.json"

            atomic_io.write_text_atomic(destination, '{"status":"ok"}\n')

            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                '{"status":"ok"}\n',
            )
            self.assertEqual(
                list(destination.parent.glob(f".{destination.name}.*.tmp")),
                [],
            )

    def test_work_paths_remain_under_the_controlled_case_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / "analysis" / "golden.sqlite"

            database_path = autoruns_golden._atomic_database_path(destination)
            work_directory = atomic_io.create_work_directory(
                root / "hunts" / "H.1234" / "snapshots",
                prefix="snapshot",
            )

            self.assertEqual(database_path.parent, destination.parent)
            self.assertEqual(
                work_directory.parent,
                root / "hunts" / "H.1234" / "snapshots",
            )
            work_directory.rmdir()


if __name__ == "__main__":
    unittest.main()
