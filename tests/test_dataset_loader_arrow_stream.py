from pathlib import Path

import pytest


def test_arrow_loader_accepts_ipc_stream_files(tmp_path: Path):
    pa = pytest.importorskip("pyarrow")
    ipc = pytest.importorskip("pyarrow.ipc")

    from vuln_commit_kg.data.dataset_loader import _arrow_rows

    path = tmp_path / "stream.arrow"
    table = pa.table({"sample_id": ["1"], "project": ["p"], "target": ["x"]})
    with pa.OSFile(str(path), "wb") as sink:
        with ipc.new_stream(sink, table.schema) as writer:
            writer.write_table(table)

    rows = _arrow_rows(path)
    assert rows == [{"sample_id": "1", "project": "p", "target": "x"}]
