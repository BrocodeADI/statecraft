import io
import json
from pathlib import Path
import tarfile
from typing import Union
import yaml

from statecraft.persistence.run import Run
from statecraft.spec.schema import EnvironmentSpec


def export_run(run: Run, file_path: Union[str, Path]) -> Path:
    """Exports a Run object to a portable .scr file (tar.gz format)."""
    target = Path(file_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "version": "1.0",
        "run_id": run.id,
        "environment_id": run.environment_spec.id,
        "seed": run.seed,
        "created_at": run.created_at,
        "event_count": len(run.events),
        "action_count": len(run.actions),
    }

    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    run_bytes = run.model_dump_json(indent=2).encode("utf-8")
    spec_bytes = yaml.safe_dump(run.environment_spec.model_dump(by_alias=True, mode="json")).encode("utf-8")
    events_bytes = "\n".join(e.model_dump_json() for e in run.events).encode("utf-8")

    with tarfile.open(target, "w:gz") as tar:
        for name, data in [
            ("manifest.json", manifest_bytes),
            ("spec.yaml", spec_bytes),
            ("events.jsonl", events_bytes),
            ("run.json", run_bytes),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    return target


def import_run(file_path: Union[str, Path]) -> Run:
    """Imports a Run object from a .scr file."""
    target = Path(file_path)
    if not target.is_file():
        raise FileNotFoundError(f"Run file not found: {file_path}")

    with tarfile.open(target, "r:gz") as tar:
        run_file = tar.extractfile("run.json")
        if run_file is None:
            raise ValueError("Corrupt .scr package: missing run.json")
        content = run_file.read().decode("utf-8")
        return Run.model_validate_json(content)
