from pathlib import Path
from typing import Any, Union
import yaml

from statecraft.spec.schema import EnvironmentSpec


def load_spec_from_dict(data: dict[str, Any]) -> EnvironmentSpec:
    """Load an EnvironmentSpec from a dictionary."""
    return EnvironmentSpec.model_validate(data)


def load_spec_from_yaml(yaml_str: str) -> EnvironmentSpec:
    """Parse YAML string and load as EnvironmentSpec."""
    data = yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        raise ValueError("Invalid YAML content: root must be a mapping")
    return load_spec_from_dict(data)


def load_spec(source: Union[str, Path]) -> EnvironmentSpec:
    """Load EnvironmentSpec from a file path or YAML/JSON string."""
    path = Path(source)
    if path.is_file():
        content = path.read_text(encoding="utf-8")
        return load_spec_from_yaml(content)
    # Otherwise treat source as string
    return load_spec_from_yaml(str(source))


def save_spec_to_yaml(spec: EnvironmentSpec, target_file: Union[str, Path]) -> None:
    """Serialize EnvironmentSpec to a YAML file."""
    path = Path(target_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = spec.model_dump(by_alias=True, exclude_none=True, mode="json")
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
