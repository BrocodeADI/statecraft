from pathlib import Path
import yaml

from statecraft.spec.loader import load_spec
from statecraft.validator.pipeline import ValidationPipeline


def test_valid_university_spec():
    spec = load_spec("scenarios/university-network.yaml")
    pipeline = ValidationPipeline()
    result = pipeline.validate(spec)
    assert result.valid is True
    assert len(result.errors) == 0
    assert result.spec is not None
    assert result.spec.draft is False


def test_stage_1_schema_error():
    with open("tests/fixtures/broken_envs/01_schema_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_1_schema" for e in result.errors)


def test_stage_2_integrity_error():
    with open("tests/fixtures/broken_envs/02_integrity_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_2_integrity" for e in result.errors)


def test_stage_3_graph_error():
    with open("tests/fixtures/broken_envs/03_graph_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_3_graph" for e in result.errors)


def test_stage_4_reachability_error():
    with open("tests/fixtures/broken_envs/04_reachability_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_4_reachability" for e in result.errors)


def test_stage_5_capability_error():
    with open("tests/fixtures/broken_envs/05_capability_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_5_capability" for e in result.errors)


def test_stage_6_cycle_error():
    with open("tests/fixtures/broken_envs/06_cycle_error.yaml") as f:
        data = yaml.safe_load(f)
    pipeline = ValidationPipeline()
    result = pipeline.validate(data)
    assert result.valid is False
    assert any(e.stage == "stage_6_cycle" for e in result.errors)
