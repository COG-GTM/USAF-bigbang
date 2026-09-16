"""Consistency tests for the cloud security assessment deliverables.

Run from the repository root:

    python3 -m pytest docs/assessments/test_assessment.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FINDINGS_JSON = HERE / "cloud-security-findings.json"
ASSESSMENT_MD = HERE / "cloud-security-assessment.md"

sys.path.insert(0, str(HERE))
import build_assessment_summary as builder  # noqa: E402

FINDING_ID_RE = re.compile(r"\bBB-[A-Z]{3}-\d{3}\b")
EVIDENCE_REF_RE = re.compile(
    r"^(?P<path>[A-Za-z0-9_./-]+):(?P<start>\d+)(?:-(?P<end>\d+))?$"
)
MD_EVIDENCE_RE = re.compile(r"`(?P<ref>[A-Za-z0-9_./-]+:\d+(?:-\d+)?)`")
SEVERITIES = {"CAT I", "CAT II", "CAT III"}
OWNERS = {"Platform", "Tenant", "Government decision"}
STIG_ID_RE = re.compile(r"^V-\d{6}$")
NIST_CONTROL_RE = re.compile(r"^[A-Z]{2}-\d+(?:\(\d+\))?$")
PILLARS = {
    "Users",
    "Devices",
    "Network",
    "Applications & Workloads",
    "Data",
    "Visibility & Analytics",
    "Automation & Orchestration",
}


@pytest.fixture(scope="module")
def data() -> dict:
    with FINDINGS_JSON.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def findings(data: dict) -> list[dict]:
    return data["findings"]


@pytest.fixture(scope="module")
def markdown() -> str:
    return ASSESSMENT_MD.read_text(encoding="utf-8")


def parse_ref(ref: str) -> tuple[Path, int, int]:
    match = EVIDENCE_REF_RE.match(ref)
    assert (
        match
    ), f"evidence reference {ref!r} is not in file:line or file:start-end form"
    start = int(match["start"])
    end = int(match["end"]) if match["end"] else start
    assert start >= 1, f"{ref}: line numbers are 1-based"
    assert end >= start, f"{ref}: end line precedes start line"
    return REPO_ROOT / match["path"], start, end


def test_finding_ids_are_unique_and_well_formed(findings: list[dict]) -> None:
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids)), "duplicate finding IDs in JSON"
    for finding_id in ids:
        assert FINDING_ID_RE.fullmatch(
            finding_id
        ), f"malformed finding ID {finding_id!r}"


def test_markdown_and_json_ids_match_bidirectionally(
    findings: list[dict], markdown: str
) -> None:
    json_ids = {f["id"] for f in findings}
    md_ids = set(FINDING_ID_RE.findall(markdown))
    assert (
        md_ids - json_ids == set()
    ), f"IDs in Markdown but not JSON: {sorted(md_ids - json_ids)}"
    assert (
        json_ids - md_ids == set()
    ), f"IDs in JSON but not Markdown: {sorted(json_ids - md_ids)}"


def test_every_json_evidence_reference_points_to_an_existing_line(
    findings: list[dict],
) -> None:
    problems = []
    for finding in findings:
        assert finding["evidence"], f"{finding['id']} has no evidence"
        for item in finding["evidence"]:
            path, start, end = parse_ref(item["ref"])
            if not path.is_file():
                problems.append(
                    f"{finding['id']}: {item['ref']} -> file does not exist"
                )
                continue
            line_count = len(
                path.read_text(encoding="utf-8", errors="replace").splitlines()
            )
            if end > line_count:
                problems.append(
                    f"{finding['id']}: {item['ref']} -> file has only {line_count} lines"
                )
    assert problems == [], "\n".join(problems)


def test_every_markdown_evidence_reference_points_to_an_existing_line(
    markdown: str,
) -> None:
    refs = {m["ref"] for m in MD_EVIDENCE_RE.finditer(markdown)}
    assert refs, "no file:line evidence references found in Markdown"
    problems = []
    for ref in sorted(refs):
        path, _start, end = parse_ref(ref)
        if not path.is_file():
            problems.append(f"{ref}: file does not exist")
            continue
        line_count = len(
            path.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if end > line_count:
            problems.append(f"{ref}: file has only {line_count} lines")
    assert problems == [], "\n".join(problems)


def test_markdown_and_json_evidence_sets_match(
    findings: list[dict], markdown: str
) -> None:
    json_refs = {item["ref"] for f in findings for item in f["evidence"]}
    md_refs = {m["ref"] for m in MD_EVIDENCE_RE.finditer(markdown)}
    assert (
        md_refs == json_refs
    ), f"only in Markdown: {sorted(md_refs - json_refs)}; only in JSON: {sorted(json_refs - md_refs)}"


def test_finding_fields_are_valid(data: dict, findings: list[dict]) -> None:
    classifications = set(data["metadata"]["classifications"])
    for finding in findings:
        fid = finding["id"]
        assert (
            finding["severity"] in SEVERITIES
        ), f"{fid}: severity {finding['severity']!r}"
        assert finding["owner"] in OWNERS, f"{fid}: owner {finding['owner']!r}"
        assert finding["classification"] in classifications, f"{fid}: classification"
        assert finding[
            "nist_controls"
        ], f"{fid}: at least one 800-53 control is required"
        for control in finding["nist_controls"]:
            assert NIST_CONTROL_RE.match(
                control
            ), f"{fid}: malformed control {control!r}"
        for rule in finding["stig_rules"]:
            assert STIG_ID_RE.match(
                rule["id"]
            ), f"{fid}: malformed STIG rule {rule['id']!r}"
            assert rule["relation"] in {"direct", "analogous"}, f"{fid}: STIG relation"
        assert (
            set(finding["zero_trust_pillars"]) <= PILLARS
        ), f"{fid}: unknown Zero Trust pillar"
        decision = finding["government_decision"]
        if finding["owner"] == "Government decision":
            assert (
                decision["required"] and decision["question"]
            ), f"{fid}: decision question missing"
        else:
            assert not decision[
                "required"
            ], f"{fid}: decision required but owner is {finding['owner']}"
        for key in ("title", "finding", "remediation"):
            assert finding[key].strip(), f"{fid}: empty {key}"


EXPECTED_FINDING_COUNT = 48


def test_finding_count_is_within_target_range(findings: list[dict]) -> None:
    assert 25 <= len(findings) <= 60, f"{len(findings)} findings; target is 25-60"


def test_finding_count_matches_control_total(findings: list[dict]) -> None:
    assert (
        len(findings) == EXPECTED_FINDING_COUNT
    ), f"{len(findings)} findings in JSON; update EXPECTED_FINDING_COUNT deliberately when findings change"


def test_assessed_commit_is_recorded(data: dict, markdown: str) -> None:
    commit = data["metadata"]["commit"]
    assert re.fullmatch(
        r"[0-9a-f]{40}", commit
    ), "metadata.commit must be a full git SHA"
    assert commit in markdown, "assessed commit SHA is not present in the Markdown"


def test_generated_sections_are_current(data: dict, markdown: str) -> None:
    regenerated = builder.apply_sections(markdown, builder.render_sections(data))
    assert (
        regenerated == markdown
    ), "generated sections are stale; run build_assessment_summary.py"


def test_build_script_check_mode_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(HERE / "build_assessment_summary.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
