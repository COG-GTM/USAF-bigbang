#!/usr/bin/env python3
"""Regenerate the generated sections of cloud-security-assessment.md from cloud-security-findings.json.

Every table and count in the Markdown that is derived from the findings lives between
``<!-- BEGIN GENERATED: <name> -->`` and ``<!-- END GENERATED: <name> -->`` markers and is
rewritten by this script, so no number in those sections is hand-typed.

Usage (from the repository root):

    python3 docs/assessments/build_assessment_summary.py          # rewrite the Markdown in place
    python3 docs/assessments/build_assessment_summary.py --check  # exit 1 if the Markdown is stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FINDINGS_JSON = HERE / "cloud-security-findings.json"
ASSESSMENT_MD = HERE / "cloud-security-assessment.md"

SEVERITY_ORDER = ["CAT I", "CAT II", "CAT III"]
OWNER_ORDER = ["Platform", "Tenant", "Government decision"]
FAMILY_NAMES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}
PILLAR_ORDER = [
    "Users",
    "Devices",
    "Network",
    "Applications & Workloads",
    "Data",
    "Visibility & Analytics",
    "Automation & Orchestration",
]

BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED: {name} -->"


def load_findings(path: Path = FINDINGS_JSON) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def control_family(control: str) -> str:
    return control.split("-", 1)[0]


def families_for(finding: dict) -> list[str]:
    return sorted({control_family(control) for control in finding["nist_controls"]})


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def format_evidence(finding: dict) -> str:
    return "<br>".join(f"`{item['ref']}`" for item in finding["evidence"])


def format_standards(finding: dict) -> str:
    parts = []
    for rule in finding["stig_rules"]:
        suffix = "" if rule["relation"] == "direct" else f" ({rule['relation']})"
        parts.append(f"{rule['id']}{suffix}")
    stig = "; ".join(parts) if parts else "no direct STIG rule"
    nist = ", ".join(finding["nist_controls"])
    return f"STIG: {stig}<br>800-53: {nist}"


def render_findings_table(findings: list[dict], classifications: dict) -> str:
    header = (
        "| ID | Finding | Evidence (file:line) | STIG rule / 800-53 control | "
        "Severity (CAT I/II/III) | Recommended remediation | Owner (Platform vs Tenant vs Government decision) |\n"
        "| --- | --- | --- | --- | --- | --- | --- |"
    )
    rows = []
    for finding in findings:
        classification = classifications[finding["classification"]]
        text = f"**{md_escape(finding['title'])}** ({classification}). {md_escape(finding['finding'])}"
        rows.append(
            "| "
            + " | ".join(
                [
                    finding["id"],
                    text,
                    format_evidence(finding),
                    format_standards(finding),
                    finding["severity"],
                    md_escape(finding["remediation"]),
                    finding["owner"],
                ]
            )
            + " |"
        )
    return "\n".join([header, *rows])


def render_count_table(
    title_col: str, counts: "OrderedDict[str, int]", total: int
) -> str:
    lines = [f"| {title_col} | Findings |", "| --- | --- |"]
    for key, value in counts.items():
        lines.append(f"| {key} | {value} |")
    lines.append(f"| **Total** | **{total}** |")
    return "\n".join(lines)


def severity_counts(findings: list[dict]) -> "OrderedDict[str, int]":
    counter = Counter(f["severity"] for f in findings)
    return OrderedDict((sev, counter.get(sev, 0)) for sev in SEVERITY_ORDER)


def owner_counts(findings: list[dict]) -> "OrderedDict[str, int]":
    counter = Counter(f["owner"] for f in findings)
    return OrderedDict((owner, counter.get(owner, 0)) for owner in OWNER_ORDER)


def classification_counts(
    findings: list[dict], classifications: dict
) -> "OrderedDict[str, int]":
    counter = Counter(f["classification"] for f in findings)
    return OrderedDict(
        (label, counter.get(key, 0)) for key, label in classifications.items()
    )


def family_rows(
    findings: list[dict],
) -> list[tuple[str, int, dict[str, int], list[str]]]:
    rows = []
    families = sorted({family for f in findings for family in families_for(f)})
    for family in families:
        members = [f for f in findings if family in families_for(f)]
        by_sev = Counter(f["severity"] for f in members)
        rows.append((family, len(members), by_sev, [f["id"] for f in members]))
    return rows


def render_family_table(findings: list[dict]) -> str:
    lines = [
        "| Family | Name | Findings | CAT I | CAT II | CAT III | Finding IDs |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for family, count, by_sev, ids in family_rows(findings):
        lines.append(
            f"| {family} | {FAMILY_NAMES.get(family, family)} | {count} | "
            f"{by_sev.get('CAT I', 0)} | {by_sev.get('CAT II', 0)} | {by_sev.get('CAT III', 0)} | "
            f"{', '.join(ids)} |"
        )
    lines.append(
        "\nA finding that cites controls from several families is counted once in each family, "
        f"so the family totals exceed the {len(findings)} distinct findings."
    )
    return "\n".join(lines)


def render_owner_table(findings: list[dict]) -> str:
    lines = [
        "| Owner | Findings | CAT I | CAT II | CAT III | Finding IDs |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for owner in OWNER_ORDER:
        members = [f for f in findings if f["owner"] == owner]
        by_sev = Counter(f["severity"] for f in members)
        lines.append(
            f"| {owner} | {len(members)} | {by_sev.get('CAT I', 0)} | {by_sev.get('CAT II', 0)} | "
            f"{by_sev.get('CAT III', 0)} | {', '.join(f['id'] for f in members)} |"
        )
    lines.append(f"| **Total** | **{len(findings)}** | | | | |")
    return "\n".join(lines)


def render_pillar_table(findings: list[dict]) -> str:
    lines = ["| Zero Trust pillar | Findings | Finding IDs |", "| --- | --- | --- |"]
    for pillar in PILLAR_ORDER:
        members = [f for f in findings if pillar in f["zero_trust_pillars"]]
        if members:
            lines.append(
                f"| {pillar} | {len(members)} | {', '.join(f['id'] for f in members)} |"
            )
    return "\n".join(lines)


def render_government_decisions(findings: list[dict]) -> str:
    items = [f for f in findings if f["government_decision"]["required"]]
    lines = [
        f"{len(items)} findings require a Government risk-acceptance or architecture decision before "
        "an engineering change can be scheduled.",
        "",
        "| ID | Decision required | Severity | Finding |",
        "| --- | --- | --- | --- |",
    ]
    for finding in items:
        lines.append(
            f"| {finding['id']} | {md_escape(finding['government_decision']['question'])} | "
            f"{finding['severity']} | {md_escape(finding['title'])} |"
        )
    return "\n".join(lines)


def render_traceability(findings: list[dict], commit: str) -> str:
    lines = [
        f"All references are relative to the repository root at commit `{commit}`.",
        "",
        "| ID | File | Line(s) | What the lines show | Commit |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        for item in finding["evidence"]:
            path, _, lines_ref = item["ref"].rpartition(":")
            lines.append(
                f"| {finding['id']} | `{path}` | {lines_ref} | {md_escape(item['note'])} | `{commit[:12]}` |"
            )
    return "\n".join(lines)


def distinct_evidence_refs(findings: list[dict]) -> set[str]:
    return {item["ref"] for f in findings for item in f["evidence"]}


def distinct_files_cited(findings: list[dict]) -> set[str]:
    return {ref.rpartition(":")[0] for ref in distinct_evidence_refs(findings)}


def render_metadata(meta: dict, findings: list[dict]) -> str:
    return "\n".join(
        [
            "| Item | Value |",
            "| --- | --- |",
            f"| Repository | `{meta['repository']}` |",
            f"| Base branch | `{meta['base_branch']}` |",
            f"| Assessed commit | `{meta['commit']}` |",
            f"| Umbrella chart version | `{meta['chart_version']}` |",
            f"| Assessment date | {meta['assessment_date']} |",
            f"| Distinct findings | {len(findings)} |",
            f"| Distinct evidence references | {len(distinct_evidence_refs(findings))} |",
            f"| Distinct files cited | {len(distinct_files_cited(findings))} |",
        ]
    )


def render_sections(data: dict) -> dict[str, str]:
    findings = data["findings"]
    classifications = data["metadata"]["classifications"]
    total = len(findings)
    return {
        "metadata": render_metadata(data["metadata"], findings),
        "severity": render_count_table("Severity", severity_counts(findings), total),
        "classification": render_count_table(
            "Classification", classification_counts(findings, classifications), total
        ),
        "findings-table": render_findings_table(findings, classifications),
        "family": render_family_table(findings),
        "owner": render_owner_table(findings),
        "pillar": render_pillar_table(findings),
        "government-decisions": render_government_decisions(findings),
        "traceability": render_traceability(findings, data["metadata"]["commit"]),
    }


def apply_sections(markdown: str, sections: dict[str, str]) -> str:
    for name, body in sections.items():
        begin = BEGIN.format(name=name)
        end = END.format(name=name)
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        if not pattern.search(markdown):
            raise SystemExit(
                f"marker pair for generated section '{name}' not found in {ASSESSMENT_MD}"
            )
        markdown = pattern.sub(
            lambda _m, b=begin, e=end, s=body: f"{b}\n{s}\n{e}", markdown
        )
    return markdown


def build(check_only: bool) -> int:
    data = load_findings()
    current = ASSESSMENT_MD.read_text(encoding="utf-8")
    updated = apply_sections(current, render_sections(data))
    if check_only:
        if updated != current:
            print(
                f"{ASSESSMENT_MD.relative_to(REPO_ROOT)} is stale; run build_assessment_summary.py"
            )
            return 1
        print("assessment markdown is up to date")
        return 0
    if updated != current:
        ASSESSMENT_MD.write_text(updated, encoding="utf-8")
        print(f"updated {ASSESSMENT_MD.relative_to(REPO_ROOT)}")
    else:
        print("no changes")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the Markdown is current without writing",
    )
    args = parser.parse_args(argv)
    return build(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
