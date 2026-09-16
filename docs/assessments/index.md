# Assessments

This section holds point-in-time security assessments of the Big Bang umbrella chart. Each assessment
is static: it reads the chart, templates, and documentation at a recorded commit, cites file and line
evidence for every finding, and does not contact a cluster or change any default.

Assessments describe the posture produced by shipped defaults. They complement, and do not replace,
the [security model](../concepts/security-model.md), the
[production considerations](../configuration/production-considerations/index.md), and the platform
owner's own authorization evidence.

## Available assessments

| Assessment | Baseline | Artifacts |
| --- | --- | --- |
| [Cloud security assessment of the default configuration](cloud-security-assessment.md) | DISA Kubernetes STIG, NIST SP 800-53 Rev. 5, DoD Zero Trust pillars | [`cloud-security-findings.json`](cloud-security-findings.json), [`build_assessment_summary.py`](build_assessment_summary.py), [`test_assessment.py`](test_assessment.py) |

## Maintaining an assessment

Finding content lives in the assessment's JSON file. Edit the JSON, regenerate the Markdown with the
matching build script, and run the matching pytest module so identifiers, evidence references, and
generated counts stay consistent:

```bash
python3 docs/assessments/build_assessment_summary.py
python3 -m pytest docs/assessments/test_assessment.py
```
