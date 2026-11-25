from delegationflow.core.models import AssessmentResult, Finding, Severity
from delegationflow.output.html import export_html


def test_html_report_escapes_untrusted_fields(tmp_path):
    result = AssessmentResult(server="dc.lab", base_dn="DC=lab,DC=local")
    result.findings.append(Finding(
        finding_id="DF-1", title="<script>alert(1)</script>", severity=Severity.HIGH,
        description="Observed <b>attribute</b>", evidence={"dn": "CN=x"},
        recommendations=["Review <this>"]
    ))
    output = tmp_path / "report.html"
    export_html(result, str(output))
    content = output.read_text()
    assert "&lt;script&gt;" in content
    assert "<script>alert(1)</script>" not in content
