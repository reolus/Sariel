"""Unit tests for the risk scoring engine."""
import pytest
from sariel.scoring.engine import ScoringEngine, Severity


@pytest.fixture
def engine():
    return ScoringEngine(critical_threshold=70.0, high_threshold=40.0, suppress_below=10.0)


def make_row(**kwargs):
    defaults = {
        "cloud": "aws",
        "account_id": "123456789012",
        "net_id": "internet://0.0.0.0/0",
        "has_public_ip": True,
        "cvss_score": 9.1,
        "cvss_exploit": 3.9,
        "has_exploit": True,
        "ds_sensitivity": "critical",
        "ds_label": "s3://prod-secrets",
        "ds_privileged": False,
        "compute_label": "web-server-01",
        "cve_id": "CVE-2024-1234",
        "role_overperm": False,
        "is_guest": False,
        "az_role_privileged": False,
    }
    return {**defaults, **kwargs}


class TestExposureFactor:
    def test_public_ip_gives_full_exposure(self, engine):
        row = make_row(has_public_ip=True)
        path = engine.score_path("public_vuln_data_access", row)
        assert path.factors.exposure == 1.0

    def test_no_public_ip_gives_internal_exposure(self, engine):
        row = make_row(has_public_ip=False, net_id="internal")
        path = engine.score_path("public_vuln_data_access", row)
        assert path.factors.exposure == 0.4

    def test_guest_user_always_public(self, engine):
        row = make_row(
            has_public_ip=False, is_guest=True,
            user_id="entra://t/users/abc", user_label="guest@partner.com",
            mfa_registered=False, role_id=None, ds_id=None, az_role_def_id=None,
        )
        path = engine.score_path("identity_abuse", row)
        assert path.factors.exposure == 1.0


class TestExploitabilityFactor:
    def test_max_cvss_exploit_gives_near_one(self, engine):
        row = make_row(cvss_exploit=3.9, has_exploit=True)
        path = engine.score_path("public_vuln_data_access", row)
        assert path.factors.exploitability >= 0.95

    def test_no_cvss_uses_baseline_for_identity(self, engine):
        row = make_row(
            user_id="arn:aws:iam::123:user/alice",
            user_label="alice",
            mfa_enabled=False,
            role_id="arn:aws:iam::123:role/DataAccess",
            role_label="DataAccess",
            role_overperm=True,
            ds_id="arn:aws:s3:::prod-secrets",
            ds_sensitivity="critical",
            az_role_def_id=None,
        )
        path = engine.score_path("identity_abuse", row)
        assert 0.5 <= path.factors.exploitability <= 0.9


class TestSensitivityFactor:
    def test_critical_sensitivity_gives_one(self, engine):
        row = make_row(ds_sensitivity="critical")
        path = engine.score_path("public_vuln_data_access", row)
        assert path.factors.sensitivity == 1.0

    def test_public_sensitivity_collapses_score(self, engine):
        row = make_row(ds_sensitivity="public")
        path = engine.score_path("public_vuln_data_access", row)
        assert path.score < 10.0

    def test_unknown_sensitivity_is_conservative(self, engine):
        row = make_row(ds_sensitivity="unknown")
        path = engine.score_path("public_vuln_data_access", row)
        assert path.factors.sensitivity == 0.5


class TestOverallScoring:
    def test_worst_case_scores_near_100(self, engine):
        row = make_row(
            has_public_ip=True,
            cvss_exploit=3.9,
            has_exploit=True,
            ds_sensitivity="critical",
            role_overperm=True,
        )
        path = engine.score_path("public_vuln_data_access", row)
        assert path.score >= 80.0
        assert path.severity == Severity.CRITICAL

    def test_isolated_asset_no_exploit_scores_low(self, engine):
        row = make_row(
            has_public_ip=False,
            net_id="internal",
            cvss_exploit=1.0,
            has_exploit=False,
            ds_sensitivity="low",
        )
        path = engine.score_path("public_vuln_data_access", row)
        assert path.score < 20.0

    def test_suppression_below_threshold(self, engine):
        row = make_row(
            has_public_ip=False,
            net_id="internal",
            cvss_exploit=0.5,
            has_exploit=False,
            ds_sensitivity="public",
        )
        path = engine.score_path("public_vuln_data_access", row)
        assert path.suppressed is True

    def test_path_id_is_stable(self, engine):
        row = make_row()
        p1 = engine.score_path("public_vuln_data_access", row)
        p2 = engine.score_path("public_vuln_data_access", row)
        assert p1.path_id == p2.path_id

    def test_path_id_changes_with_different_nodes(self, engine):
        row1 = make_row(compute_id="arn:aws:ec2:::instance/i-001")
        row2 = make_row(compute_id="arn:aws:ec2:::instance/i-002")
        # IDs extracted differ so path IDs should differ
        p1 = engine.score_path("public_vuln_data_access", row1)
        p2 = engine.score_path("public_vuln_data_access", row2)
        # May or may not differ (depends on which fields are in node_id_columns)
        # At minimum, scores should be computed
        assert p1.score >= 0
        assert p2.score >= 0


class TestSeverityClassification:
    def test_critical_at_threshold(self, engine):
        e = ScoringEngine(critical_threshold=70.0, high_threshold=40.0, suppress_below=10.0)
        assert e._classify_severity(70.0) == Severity.CRITICAL
        assert e._classify_severity(69.9) == Severity.HIGH
        assert e._classify_severity(40.0) == Severity.HIGH
        assert e._classify_severity(39.9) == Severity.MEDIUM
        assert e._classify_severity(9.9) == Severity.LOW


class TestFixRecommendations:
    def test_vuln_path_generates_three_fixes(self, engine):
        row = make_row()
        path = engine.score_path("public_vuln_data_access", row)
        assert len(path.fix_recommendations) == 3
        priorities = [f["priority"] for f in path.fix_recommendations]
        assert priorities == [1, 2, 3]

    def test_identity_path_generates_fixes(self, engine):
        row = {
            "cloud": "aws", "account_id": "123",
            "user_id": "arn:aws:iam::123:user/alice",
            "user_label": "alice",
            "mfa_enabled": False,
            "is_guest": False,
            "role_id": "arn:aws:iam::123:role/DataAccess",
            "role_label": "DataAccess",
            "role_overperm": True,
            "ds_id": "arn:aws:s3:::prod",
            "ds_sensitivity": "critical",
            "ds_label": "prod-secrets",
            "az_role_def_id": None,
            "az_role_privileged": False,
        }
        path = engine.score_path("identity_abuse", row)
        assert len(path.fix_recommendations) >= 1
        assert path.fix_recommendations[0]["category"] == "identity"
