"""Unit tests for the SecretScan scanner module."""

import pytest

from ai_artifact_risk_validator.models import (
    ArtifactType,
    ScannerModule,
)
from ai_artifact_risk_validator.scanners.secret_scan import (
    SecretScanScanner,
    _calculate_shannon_entropy,
    _find_high_entropy_strings,
)


@pytest.fixture
def scanner() -> SecretScanScanner:
    """Create a SecretScanScanner instance for testing."""
    return SecretScanScanner()


class TestScannerMetadata:
    """Tests for scanner properties and metadata."""

    def test_name(self, scanner: SecretScanScanner) -> None:
        assert scanner.name == ScannerModule.SECRET_SCAN

    def test_applicable_artifact_types_covers_all_14(self, scanner: SecretScanScanner) -> None:
        types = scanner.applicable_artifact_types
        assert len(types) == 14
        assert set(types) == set(ArtifactType)

    def test_detected_risk_ids(self, scanner: SecretScanScanner) -> None:
        risk_ids = scanner.detected_risk_ids
        expected = [
            "P-S3",
            "P-S4",
            "P-S8",
            "SK-S5",
            "SOP-S1",
            "I-S3",
            "M-S2",
            "M-S3",
            "M-S4",
            "EV-S2",
            "MCP-S3",
            "H-S2",
            "RAG-S3",
            "GOV-1",
        ]
        assert set(risk_ids) == set(expected)

    def test_is_available_always_true(self, scanner: SecretScanScanner) -> None:
        assert scanner.is_available() is True


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_string_returns_zero(self) -> None:
        assert _calculate_shannon_entropy("") == 0.0

    def test_single_character_returns_zero(self) -> None:
        # All same character = zero entropy
        assert _calculate_shannon_entropy("aaaa") == 0.0

    def test_two_equal_characters_returns_one(self) -> None:
        # Perfectly balanced binary = 1 bit
        assert abs(_calculate_shannon_entropy("ab") - 1.0) < 0.01

    def test_high_entropy_string(self) -> None:
        # Random-looking string should have high entropy
        high_entropy = "aB3$xZ9!qR7&mK2@pL5^wY"
        entropy = _calculate_shannon_entropy(high_entropy)
        assert entropy > 4.0

    def test_low_entropy_string(self) -> None:
        # Repetitive string should have low entropy
        low_entropy = "aaaaabbbbbccccc"
        entropy = _calculate_shannon_entropy(low_entropy)
        assert entropy < 2.0

    def test_realistic_api_key_entropy(self) -> None:
        # A realistic API key should exceed the threshold
        api_key = "sk-proj-abc123XYZ789def456GHI012jkl345"
        entropy = _calculate_shannon_entropy(api_key)
        assert entropy > 4.5


class TestHighEntropyStrings:
    """Tests for high-entropy string finder."""

    def test_finds_high_entropy_quoted_string(self) -> None:
        content = 'api_key = "aB3xZ9qR7mK2pL8nW4vY6tU0sE5hJ1fD"'
        results = _find_high_entropy_strings(content)
        assert len(results) >= 1
        assert results[0][1] > 4.5  # entropy
        assert results[0][2] == 1  # line number

    def test_ignores_low_entropy_strings(self) -> None:
        content = 'name = "aaaaaaaaaaaaaaaaaabbbbbbbb"'
        results = _find_high_entropy_strings(content)
        # Low entropy string should not be flagged
        assert len(results) == 0

    def test_reports_correct_line_numbers(self) -> None:
        content = 'line one\nline two\nsecret = "xK9mR4qZ7wL2bN5vC8yP0tU3sA6hJ1fE"\nline four\n'
        results = _find_high_entropy_strings(content)
        if results:
            assert results[0][2] == 3


class TestRegexSecretDetection:
    """Tests for regex-based secret pattern detection."""

    def test_detects_aws_access_key(self, scanner: SecretScanScanner) -> None:
        content = "aws_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        secret_findings = [f for f in findings if "AWS" in f.description]
        assert len(secret_findings) >= 1
        assert secret_findings[0].confidence >= 0.95

    def test_detects_github_token(self, scanner: SecretScanScanner) -> None:
        content = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert len(findings) >= 1
        assert any(f.id == "SK-S5" for f in findings)

    def test_detects_openai_api_key(self, scanner: SecretScanScanner) -> None:
        content = "OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        findings = scanner.scan(content, ArtifactType.EVAL_HARNESS, "eval.yaml")
        assert len(findings) >= 1
        assert any(f.id == "EV-S2" for f in findings)

    def test_detects_generic_api_key(self, scanner: SecretScanScanner) -> None:
        content = 'api_key = "sk_live_abcdef1234567890abcdef"'
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        secret_findings = [f for f in findings if f.confidence >= 0.80]
        assert len(secret_findings) >= 1

    def test_detects_password_in_config(self, scanner: SecretScanScanner) -> None:
        content = "database_password: SuperSecret123!"
        findings = scanner.scan(content, ArtifactType.SOP, "setup.sop.md")
        assert len(findings) >= 1
        assert any(f.id == "SOP-S1" for f in findings)

    def test_detects_connection_string(self, scanner: SecretScanScanner) -> None:
        content = "DATABASE_URL=postgresql://admin:s3cr3tP@ss@db.example.com:5432/prod"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.instructions.md")
        secret_findings = [f for f in findings if "Connection" in f.description]
        assert len(secret_findings) >= 1

    def test_detects_private_key(self, scanner: SecretScanScanner) -> None:
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----"
        )
        findings = scanner.scan(content, ArtifactType.MEMORY, "session.memory")
        assert len(findings) >= 1
        assert any(f.confidence >= 0.99 for f in findings)

    def test_detects_slack_token(self, scanner: SecretScanScanner) -> None:
        content = "SLACK_TOKEN=xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"
        findings = scanner.scan(content, ArtifactType.HOOK, "notify.hook.yaml")
        assert len(findings) >= 1
        assert any(f.id == "H-S2" for f in findings)

    def test_detects_jwt_token(self, scanner: SecretScanScanner) -> None:
        content = "auth_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = scanner.scan(content, ArtifactType.RAG, "knowledge.md")
        assert len(findings) >= 1

    def test_detects_stripe_key(self, scanner: SecretScanScanner) -> None:
        content = "stripe_key: sk_live_abcdefghijklmnopqrstuvwxyz"
        findings = scanner.scan(content, ArtifactType.PLUGIN, "payment.plugin.json")
        assert len(findings) >= 1

    def test_detects_google_api_key(self, scanner: SecretScanScanner) -> None:
        content = "GOOGLE_API_KEY=AIzaSyA-abcdef0123456789abcdefghijklmno"
        findings = scanner.scan(content, ArtifactType.AGENT, "agent.md")
        assert len(findings) >= 1


class TestPIIDetection:
    """Tests for PII pattern detection."""

    def test_detects_email_address(self, scanner: SecretScanScanner) -> None:
        content = "Contact: john.doe@company.com for support"
        findings = scanner.scan(content, ArtifactType.PROMPT, "example.prompt.md")
        pii_findings = [f for f in findings if "PII" in f.description]
        assert len(pii_findings) >= 1

    def test_detects_ssn(self, scanner: SecretScanScanner) -> None:
        content = "SSN: 123-45-6789"
        findings = scanner.scan(content, ArtifactType.MEMORY, "user.memory")
        assert len(findings) >= 1

    def test_detects_phone_number(self, scanner: SecretScanScanner) -> None:
        content = "Call us at (555) 123-4567"
        findings = scanner.scan(content, ArtifactType.PROMPT, "support.prompt.md")
        pii_findings = [f for f in findings if "Phone" in f.description]
        assert len(pii_findings) >= 1

    def test_prompt_pii_uses_P_S4_risk(self, scanner: SecretScanScanner) -> None:
        content = "Example user: john.doe@company.com"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        pii_findings = [f for f in findings if "PII" in f.description]
        assert any(f.id == "P-S4" for f in pii_findings)

    def test_memory_pii_uses_M_S3_risk(self, scanner: SecretScanScanner) -> None:
        content = "User provided SSN: 123-45-6789"
        findings = scanner.scan(content, ArtifactType.MEMORY, "session.memory")
        pii_findings = [f for f in findings if "PII" in f.description]
        assert any(f.id == "M-S3" for f in pii_findings)


class TestEntropyDetection:
    """Tests for entropy-based secret detection."""

    def test_detects_high_entropy_string(self, scanner: SecretScanScanner) -> None:
        # Generate a high-entropy string that doesn't match any regex pattern
        content = 'custom_secret = "xK9mR4qZ7wL2bN5vC8yP0tU3sA6hJ1fE"'
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        entropy_findings = [f for f in findings if "entropy" in f.description.lower()]
        assert len(entropy_findings) >= 1
        assert all(0.80 <= f.confidence <= 0.94 for f in entropy_findings)

    def test_does_not_flag_normal_text(self, scanner: SecretScanScanner) -> None:
        content = "This is a normal prompt with regular text and instructions."
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        # Should have no secret findings for plain text
        assert len(findings) == 0

    def test_entropy_not_duplicated_with_regex(self, scanner: SecretScanScanner) -> None:
        # AWS key is caught by regex; entropy should NOT duplicate it
        content = "key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        entropy_findings = [f for f in findings if "entropy" in f.description.lower()]
        # The AWS key itself shouldn't appear as an entropy finding
        assert not any("AKIAIOSFODNN7EXAMPLE" in f.evidence for f in entropy_findings)


class TestArtifactTypeMapping:
    """Tests for correct risk ID assignment per artifact type."""

    def test_prompt_uses_P_S3(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert any(f.id == "P-S3" for f in findings)

    def test_skill_uses_SK_S5(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.SKILL, "skill.md")
        assert any(f.id == "SK-S5" for f in findings)

    def test_sop_uses_SOP_S1(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.SOP, "deploy.sop.md")
        assert any(f.id == "SOP-S1" for f in findings)

    def test_instruction_uses_I_S3(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.INSTRUCTION, "setup.instructions.md")
        assert any(f.id == "I-S3" for f in findings)

    def test_memory_uses_M_S2(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.MEMORY, "context.memory")
        assert any(f.id == "M-S2" for f in findings)

    def test_eval_harness_uses_EV_S2(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.EVAL_HARNESS, "eval.yaml")
        assert any(f.id == "EV-S2" for f in findings)

    def test_mcp_uses_MCP_S3(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.MCP, "mcp.json")
        assert any(f.id == "MCP-S3" for f in findings)

    def test_hook_uses_H_S2(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.HOOK, "notify.hook.yaml")
        assert any(f.id == "H-S2" for f in findings)

    def test_rag_uses_RAG_S3(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.RAG, "docs.md")
        assert any(f.id == "RAG-S3" for f in findings)


class TestConfidenceBands:
    """Tests for confidence band assignment."""

    def test_exact_regex_match_high_confidence(self, scanner: SecretScanScanner) -> None:
        content = "key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        regex_findings = [f for f in findings if "AWS" in f.description]
        assert all(f.confidence >= 0.95 for f in regex_findings)

    def test_entropy_detection_moderate_confidence(self, scanner: SecretScanScanner) -> None:
        content = 'token = "xK9mR4qZ7wL2bN5vC8yP0tU3sA6hJ1fE"'
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        entropy_findings = [f for f in findings if "entropy" in f.description.lower()]
        assert all(0.80 <= f.confidence <= 0.94 for f in entropy_findings)

    def test_pii_pattern_confidence(self, scanner: SecretScanScanner) -> None:
        content = "SSN: 123-45-6789"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        pii_findings = [f for f in findings if "PII" in f.description]
        assert all(0.60 <= f.confidence <= 1.0 for f in pii_findings)


class TestEdgeCases:
    """Tests for edge cases and clean content."""

    def test_empty_content_returns_no_findings(self, scanner: SecretScanScanner) -> None:
        findings = scanner.scan("", ArtifactType.PROMPT, "empty.prompt.md")
        assert findings == []

    def test_clean_content_returns_no_findings(self, scanner: SecretScanScanner) -> None:
        content = """# System Prompt

You are a helpful assistant that helps users write code.

## Guidelines

- Be concise and accurate
- Follow best practices
- Explain your reasoning
"""
        findings = scanner.scan(content, ArtifactType.PROMPT, "clean.prompt.md")
        assert findings == []

    def test_evidence_is_truncated(self, scanner: SecretScanScanner) -> None:
        # Very long secret should be truncated in evidence
        content = "password: " + "a" * 100
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        if findings:
            assert len(findings[0].evidence) <= 63  # 60 + "..."

    def test_multiple_secrets_on_same_line(self, scanner: SecretScanScanner) -> None:
        content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE password=SuperSecret123!"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert len(findings) >= 2

    def test_finding_location_has_line_number(self, scanner: SecretScanScanner) -> None:
        content = "line1\nline2\napi_key = AKIAIOSFODNN7EXAMPLE\nline4"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        aws_findings = [f for f in findings if "AWS" in f.description]
        assert aws_findings[0].location.line == 3

    def test_scanner_module_set_correctly(self, scanner: SecretScanScanner) -> None:
        content = "api_key = AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan(content, ArtifactType.PROMPT, "test.prompt.md")
        assert all(f.scanner_module == ScannerModule.SECRET_SCAN for f in findings)


class TestPresidioFalsePositiveFixes:
    """Regression tests for Presidio false-positive filters.

    These tests verify that known noise sources (PERSON entities for tech names,
    very short entities, and CI component-path references that look like emails)
    do not produce findings.
    """

    def test_person_entity_not_flagged_as_secret(self, scanner: SecretScanScanner) -> None:
        """PERSON entities (e.g. tech names Kafka, Helm) must not become secret findings."""
        from unittest.mock import MagicMock, patch

        person_result = MagicMock()
        person_result.entity_type = "PERSON"
        person_result.start = 0
        person_result.end = 5
        person_result.score = 0.85

        mock_presidio = MagicMock()
        mock_presidio.analyze.return_value = [person_result]

        with patch.object(scanner, "_load_presidio", return_value=mock_presidio):
            findings = scanner.scan("Kafka", ArtifactType.PROMPT, "test.prompt.md")

        presidio_findings = [f for f in findings if "presidio" in f.description]
        assert len(presidio_findings) == 0

    def test_short_entity_not_flagged(self, scanner: SecretScanScanner) -> None:
        """Presidio entities shorter than 4 characters must be filtered out."""
        from unittest.mock import MagicMock, patch

        short_result = MagicMock()
        short_result.entity_type = "US_DRIVER_LICENSE"
        short_result.start = 0
        short_result.end = 2
        short_result.score = 0.80

        mock_presidio = MagicMock()
        mock_presidio.analyze.return_value = [short_result]

        with patch.object(scanner, "_load_presidio", return_value=mock_presidio):
            findings = scanner.scan("K6", ArtifactType.PROMPT, "test.prompt.md")

        presidio_findings = [f for f in findings if "presidio" in f.description]
        assert len(presidio_findings) == 0

    def test_ci_component_path_not_flagged_as_email(self, scanner: SecretScanScanner) -> None:
        """EMAIL_ADDRESS matches containing '/' are CI/URL paths, not real emails."""
        from unittest.mock import MagicMock, patch

        content = "- component: 'gitlab.example.com/group/project@v1.0'"
        evidence_str = "gitlab.example.com/group/project@v1.0"

        email_result = MagicMock()
        email_result.entity_type = "EMAIL_ADDRESS"
        email_result.start = content.index(evidence_str)
        email_result.end = email_result.start + len(evidence_str)
        email_result.score = 0.90

        mock_presidio = MagicMock()
        mock_presidio.analyze.return_value = [email_result]

        with patch.object(scanner, "_load_presidio", return_value=mock_presidio):
            findings = scanner.scan(content, ArtifactType.ORCHESTRATION, "ci.yml")

        presidio_findings = [f for f in findings if "presidio" in f.description]
        assert len(presidio_findings) == 0
