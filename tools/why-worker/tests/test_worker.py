"""Tests for the Python worker. All tests are network-free."""

import json
import io
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from models import (
    WorkerResponse,
    DecisionAdditions,
    NextAction,
    dict_to_worker_request,
    to_json_dict,
)
import main as main_module

WORKER_PATH = Path(__file__).parent.parent / "main.py"

MINIMAL_REQUEST = {
    "version": "v1alpha1",
    "requestId": "test-001",
    "input": {
        "resource": {"kind": "Pod", "name": "test-pod", "namespace": "default"}
    },
}

REQUEST_WITH_FINDINGS = {
    "version": "v1alpha1",
    "requestId": "test-002",
    "locale": "en",
    "input": {
        "resource": {"kind": "Pod", "name": "test-pod", "namespace": "default"},
        "policyFindings": [
            {
                "policyId": "PSP-001",
                "title": "Running as root",
                "severity": "HIGH",
                "message": "Container runs as root user",
            }
        ],
    },
}

MOCK_AI_RESULT = {
    "summary": "Pod blocked: running as root",
    "nextActions": [
        {"title": "Set runAsNonRoot", "detail": "Add runAsNonRoot: true to securityContext"},
    ],
}


# --- Helpers ---


def _subprocess_run(input_data, env_overrides=None):
    """Run worker as subprocess. Returns (stdout, stderr, returncode)."""
    env = os.environ.copy()
    env.pop("WHY_AI_API_KEY", None)
    env.pop("WHY_AI_PROVIDER", None)
    if env_overrides:
        env.update(env_overrides)
    input_str = json.dumps(input_data) if isinstance(input_data, dict) else input_data
    result = subprocess.run(
        [sys.executable, str(WORKER_PATH)],
        input=input_str,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout, result.stderr, result.returncode


def _run_in_process(request_data, mock_provider=None):
    """Run main() in-process with optional mocked provider. Returns parsed response dict."""
    stdin_buf = io.StringIO(json.dumps(request_data))
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with patch("sys.stdin", stdin_buf), \
         patch("sys.stdout", stdout_buf), \
         patch("sys.stderr", stderr_buf):
        if mock_provider is not None:
            with patch.object(main_module, "create_provider", return_value=mock_provider):
                main_module.main()
        else:
            main_module.main()

    stdout_buf.seek(0)
    return json.loads(stdout_buf.read())


# --- Model unit tests ---


class TestModels:

    def test_minimal_request_parsing(self):
        req = dict_to_worker_request(MINIMAL_REQUEST)
        assert req.version == "v1alpha1"
        assert req.requestId == "test-001"
        assert req.input.resource.kind == "Pod"

    def test_full_request_parsing(self):
        data = {
            "version": "v1alpha1",
            "requestId": "test-full",
            "locale": "ko",
            "input": {
                "resource": {
                    "kind": "Deployment",
                    "name": "nginx",
                    "namespace": "prod",
                    "uid": "abc-123",
                    "apiVersion": "apps/v1",
                },
                "imageRefs": ["nginx:1.19", "alpine:latest"],
                "policyFindings": [
                    {
                        "policyId": "PSP-001",
                        "title": "Running as root",
                        "severity": "HIGH",
                        "message": "Container runs as root user",
                        "evidence": [
                            {
                                "type": "K8S_FIELD",
                                "subject": "spec.securityContext.runAsNonRoot",
                                "detail": "false",
                            }
                        ],
                        "suggestedFixes": [
                            {
                                "title": "Enable non-root",
                                "detail": "Set runAsNonRoot to true",
                                "patch": {"format": "yaml", "content": "runAsNonRoot: true"},
                            }
                        ],
                    }
                ],
            },
        }
        req = dict_to_worker_request(data)
        assert req.locale == "ko"
        assert len(req.input.policyFindings) == 1
        assert req.input.policyFindings[0].policyId == "PSP-001"
        assert len(req.input.policyFindings[0].evidence) == 1
        assert req.input.policyFindings[0].suggestedFixes[0].patch.format == "yaml"

    def test_response_serialization(self):
        response = WorkerResponse(
            version="v1alpha1",
            requestId="test-ser",
            decisionAdditions=DecisionAdditions(
                summary="Test summary",
                nextActions=[
                    NextAction(title="Fix it", detail="Run kubectl apply"),
                ],
            ),
        )
        d = to_json_dict(response)
        assert d["version"] == "v1alpha1"
        assert d["requestId"] == "test-ser"
        assert d["decisionAdditions"]["summary"] == "Test summary"
        assert d["decisionAdditions"]["nextActions"][0]["title"] == "Fix it"
        json.dumps(d)  # must be serializable

    def test_response_omits_none_fields(self):
        response = WorkerResponse(version="v1alpha1", requestId="test-none")
        d = to_json_dict(response)
        assert "decisionAdditions" not in d

    def test_extra_fields_ignored(self):
        data = {
            "version": "v1alpha1",
            "requestId": "test-extra",
            "unknownField": "should be ignored",
            "input": {
                "resource": {"kind": "Pod", "name": "x", "namespace": "y"},
                "extraField": "ignored",
            },
        }
        req = dict_to_worker_request(data)
        assert req.version == "v1alpha1"
        assert not hasattr(req, "unknownField")


# --- E2E subprocess tests ---


class TestEndToEnd:

    def test_no_findings_returns_valid_response(self):
        stdout, _, rc = _subprocess_run(MINIMAL_REQUEST)
        assert rc == 0
        resp = json.loads(stdout)
        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-001"

    def test_missing_api_key_returns_error_response(self):
        stdout, _, rc = _subprocess_run(REQUEST_WITH_FINDINGS, {"WHY_AI_API_KEY": ""})
        assert rc == 0
        resp = json.loads(stdout)
        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        assert "decisionAdditions" in resp
        summary = resp["decisionAdditions"]["summary"].lower()
        assert "unavailable" in summary

    def test_stdout_is_json_only(self):
        stdout, _, _ = _subprocess_run(MINIMAL_REQUEST)
        parsed = json.loads(stdout)
        assert parsed["requestId"] == "test-001"
        for line in stdout.strip().split("\n"):
            if line.strip():
                assert not line.startswith("["), "Log line leaked to stdout"

    def test_exit_code_zero_on_invalid_json(self):
        env = os.environ.copy()
        env.pop("WHY_AI_API_KEY", None)
        result = subprocess.run(
            [sys.executable, str(WORKER_PATH)],
            input="not valid json",
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        resp = json.loads(result.stdout)
        assert "requestId" in resp

    def test_unsupported_provider_returns_error(self):
        stdout, _, rc = _subprocess_run(
            REQUEST_WITH_FINDINGS,
            {"WHY_AI_PROVIDER": "nonexistent", "WHY_AI_API_KEY": "fake"},
        )
        assert rc == 0
        resp = json.loads(stdout)
        assert resp["version"] == "v1alpha1"
        summary = resp["decisionAdditions"]["summary"].lower()
        assert "unsupported" in summary

    def test_default_provider_is_openai(self):
        """Without WHY_AI_PROVIDER set, should default to openai (shown by api key error)."""
        stdout, _, _ = _subprocess_run(REQUEST_WITH_FINDINGS, {"WHY_AI_API_KEY": ""})
        resp = json.loads(stdout)
        summary = resp["decisionAdditions"]["summary"]
        assert "WHY_AI_API_KEY" in summary or "api key" in summary.lower()
        assert "unsupported" not in summary.lower()

    def test_gemini_provider_missing_key(self):
        """Gemini provider without API key should return error response."""
        stdout, _, rc = _subprocess_run(
            REQUEST_WITH_FINDINGS,
            {"WHY_AI_PROVIDER": "gemini", "WHY_GEMINI_API_KEY": ""},
        )
        assert rc == 0
        resp = json.loads(stdout)
        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        summary = resp["decisionAdditions"]["summary"].lower()
        assert "unavailable" in summary or "gemini" in summary
        assert "WHY_GEMINI_API_KEY" in resp["decisionAdditions"]["summary"]

    def test_gemini_provider_via_env(self):
        """Test Gemini provider selection via WHY_AI_PROVIDER env."""
        # Without API key, should fail with Gemini-specific error
        stdout, _, _ = _subprocess_run(
            REQUEST_WITH_FINDINGS,
            {"WHY_AI_PROVIDER": "gemini"},
        )
        resp = json.loads(stdout)
        summary = resp["decisionAdditions"]["summary"]
        assert "WHY_GEMINI_API_KEY" in summary

    def test_gemini_provider_via_request_param(self):
        """Test Gemini provider selection via request.provider parameter."""
        request = {**REQUEST_WITH_FINDINGS, "provider": "gemini"}
        stdout, _, rc = _subprocess_run(request, {"WHY_GEMINI_API_KEY": ""})
        assert rc == 0
        resp = json.loads(stdout)
        summary = resp["decisionAdditions"]["summary"]
        # Should fail with Gemini key error
        assert "WHY_GEMINI_API_KEY" in summary

    def test_request_provider_overrides_env(self):
        """Request provider parameter should override WHY_AI_PROVIDER env."""
        request = {**REQUEST_WITH_FINDINGS, "provider": "gemini"}
        stdout, _, _ = _subprocess_run(
            request,
            {"WHY_AI_PROVIDER": "openai", "WHY_AI_API_KEY": "fake-openai"},
        )
        resp = json.loads(stdout)
        # Should fail with Gemini key error, not OpenAI
        summary = resp["decisionAdditions"]["summary"]
        assert "WHY_GEMINI_API_KEY" in summary
        assert "WHY_AI_API_KEY" not in summary

    def test_claude_provider_missing_key(self):
        """Claude provider without API key should return error response."""
        stdout, _, rc = _subprocess_run(
            REQUEST_WITH_FINDINGS,
            {"WHY_AI_PROVIDER": "claude", "WHY_CLAUDE_API_KEY": ""},
        )
        assert rc == 0
        resp = json.loads(stdout)
        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        summary = resp["decisionAdditions"]["summary"].lower()
        assert "unavailable" in summary or "claude" in summary
        assert "WHY_CLAUDE_API_KEY" in resp["decisionAdditions"]["summary"]

    def test_claude_provider_via_env(self):
        """Test Claude provider selection via WHY_AI_PROVIDER env."""
        # Without API key, should fail with Claude-specific error
        stdout, _, _ = _subprocess_run(
            REQUEST_WITH_FINDINGS,
            {"WHY_AI_PROVIDER": "claude"},
        )
        resp = json.loads(stdout)
        summary = resp["decisionAdditions"]["summary"]
        assert "WHY_CLAUDE_API_KEY" in summary

    def test_claude_provider_via_request_param(self):
        """Test Claude provider selection via request.provider parameter."""
        request = {**REQUEST_WITH_FINDINGS, "provider": "claude"}
        stdout, _, rc = _subprocess_run(request, {"WHY_CLAUDE_API_KEY": ""})
        assert rc == 0
        resp = json.loads(stdout)
        summary = resp["decisionAdditions"]["summary"]
        # Should fail with Claude key error
        assert "WHY_CLAUDE_API_KEY" in summary


# --- In-process mock tests (no network) ---


class TestMockedEnrichment:

    def test_successful_enrichment(self):
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.return_value = MOCK_AI_RESULT

        resp = _run_in_process(REQUEST_WITH_FINDINGS, mock_provider=mock_provider)

        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        additions = resp["decisionAdditions"]
        assert additions["summary"] == "Pod blocked: running as root"
        assert len(additions["nextActions"]) == 1
        assert additions["nextActions"][0]["title"] == "Set runAsNonRoot"

    def test_ai_failure_returns_error_response(self):
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.side_effect = RuntimeError("API timeout")

        resp = _run_in_process(REQUEST_WITH_FINDINGS, mock_provider=mock_provider)

        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        assert "unavailable" in resp["decisionAdditions"]["summary"].lower()
        assert len(resp["decisionAdditions"]["nextActions"]) > 0

    def test_no_findings_skips_ai(self):
        mock_provider = MagicMock()

        resp = _run_in_process(MINIMAL_REQUEST, mock_provider=mock_provider)

        mock_provider.generate_enrichment.assert_not_called()
        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-001"

    def test_enrichment_with_translations(self):
        result_with_trans = {
            "summary": "Pod blocked: running as root",
            "nextActions": [
                {"title": "Set runAsNonRoot", "detail": "Enable non-root user"},
            ],
            "translations": {
                "summary": "Pod 차단: 루트로 실행 중",
                "nextActions": [
                    {"title": "runAsNonRoot 설정", "detail": "non-root 사용자 활성화"},
                ],
            },
        }
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.return_value = result_with_trans

        request = {**REQUEST_WITH_FINDINGS, "locale": "ko"}
        resp = _run_in_process(request, mock_provider=mock_provider)

        additions = resp["decisionAdditions"]
        assert additions["summary"] == "Pod blocked: running as root"
        assert "translations" in additions
        assert additions["translations"]["summary"] == "Pod 차단: 루트로 실행 중"
        assert len(additions["translations"]["nextActions"]) == 1

    def test_round_trip_preserves_ids(self):
        """Version and requestId must be echoed back exactly."""
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.return_value = MOCK_AI_RESULT

        for req_id in ["abc-123", "req/special-chars", "00000"]:
            request = {
                "version": "v1alpha1",
                "requestId": req_id,
                "input": {
                    "resource": {"kind": "Pod", "name": "x", "namespace": "y"},
                    "policyFindings": [
                        {
                            "policyId": "T-1",
                            "title": "t",
                            "severity": "LOW",
                            "message": "m",
                        }
                    ],
                },
            }
            resp = _run_in_process(request, mock_provider=mock_provider)
            assert resp["requestId"] == req_id
            assert resp["version"] == "v1alpha1"

    def test_gemini_provider_with_mock(self):
        """Test Gemini provider with mocked API response."""
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.return_value = MOCK_AI_RESULT

        request = {**REQUEST_WITH_FINDINGS, "provider": "gemini"}
        resp = _run_in_process(request, mock_provider=mock_provider)

        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        additions = resp["decisionAdditions"]
        assert additions["summary"] == "Pod blocked: running as root"
        assert len(additions["nextActions"]) == 1
        assert additions["nextActions"][0]["title"] == "Set runAsNonRoot"

        # Verify the mock was called with correct parameters
        mock_provider.generate_enrichment.assert_called_once()
        call_args = mock_provider.generate_enrichment.call_args
        policy_findings, resource_info, locale = call_args[0]
        assert locale == "en"
        assert len(policy_findings) == 1
        assert policy_findings[0]["policyId"] == "PSP-001"

    def test_claude_provider_with_mock(self):
        """Test Claude provider with mocked API response."""
        mock_provider = MagicMock()
        mock_provider.generate_enrichment.return_value = MOCK_AI_RESULT

        request = {**REQUEST_WITH_FINDINGS, "provider": "claude"}
        resp = _run_in_process(request, mock_provider=mock_provider)

        assert resp["version"] == "v1alpha1"
        assert resp["requestId"] == "test-002"
        additions = resp["decisionAdditions"]
        assert additions["summary"] == "Pod blocked: running as root"
        assert len(additions["nextActions"]) == 1
        assert additions["nextActions"][0]["title"] == "Set runAsNonRoot"

        # Verify the mock was called with correct parameters
        mock_provider.generate_enrichment.assert_called_once()
        call_args = mock_provider.generate_enrichment.call_args
        policy_findings, resource_info, locale = call_args[0]
        assert locale == "en"
        assert len(policy_findings) == 1
        assert policy_findings[0]["policyId"] == "PSP-001"

    def test_provider_model_logging_to_stderr(self):
        """Verify provider+model is logged to stderr for transparency."""
        mock_provider = MagicMock()
        mock_provider.model = "test-model-123"
        mock_provider.generate_enrichment.return_value = MOCK_AI_RESULT

        stdin_buf = io.StringIO(json.dumps(REQUEST_WITH_FINDINGS))
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        with patch("sys.stdin", stdin_buf), \
             patch("sys.stdout", stdout_buf), \
             patch("sys.stderr", stderr_buf), \
             patch.object(main_module, "create_provider", return_value=mock_provider):
            main_module.main()

        stderr_output = stderr_buf.getvalue()
        # Should log provider=openai (default) and model
        assert "AI: provider=openai model=test-model-123" in stderr_output
        assert "AI: enrichment succeeded" in stderr_output

        # Stdout should still be JSON only
        stdout_buf.seek(0)
        resp = json.loads(stdout_buf.read())
        assert resp["version"] == "v1alpha1"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
