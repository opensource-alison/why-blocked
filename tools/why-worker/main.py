#!/usr/bin/env python3
"""Worker for kubectl-why AI enrichment. Reads JSON stdin, writes JSON stdout, logs to stderr."""

import sys
import json
import os
from typing import Optional

from models import (
    WorkerRequest,
    WorkerResponse,
    DecisionAdditions,
    NextAction,
    Translations,
    ActionTranslation,
    dict_to_worker_request,
    to_json_dict,
)
from providers import create_provider


def log(msg: str) -> None:
    print(f"[why-worker] {msg}", file=sys.stderr, flush=True)


def write_response(response: WorkerResponse) -> None:
    json.dump(to_json_dict(response), sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.stdout.flush()


def error_response(version: str, request_id: str, message: str) -> WorkerResponse:
    """Create schema-valid error response with concise, actionable message."""
    concise_msg = message[:200] + "..." if len(message) > 200 else message
    return WorkerResponse(
        version=version,
        requestId=request_id,
        decisionAdditions=DecisionAdditions(
            summary=f"AI enrichment unavailable: {concise_msg}",
            nextActions=[
                NextAction(
                    title="Review findings manually",
                    detail="AI enrichment failed. Please review the policy findings directly.",
                )
            ],
        ),
    )


def enrich(request: WorkerRequest) -> Optional[DecisionAdditions]:
    """Attempt AI enrichment. Returns None if no findings to enrich."""
    findings = request.input.policyFindings
    if not findings:
        log("No policy findings, skipping AI enrichment")
        return None

    locale = request.locale or "en"
    resource = request.input.resource

    provider_name = request.provider or os.environ.get("WHY_AI_PROVIDER", "openai")
    provider = create_provider(provider_name)

    model_name = getattr(provider, "model", "unknown")
    log(f"AI: provider={provider_name} model={model_name}")

    findings_dicts = [
        {
            "policyId": f.policyId,
            "title": f.title,
            "severity": f.severity,
            "message": f.message,
            "evidence": [to_json_dict(e) for e in f.evidence],
        }
        for f in findings
    ]
    resource_info = {
        "kind": resource.kind,
        "name": resource.name,
        "namespace": resource.namespace,
    }

    result = provider.generate_enrichment(findings_dicts, resource_info, locale)
    log(f"AI: enrichment succeeded")
    return _parse_additions(result, locale)


def _parse_additions(result: dict, locale: str) -> DecisionAdditions:
    """Convert raw AI result dict into DecisionAdditions model."""
    next_actions = [
        NextAction(title=a["title"], detail=a["detail"])
        for a in result.get("nextActions", [])
    ]

    translations = None
    if locale != "en" and "translations" in result:
        trans = result["translations"]
        trans_actions = [
            ActionTranslation(title=a["title"], detail=a["detail"])
            for a in trans.get("nextActions", [])
        ]
        translations = Translations(
            summary=trans.get("summary"),
            nextActions=trans_actions or None,
        )

    return DecisionAdditions(
        summary=result.get("summary", ""),
        nextActions=next_actions or None,
        translations=translations,
    )


def main() -> None:
    version, request_id = "v1alpha1", "unknown"
    try:
        request_data = json.load(sys.stdin)
        version = request_data.get("version", version)
        request_id = request_data.get("requestId", request_id)
        log(f"Processing request {request_id} (version={version})")

        request = dict_to_worker_request(request_data)
        additions = enrich(request)

        write_response(WorkerResponse(
            version=version,
            requestId=request_id,
            decisionAdditions=additions,
        ))
        log("Response written successfully")
    except Exception as e:
        log(f"Error: {e}")
        write_response(error_response(version, request_id, str(e)))


if __name__ == "__main__":
    main()
    sys.exit(0)
