# Worker Protocol Documentation

This document defines the JSON-based integration protocol between the Go application (`kubectl-why`) and the external Python worker.

## Overview

The Go application can optionally delegate or enrich its security decision explanations using a worker. The worker's primary role is to provide better summaries, additional insights, and translations.

**Crucially, the worker cannot change the `allow` or `deny` status of a decision.** It only enriches the existing decision.

## Execution Model

The Go application calls the worker using a standard process execution model:

- **Input**: The Go side writes a `WorkerRequest` JSON to the worker's **stdin**.
- **Output**: The worker writes a `WorkerResponse` JSON to its **stdout**.
- **Lifecycle**: A new worker process may be spawned for each request, or a persistent process could be used if implemented.

## Configuration

The worker command can be specified via environment variables or flags:

- `WHY_WORKER_COMMAND`: Path to the worker executable (e.g., `/usr/local/bin/why-worker` or `python3 main.py`).
- `--worker-command`: CLI flag to override the environment variable.

If no worker is configured, `kubectl-why` operates in rule-only mode.

## Versioning Strategy

The protocol uses a version field (e.g., `v1alpha1`) to ensure compatibility.

- **Additive Changes**: New fields can be added to the request or response without incrementing the major version.
- **Backwards Compatibility**: The Go side must ignore unknown fields in the worker response. The worker should gracefully handle missing optional fields in the request.
- **Breaking Changes**: Any change that removes fields or changes the fundamental structure will require a new version (e.g., `v1`).

## Error Handling

- **Worker Failure**: If the worker exits with a non-zero code, fails to start, or times out, Go continues with the rule-only explanation and logs a warning.
- **Invalid JSON**: If the worker returns malformed JSON or JSON that does not match the schema, Go logs a warning and proceeds without the worker's additions.
- **Missing Request ID**: The worker **must** echo back the `requestId` from the request. If it doesn't match, the response may be discarded.

## JSON Schemas

The following schemas define the contract:

1.  `schemas/security-decision.schema.json`: Represents the core domain model.
2.  `schemas/worker-request.schema.json`: The shape of the request sent to the worker.
3.  `schemas/worker-response.schema.json`: The shape of the response expected from the worker.

## Design Choices

- **JSON Schema Draft 2020-12**: Used for modern features and better tool support.
- **camelCase**: Used for all JSON keys to match the existing Go domain model.
- **RFC3339**: Used for timestamps to ensure standardized date-time representation.
- **Separation of Concerns**: The worker focuses on "enrichment" (summaries, translations, extra actions) while the Go side retains authority over the final `status` (ALLOWED/BLOCKED).
- **Extensibility**: `additionalProperties: true` is allowed for `metadata` and `raw` fields to support future data types without schema updates.
