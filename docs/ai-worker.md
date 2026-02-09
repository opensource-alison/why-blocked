# why-worker: AI Enrichment Worker for kubectl-why

Python worker that provides AI-powered enrichment for kubectl-why security decisions.

## Overview

This worker is **optional** and only used when `--ai` flag is enabled in the kubectl-why CLI. The CLI works completely offline without it.

### What it does
- Reads one JSON request from STDIN
- Generates AI-powered summaries and action items
- Writes one JSON response to STDOUT
- Always exits with code 0 (errors returned as valid JSON responses)

### What it does NOT do
- Does NOT change decision outcomes (BLOCKED/ALLOWED status)
- Does NOT modify technical identifiers (CVE IDs, K8s paths, image refs, policy IDs)
- Only enriches with: summaries, explanations, translations, suggested actions

## Usage

### Basic usage
```bash
cat request.json | python3 tools/why-worker/main.py > response.json
```

### With OpenAI (default)
```bash
export WHY_AI_API_KEY="your-openai-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### With Gemini via environment variable
```bash
export WHY_AI_PROVIDER="gemini"
export WHY_GEMINI_API_KEY="your-gemini-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### With Gemini via request parameter
```bash
export WHY_GEMINI_API_KEY="your-gemini-api-key"
# Add "provider": "gemini" to your request.json
cat request.json | python3 tools/why-worker/main.py > response.json
```

### With Claude via environment variable
```bash
export WHY_AI_PROVIDER="claude"
export WHY_CLAUDE_API_KEY="your-claude-api-key"
cat request.json | python3 tools/why-worker/main.py > response.json
```

### With Claude via request parameter
```bash
export WHY_CLAUDE_API_KEY="your-claude-api-key"
# Add "provider": "claude" to your request.json
cat request.json | python3 tools/why-worker/main.py > response.json
```

### Example request
```json
{
  "version": "v1alpha1",
  "requestId": "req-123",
  "locale": "en",
  "provider": "gemini",
  "input": {
    "resource": {
      "kind": "Pod",
      "name": "nginx",
      "namespace": "default"
    },
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
            "detail": "false"
          }
        ]
      }
    ]
  }
}
```

### Example response
```json
{
  "version": "v1alpha1",
  "requestId": "req-123",
  "decisionAdditions": {
    "summary": "- Pod blocked due to HIGH severity security policy violation\n- Container configured to run as root user (spec.securityContext.runAsNonRoot=false)\n- This violates PSP-001 policy",
    "nextActions": [
      {
        "title": "Enable non-root user constraint",
        "detail": "Set spec.securityContext.runAsNonRoot to true in your Pod spec"
      },
      {
        "title": "Specify a non-root user ID",
        "detail": "Add spec.securityContext.runAsUser with a value > 0 (e.g., 1000)"
      }
    ]
  }
}
```

## Configuration

### Environment Variables

#### Provider Selection
- `WHY_AI_PROVIDER`: AI provider to use (default: `openai`)
  - Supported values: `openai`, `gemini`, `claude`
  - Can also be specified in request JSON via `"provider": "claude"`
  - Priority: request parameter > env variable > default (`openai`)
  - If unsupported provider specified, returns schema-valid error response

#### API Keys
- **OpenAI**: `WHY_AI_API_KEY`
  - Your OpenAI API key (e.g., `sk-...`)
  - Used when `WHY_AI_PROVIDER=openai` (default)

- **Gemini**: `WHY_GEMINI_API_KEY`
  - Your Google Generative AI API key
  - Used when `WHY_AI_PROVIDER=gemini` or `"provider": "gemini"` in request
  - Get your key at: https://makersuite.google.com/app/apikey

- **Claude**: `WHY_CLAUDE_API_KEY`
  - Your Anthropic API key
  - Used when `WHY_AI_PROVIDER=claude` or `"provider": "claude"` in request
  - Get your key at: https://console.anthropic.com/

#### Optional Configuration
- `WHY_GEMINI_MODEL`: Override default Gemini model (default: `gemini-1.5-flash`)
  - Other options: `gemini-1.5-pro`, `gemini-1.5-flash-8b`
- `WHY_CLAUDE_MODEL`: Override default Claude model (default: `claude-3-5-haiku-20241022`)
  - Other options: `claude-3-5-sonnet-20241022`, `claude-3-opus-20240229`
- Note: OpenAI model defaults to `gpt-4o`. Override via code if needed (no env var currently)

### Supported Locales
- `en` - English (default)
- `ko` - Korean
- `ja` - Japanese
- `zh` - Chinese
- `es` - Spanish

Translations are included in the `translations` field when locale is not English.

## Architecture

### Components
```
tools/why-worker/
├── main.py              # Entrypoint (stdin → stdout)
├── models.py            # Schema-matching data models
├── prompt.py            # Deterministic prompt builder
├── providers/
│   ├── __init__.py      # AI provider interface & factory
│   ├── openai.py        # OpenAI implementation
│   ├── gemini.py        # Google Gemini implementation
│   └── claude.py        # Anthropic Claude implementation
└── tests/
    └── test_worker.py   # Comprehensive tests (25 tests)
```

### Provider Selection

Providers are selected with the following priority:
1. **Request parameter**: `"provider": "gemini"` in request JSON (highest priority)
2. **Environment variable**: `WHY_AI_PROVIDER=gemini`
3. **Default**: `openai` (lowest priority)

The worker uses a factory pattern in `providers/__init__.py:create_provider()` to instantiate the correct provider.

**Supported providers:**
- `openai` - OpenAI GPT models (default: `gpt-4o`)
- `gemini` - Google Generative AI (default: `gemini-1.5-flash`)
- `claude` - Anthropic Claude models (default: `claude-3-5-haiku-20241022`)

**To add a new provider:**
1. Implement `AIProvider` protocol in `providers/yourprovider.py`
2. Add factory function `create_yourprovider_provider()`
3. Update `providers/__init__.py:create_provider()` to add the new provider case
4. Update the `SUPPORTED_PROVIDERS` list
5. Add tests for provider selection and error handling

See `ADDING_PROVIDERS.md` for detailed instructions.

## Development

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run tests
```bash
cd tools/why-worker
python -m pytest tests/ -v
```

### Test coverage
- Schema compliance (request/response parsing)
- End-to-end stdin → stdout flow
- Error handling (missing API key, invalid JSON, etc.)
- Exit code 0 verification
- Stdout JSON-only verification (no logs)
- AI enrichment with mocked providers

### Design Principles
1. **Minimal dependencies**: Uses Python stdlib (json, urllib, etc.)
2. **Schema-first**: Exact match with `schemas/*.schema.json`
3. **Fail-safe**: Always returns valid response, never crashes
4. **Pluggable**: Easy to add new AI providers
5. **Testable**: All network calls are mockable

## Schema Sources of Truth

The worker strictly follows these schemas:
- `schemas/worker-request.schema.json` - Input format
- `schemas/worker-response.schema.json` - Output format
- `schemas/security-decision.schema.json` - Security decision structure

**Never** invent field names or change casing. Use exact camelCase as defined in schemas.

## Critical Rules (Embedded in Prompts)

When generating AI enrichment:
1. **DO NOT** translate technical identifiers:
   - CVE IDs (CVE-2024-1234)
   - K8s field paths (spec.containers[0].image)
   - JSONPath expressions
   - Image references (nginx:latest)
   - Policy IDs
   - File paths
   - Resource names/kinds/namespaces

2. **ONLY** translate human-readable sentences

3. Keep summaries developer-friendly (3-6 short lines)

4. Provide 3-6 concrete, prioritized actions

## Logging

- All logs go to **stderr** only
- stdout is reserved for JSON response only
- Log format: `[why-worker] message`

## Error Handling

- Invalid JSON input → returns error in summary field
- Missing API key → returns actionable error response
- AI timeout/failure → returns error response with manual fallback action
- Always exits with code 0 for graceful Go fallback
