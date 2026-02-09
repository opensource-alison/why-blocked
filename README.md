# kubectl-why

**Fast, offline Kubernetes security decision explainer.**

kubectl-why explains **why a Kubernetes resource was blocked** by security policies using static analysis and clear, human-readable output.

It's a **reasoning CLI**, not a scanner. It works **offline by default** and integrates naturally as a **kubectl plugin**.

---

## Installation

### Via Krew (Recommended)

```bash
kubectl krew install why
```

### Manual Installation

Download the latest binary from [GitHub Releases](https://github.com/opensource-alison/why-blocked/releases):

```bash
# macOS/Linux
curl -LO https://github.com/opensource-alison/why-blocked/releases/latest/download/kubectl-why-$(uname -s)-$(uname -m)
chmod +x kubectl-why-*
sudo mv kubectl-why-* /usr/local/bin/kubectl-why

# Verify installation
kubectl why version
```

### From Source

Build from source (developer): see the Usage Guide for build notes: [docs/usage-guide.md](docs/usage-guide.md).

---

## Quick Start

```bash
# Explain why a resource was blocked
kubectl why explain deployment my-app

# List recent security decisions
kubectl why decision list

# Get details of a specific decision
kubectl why decision get <decision-id>

# Evaluate a manifest file (offline, no cluster needed)
kubectl why eval -f deployment.yaml

# Create a test decision to explore the tool
kubectl why mock create test-app
kubectl why explain test-app
```

---

## Features

- ✅ **Offline-first** – Works without cluster access via `eval` command
  - ✅ **Fast static analysis** – Explains blocking decisions in milliseconds
  - ✅ **Human-readable output** – Clear violations, evidence, and fix suggestions
  - ✅ **Multi-language support** – Output in English, Korean, Japanese, Chinese, Spanish
  - ✅ **JSON output** – Structured data for CI/CD automation
  - ✅ **Optional AI explanations** – Enhanced summaries via `--ai` flag
  - ✅ **Optional CVE/SBOM scanning** – Attach live scan results via `--scan` flag

---

## Common Commands

| Command | Description |
|---------|-------------|
| `kubectl why explain <name>` | Explain why a Deployment was blocked (assumes kind=Deployment) |
| `kubectl why explain pod <name>` | Explain why a Pod was blocked |
| `kubectl why decision list` | List recent security decisions (up to 10) |
| `kubectl why decision get <id>` | Retrieve a specific decision by ID |
| `kubectl why eval -f <file>` | Evaluate a YAML manifest offline (no cluster needed) |
| `kubectl why mock create <name>` | Create a mock blocked decision for testing |
| `kubectl why help` | Show all help topics |
| `kubectl why version` | Show version information |

---

## Output Examples

### Text Output (Default)

```bash
$ kubectl why explain deployment my-app

WHY: Resource blocked: 1 critical, 1 high severity violations found
STATUS: BLOCKED

RESOURCE: Deployment/my-app
NAMESPACE: production
DECISION: dec-a1b2c3d4
TIME: 2026-02-09T10:30:00Z

VIOLATIONS (2):
1) [CRITICAL] Privileged Container
   What: Container 'nginx' runs in privileged mode, which grants access to all
   host devices and bypasses security boundaries.
   Evidence:
     - (K8S_FIELD) spec.template.spec.containers[0].securityContext.privileged:
       privileged: true
   Fix (minimal):
     - Disable privileged mode: Set securityContext.privileged: false

2) [HIGH] Missing runAsNonRoot
   What: Container 'nginx' does not enforce running as a non-root user.
   Evidence:
     - (K8S_FIELD) spec.template.spec.containers[0].securityContext.runAsNonRoot:
       not set or false
   Fix (minimal):
     - Set securityContext.runAsNonRoot: true for container 'nginx'
```

### JSON Output

```bash
$ kubectl why explain deployment my-app -o json

{
  "schemaVersion": "v1",
  "decision": {
    "id": "dec-a1b2c3d4",
    "timestamp": "2026-02-09T10:30:00Z",
    "status": "BLOCKED",
    "summary": "Resource blocked: 1 critical, 1 high severity violations found",
    "resource": {
      "kind": "Deployment",
      "name": "my-app",
      "namespace": "production"
    },
    "violations": [...]
  }
}
```

---

## Optional Features

### Multi-Language Output

```bash
# Korean
kubectl why --lang ko explain deployment my-app

# Japanese
kubectl why --lang ja explain deployment my-app

# Chinese
kubectl why --lang zh explain deployment my-app

# Spanish
kubectl why --lang es explain deployment my-app
```

Supported languages: `en` (default), `ko`, `ja`, `zh`, `es`

Language is auto-detected from `LC_ALL` or `LANG` environment variables if `--lang` is not specified.

### AI-Powered Explanations

Add AI-generated summaries and action items:

```bash
# Set API key
export WHY_AI_API_KEY=your-openai-api-key

# Get AI-enhanced explanation
kubectl why --ai explain deployment my-app
```

**Requirements:**
- Python 3.x installed (auto-detected as `python3` or `python`)
  - OpenAI API key (or compatible provider)

**Optional configuration:**
```bash
# Use custom Python path
export WHY_WORKER_COMMAND="python3 /path/to/worker/main.py"

# Use different AI provider
export WHY_AI_PROVIDER=gemini
export WHY_GEMINI_API_KEY=your-gemini-key
```

See [docs/ai-worker-dev.md](docs/ai-worker-dev.md) for detailed setup.

### External Vulnerability Scanning

Attach live CVE and SBOM data from external scanners:

```bash
# CVE scanning (requires trivy)
kubectl why --scan cve explain deployment my-app

# SBOM generation (requires syft)
kubectl why --scan sbom explain deployment my-app

# Both scanners
kubectl why --scan cve,sbom explain deployment my-app
```

**Installation:**
```bash
# macOS
brew install trivy syft

# Linux
# See https://trivy.dev and https://github.com/anchore/syft
```

If scanners are not installed, kubectl-why will warn and continue without scan data.

---

## Offline Manifest Evaluation

Evaluate Kubernetes YAML files without cluster access:

```bash
# Evaluate a deployment manifest
kubectl why eval -f deployment.yaml

# Evaluate with JSON output
kubectl why -o json eval -f deployment.yaml

# Override namespace
kubectl why eval -f deployment.yaml -n production
```

**Exit codes:**
- `0` = ALLOWED (resource meets security requirements)
  - `1` = ERROR (invalid file, parse error, etc.)
  - `2` = BLOCKED (resource has security violations)

**CI/CD Integration:**
```bash
#!/bin/bash
# Fail pipeline if any manifest violates security policies
for manifest in k8s/*.yaml; do
    if ! kubectl why eval -f "$manifest"; then
        echo "❌ FAILED: $manifest has security violations"
        exit 1
    fi
done
echo "✅ All manifests passed security checks"
```

See [docs/usage-guide.md](docs/usage-guide.md) for comprehensive examples.

---

## Security Policies

kubectl-why evaluates resources against these policies:

| Policy ID | Severity | Check |
|-----------|----------|-------|
| POL-SEC-001 | CRITICAL | Privileged containers |
| POL-SEC-002 | HIGH | HostPath volumes |
| POL-SEC-003 | HIGH | Missing runAsNonRoot setting |
| POL-SEC-004 | HIGH | Image tag is `:latest` or missing |

---

## Global Flags

```bash
--dir <path>          Decision storage directory (default: ~/.kubectl-why/decisions)
--lang <code>         Output language: en, ko, ja, zh, es (auto-detected if not set)
-o, --output <fmt>    Output format: text, json (default: text)
--scan <modes>        Enable scanners: cve, sbom (comma-separated)
--ai                  Add AI-generated explanation (requires WHY_AI_API_KEY)
--quiet               Suppress status messages (keeps warnings/errors)
--no-color            Disable colored output
```

---

## Documentation

- **[Usage Guide](docs/usage-guide.md)** – Comprehensive command reference and examples
- **[AI Worker (Dev Notes)](docs/ai-worker-dev.md)** – Optional AI enrichment setup & worker integration notes
- **[Extending AI Providers](docs/extending-ai-providers.md)** – Developer guide to add new AI providers

---

## Philosophy

kubectl-why is intentionally focused:

- **Fast and local** – Offline-first, no external dependencies by default
  - **Explains decisions** – Not a scanner, not a platform, not a runtime analyzer
  - **Human-readable** – Clear reasoning over technical dumps
  - **Minimal scope** – Answers "Why was this blocked?" and nothing more

---

## Examples

### Example 1: Check why a deployment was blocked

```bash
kubectl why explain deployment nginx-app
```

### Example 2: List recent decisions

```bash
kubectl why decision list
```

### Example 3: Get decision details in Korean

```bash
kubectl why --lang ko decision get dec-12345
```

### Example 4: Evaluate manifest in CI/CD

```bash
kubectl why eval -f k8s/deployment.yaml
if [ $? -eq 2 ]; then
  echo "Deployment has security violations"
  exit 1
fi
```

### Example 5: AI-enhanced explanation with CVE scanning

```bash
export WHY_AI_API_KEY=sk-...
kubectl why --ai --scan cve explain deployment my-app
```

---

## Support

- **Issues:** https://github.com/opensource-alison/why-blocked/issues
  - **Discussions:** https://github.com/opensource-alison/why-blocked/discussions
  - **Documentation:** Run `kubectl why help` for built-in help
---

## License

MIT – See [LICENSE](LICENSE) for details.
