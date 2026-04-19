# kubectl-why

A kubectl plugin that explains why Kubernetes resources are blocked and guides you to the fix.

## What it does

- Evaluates manifests against 14 security rules + 1 advisory, all grounded in CIS Kubernetes Benchmark and Pod Security Standards
- Detects which admission system blocked your resource: PSA, Kyverno, Gatekeeper, RBAC, or a generic admission webhook
- Shows concrete YAML fix examples with standard references

## Quick start

```bash
# Check a manifest before deploying
kubectl why eval -f deployment.yaml

# Find out why kubectl apply was rejected
kubectl apply -f pod.yaml 2>&1 | kubectl why diagnose -
```

## Installation

```bash
# From source
go install github.com/opensource-alison/why-blocked/cmd/why@latest
```

Or download a binary from the [Releases](../../releases) page.

## Commands

| Command | Description |
| --- | --- |
| `eval -f <file>` | Evaluate a manifest against security rules |
| `diagnose` | Identify which admission system blocked a resource |
| `explain <name>` | Explain why a saved resource was blocked (assumes `Deployment`) |
| `explain <kind> <name>` | Explain why a saved resource was blocked for an explicit kind |
| `decision list` | List recent security decisions |
| `decision get <id>` | Get details of a specific decision |
| `mock create <name>` | Create a mock decision for testing |
| `help [topic]` | Show detailed help for a topic |
| `version` | Show version information |

## Security rules

| Rule ID | Check | Severity | Standards |
| --- | --- | --- | --- |
| `POL-SEC-001` | Privileged container | `CRITICAL` | `CIS 5.2.1`, `PSA restricted` |
| `POL-SEC-002` | HostPath volume | `HIGH` | `CIS 5.2.8`, `PSA baseline` |
| `POL-SEC-003` | Missing `runAsNonRoot` | `HIGH` | `CIS 5.2.6`, `PSA restricted` |
| `POL-SEC-004` | Latest image tag | `HIGH` | `CIS 5.5.1` |
| `POL-SEC-005` | `hostPID` | `HIGH` | `CIS 5.2.2`, `PSA baseline` |
| `POL-SEC-006` | `hostNetwork` | `HIGH` | `CIS 5.2.4`, `PSA baseline` |
| `POL-SEC-007` | `hostIPC` | `HIGH` | `CIS 5.2.3`, `PSA baseline` |
| `POL-SEC-008` | Dangerous capabilities | `HIGH` | `CIS 5.2.7`, `PSA restricted` |
| `POL-SEC-009` | `allowPrivilegeEscalation` not disabled | `MEDIUM` | `CIS 5.2.5`, `PSA restricted` |
| `POL-SEC-010` | Runs as root (UID 0) | `HIGH` | `CIS 5.2.6`, `PSA restricted` |
| `POL-RBAC-001` | Wildcard RBAC permissions | `CRITICAL` | `CIS 5.1.3` |
| `POL-RBAC-002` | Unrestricted secret access | `HIGH` | `CIS 5.1.2` |
| `POL-RBAC-003` | `pods/exec` permission | `HIGH` | `CIS 5.1.3` |
| `POL-RBAC-004` | `cluster-admin` binding | `CRITICAL` | `CIS 5.1.1` |
| `ADV-NET-001` | NetworkPolicy not verified | `INFO` | `CIS 5.3.2` |

Every rule references a published security standard. INFO-level advisories do not affect the exit code or block status.

## Supported resources

The evaluator handles these Kubernetes resource types:

- Pod-like: `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ReplicaSet`
- RBAC: `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`

## Policy engine detection

| Engine | Confidence |
| --- | --- |
| Pod Security Admission (PSA) | High |
| Kyverno | High |
| Gatekeeper / OPA | High |
| RBAC Forbidden | High |
| Generic Webhook | Medium |

```bash
kubectl apply -f pod.yaml 2>&1 | kubectl why diagnose -

# Combined: detect blocker + evaluate manifest
kubectl why diagnose --error "denied the request" -f pod.yaml
```

## Output formats

`--output text` is the default:

```text
$ kubectl why eval -f testdata/safe-deployment.yaml
WHY: Resource meets security requirements with 1 advisory
STATUS: ALLOWED
```

Use `--output json` for automation:

```json
{
  "schemaVersion": "v1",
  "decision": {
    "status": "ALLOWED",
    "violations": [
      {
        "policyId": "ADV-NET-001",
        "severity": "INFO"
      }
    ]
  }
}
```

## Languages

5 languages are supported with 119 localized strings each:

- `en`
- `ko`
- `ja`
- `zh`
- `es`

```bash
kubectl why eval -f pod.yaml --lang ko
```

## Optional features

### AI enhancement

```bash
export WHY_AI_API_KEY=your-key
kubectl why eval -f pod.yaml --ai
```

AI changes presentation only. It does not change rule evaluation, severity, or exit codes. The bundled worker supports OpenAI, Gemini, and Claude providers.

### CVE / SBOM scanning

```bash
kubectl why eval -f pod.yaml --scan cve,sbom
```

Requires `trivy` and/or `syft` to be installed.

## Design principles

- Offline-first: core evaluation and diagnosis work without cluster access or external services
- Evidence-based: when evidence is insufficient, detection returns `Unknown` instead of guessing
- Standards-grounded: every rule cites CIS or PSA; there is no subjective scoring
- Explanation engine: it complements admission controllers, it does not replace them

## Project structure

- `cmd/why/` — CLI entry point and subcommands
- `internal/eval/` — offline rule evaluator
- `internal/detect/` — admission blocker detection engine
- `internal/decision/` — decision schema and stored decision types
- `internal/output/` — text and JSON rendering
- `internal/i18n/` — embedded locale files and translation loading
- `internal/repository/` — local decision storage
- `internal/scan/` — Trivy and Syft integration
- `internal/ui/` — terminal colors and formatting
- `tools/why-worker/` — optional Python AI worker

## License

MIT License. See [LICENSE](LICENSE).
