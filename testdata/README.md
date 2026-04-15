# Test data for `kubectl why eval`

This directory contains sample Kubernetes manifests used by tests and manual CLI verification.

## Fixtures

### `privileged-deployment.yaml`

- Status: `BLOCKED`
- Expected findings:
  - `POL-SEC-001` (`CRITICAL`) Privileged container
  - `POL-SEC-003` (`HIGH`) Missing `runAsNonRoot`
  - `POL-SEC-009` (`MEDIUM`) `allowPrivilegeEscalation` not disabled
  - `ADV-NET-001` (`INFO`) NetworkPolicy not verified

```bash
kubectl why eval -f testdata/privileged-deployment.yaml
```

### `safe-deployment.yaml`

- Status: `ALLOWED`
- Expected findings:
  - `ADV-NET-001` (`INFO`) NetworkPolicy not verified

```bash
kubectl why eval -f testdata/safe-deployment.yaml
```

### `hostpath-deployment.yaml`

- Status: `BLOCKED`
- Expected findings:
  - `POL-SEC-002` (`HIGH`) HostPath volume
  - `POL-SEC-003` (`HIGH`) Missing `runAsNonRoot`
  - `POL-SEC-009` (`MEDIUM`) `allowPrivilegeEscalation` not disabled
  - `ADV-NET-001` (`INFO`) NetworkPolicy not verified

```bash
kubectl why eval -f testdata/hostpath-deployment.yaml
```

### `job-privileged.yaml`

- Status: `BLOCKED`
- Expected findings:
  - `POL-SEC-001` (`CRITICAL`) Privileged container
  - `POL-SEC-003` (`HIGH`) Missing `runAsNonRoot`
  - `POL-SEC-009` (`MEDIUM`) `allowPrivilegeEscalation` not disabled
  - `ADV-NET-001` (`INFO`) NetworkPolicy not verified

```bash
kubectl why eval -f testdata/job-privileged.yaml
```

### `cronjob-privileged.yaml`

- Status: `BLOCKED`
- Expected findings:
  - `POL-SEC-001` (`CRITICAL`) Privileged container
  - `POL-SEC-003` (`HIGH`) Missing `runAsNonRoot`
  - `POL-SEC-009` (`MEDIUM`) `allowPrivilegeEscalation` not disabled
  - `ADV-NET-001` (`INFO`) NetworkPolicy not verified

```bash
kubectl why eval -f testdata/cronjob-privileged.yaml
```

## Expected results

| File | Status | Findings | Exit code |
| --- | --- | --- | --- |
| `privileged-deployment.yaml` | `BLOCKED` | 4 | `2` |
| `safe-deployment.yaml` | `ALLOWED` | 1 INFO advisory | `0` |
| `hostpath-deployment.yaml` | `BLOCKED` | 4 | `2` |
| `job-privileged.yaml` | `BLOCKED` | 4 | `2` |
| `cronjob-privileged.yaml` | `BLOCKED` | 4 | `2` |
