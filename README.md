# K8s Policy Enforcer

Kubernetes policy enforcement engine for scanning manifest files against security, network, resource, and pod policies.

## Problem

Kubernetes policy enforcement is fragmented across multiple tools (OPA/Gatekeeper, Kyverno) with different approaches. This tool provides a standalone scanner that evaluates Kubernetes manifests against a configurable set of policies, suitable for CI/CD pipelines and pre-commit hooks.

## Features

- Security context validation (privileged containers, run as non-root, read-only filesystem, privilege escalation)
- Network policy detection
- Resource limit and request validation
- Pod security checks (host network, host PID, host IPC, service account token auto-mount)
- Image tag validation (no `latest` tag enforcement)
- Service account validation
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW
- Enforcement levels: strict, warn, audit
- Namespace filtering
- Dry-run mode

## Installation

### Build from source

```bash
go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer
```

### Docker

```bash
docker build -t k8s-policy-enforcer .
docker run --rm -v $(pwd)/manifests:/manifests k8s-policy-enforcer --dir=/manifests
```

## Usage

```bash
# Scan manifests in current directory
./k8s-policy-enforcer --dir=./k8s-manifests

# Fail on strict violations only (default)
./k8s-policy-enforcer --dir=./k8s-manifests --fail-strict=true --fail-warn=false

# Scan specific namespace
./k8s-policy-enforcer --dir=./k8s-manifests --namespace=production

# Dry run (no exit code impact)
./k8s-policy-enforcer --dir=./k8s-manifests --dry-run

# Verbose output
./k8s-policy-enforcer --dir=./k8s-manifests --verbose
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--dir` | Directory containing Kubernetes manifests | `.` |
| `--fail-strict` | Fail if strict violations found | `true` |
| `--fail-warn` | Fail if warning violations found | `false` |
| `--namespace` | Namespace to evaluate (`*` for all) | `*` |
| `--dry-run` | Dry run mode | `false` |
| `--verbose` | Verbose output | `false` |

## Policies

The following policies are evaluated against each resource:

### Security Context

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-SEC-001 | No Privileged Containers | CRITICAL | strict | `securityContext.privileged` must be false |
| K8S-SEC-002 | Run as Non-Root | HIGH | strict | `securityContext.runAsNonRoot` must be true |
| K8S-SEC-003 | Read-Only Root Filesystem | MEDIUM | warn | `securityContext.readOnlyRootFilesystem` must be true |
| K8S-SEC-004 | No Allow Privilege Escalation | HIGH | strict | `securityContext.allowPrivilegeEscalation` must be false |

### Network

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-NET-001 | Network Policies Required | MEDIUM | warn | NetworkPolicy resource should be present |

### Resources

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-RES-001 | Resource Limits Required | MEDIUM | warn | `resources.limits` must be defined |
| K8S-RES-002 | Resource Requests Required | LOW | warn | `resources.requests` must be defined |

### Pod Security

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-POD-001 | No Host Network | HIGH | strict | `hostNetwork` must be false |
| K8S-POD-002 | No Host PID | HIGH | strict | `hostPID` must be false |
| K8S-POD-003 | No Host IPC | HIGH | strict | `hostIPC` must be false |
| K8S-POD-004 | Automount Service Account Token | MEDIUM | warn | `automountServiceAccountToken` must be false |

### Image Security

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-IMG-001 | No Latest Tag | MEDIUM | warn | Image tag must not be `latest` |
| K8S-IMG-002 | Image Pull Policy | LOW | warn | `imagePullPolicy` should be specified |

### Service Accounts

| ID | Name | Severity | Enforcement | Rule |
|----|------|----------|-------------|------|
| K8S-SA-001 | No Default Service Account | MEDIUM | warn | `serviceAccountName` must not be `default` |

## CI/CD Integration

### GitHub Actions

```yaml
name: Kubernetes Policy Check
on: [push, pull_request]

jobs:
  policy-enforcement:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build k8s-policy-enforcer
        run: go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer

      - name: Run policy enforcement
        run: ./k8s-policy-enforcer --dir=./k8s-manifests --fail-strict=true
```

### GitLab CI

```yaml
k8s-policy-check:
  stage: security
  image: golang:1.21
  script:
    - go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer
    - ./k8s-policy-enforcer --dir=./k8s-manifests --fail-strict=true
```

## Testing

```bash
make test
```

This runs all unit tests with race detection and coverage reporting.

## Report Output

The tool outputs a structured report showing:

- Total policies defined and checks performed
- Compliance rate percentage
- Violations grouped by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Violations grouped by enforcement level (strict, warn, audit)
- Detailed violation information including policy ID, resource details, field values, and remediation suggestions

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed or no violations at configured levels |
| 1 | Violations found at the configured failure level |

## License

MIT License
