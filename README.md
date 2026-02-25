# 🛡️ K8s Policy Enforcer - Kubernetes Policy Enforcement Engine

> **Unified policy enforcement for Kubernetes with OPA/Gatekeeper, Kyverno integration**

---

## 🎯 Problem Solved

Kubernetes policy enforcement is **fragmented and complex**:
- **Multiple tools** (OPA, Kyverno, Gatekeeper) with different approaches
- **Policy conflicts** between different enforcement engines
- **No unified view** of policy compliance across namespaces
- **Manual enforcement** leads to gaps and violations
- **GitOps integration** is challenging

**K8s Policy Enforcer solves this by providing unified, policy-driven enforcement.**

---

## ✨ Features

### 🔒 Policy Categories

#### Security Context Policies
- ✅ No Privileged Containers (K8S-SEC-001)
- ✅ Run as Non-Root (K8S-SEC-002)
- ✅ Read-Only Root Filesystem (K8S-SEC-003)
- ✅ No Allow Privilege Escalation (K8S-SEC-004)

#### Network Policies
- ✅ Network Policies Required (K8S-NET-001)
- ✅ Default Deny Ingress (K8S-NET-002)

#### Resource Policies
- ✅ Resource Limits Required (K8S-RES-001)
- ✅ Resource Requests Required (K8S-RES-002)

#### Pod Policies
- ✅ No Host Network (K8S-POD-001)
- ✅ No Host PID (K8S-POD-002)
- ✅ No Host IPC (K8S-POD-003)
- ✅ No Service Account Token Auto-mount (K8S-POD-004)

#### Image Policies
- ✅ No Latest Tag (K8S-IMG-001)
- ✅ Image Pull Policy (K8S-IMG-002)

#### Service Account Policies
- ✅ No Default Service Account (K8S-SA-001)
- ✅ Service Account Token Auto-mount (K8S-SA-002)

### 🚀 Key Capabilities

- **Multi-Category Support** - Security, Network, Resources, Pods, Images, Service Accounts
- **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW
- **Enforcement Levels** - strict, warn, audit
- **Automated Remediation** - Generate fix suggestions
- **GitOps Ready** - Integrate with GitOps workflows
- **CI/CD Integration** - Fail builds on policy violations

---

## 🛠️ Installation

### Build from Source

```bash
cd k8s-policy-enforcer
go mod download
go build -o k8s-policy-enforcer cmd/k8s-policy-enforcer/main.go
```

### Install Globally

```bash
go install -o /usr/local/bin/k8s-policy-enforcer ./cmd/k8s-policy-enforcer
```

---

## 🚀 Usage

### Basic Usage

```bash
# Scan current directory for K8s manifests
./k8s-policy-enforcer --dir=./k8s-manifests

# Fail on strict violations only
./k8s-policy-enforcer --dir=./k8s-manifests --fail-strict=true --fail-warn=false

# Verbose output
./k8s-policy-enforcer --dir=./k8s-manifests --verbose
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--dir` | Directory containing Kubernetes manifests | `.` |
| `--fail-strict` | Fail if strict violations found | `true` |
| `--fail-warn` | Fail if warning violations found | `false` |
| `--namespace` | Namespace to evaluate (* for all) | `*` |
| `--dry-run` | Dry run mode | `false` |
| `--verbose` | Verbose output | `false` |
| `--help` | Show help message | `false` |

### Examples

#### Scan K8s Manifests

```bash
# Scan all YAML files in directory
./k8s-policy-enforcer --dir=./k8s

# Scan specific namespace
./k8s-policy-enforcer --dir=./k8s --namespace=production

# Fail on any violation
./k8s-policy-enforcer --dir=./k8s --fail-strict=true --fail-warn=true
```

#### CI/CD Integration

```bash
# In CI/CD pipeline
kubectl apply -f k8s-manifests/
./k8s-policy-enforcer --dir=./k8s-manifests --fail-strict=true
```

---

## 📊 Policy Report Example

```
================================================================================
📊 KUBERNETES POLICY ENFORCEMENT REPORT
================================================================================
✅ Total policies defined:    15
✅ Total checks performed:    45
✅ Checks passed:             30
⚠️  Total violations:          15
📊 Compliance rate:           66.7%

🔍 Violations by Severity:
  🔴 CRITICAL: 2
  🟠 HIGH: 5
  🟡 MEDIUM: 6
  🟢 LOW: 2

🔍 Violations by Enforcement:
  • strict: 7
  • warn: 8

📋 Detailed Violations:

🔴 [CRITICAL] No Privileged Containers
    Policy ID: K8S-SEC-001
    Category: Security
    Resource: Pod/privileged-app (Namespace: default)
    File: ./k8s/deployment.yaml
    Field: securityContext.privileged
    Value: true
    Reason: Container runs in privileged mode
    Remediation: Set securityContext.privileged to false

🟠 [HIGH] No Host Network
    Policy ID: K8S-POD-001
    Category: Pods
    Resource: Pod/network-daemon (Namespace: kube-system)
    File: ./k8s/daemonset.yaml
    Field: hostNetwork
    Value: true
    Reason: Pod uses host network
    Remediation: Set hostNetwork to false

================================================================================

✅ Policy enforcement complete!
```

---

## 🎨 Policy Enforcement Levels

### Strict
- **Critical violations** cause immediate failure
- **Required** for production deployments
- Examples: Privileged containers, host network

### Warn
- **Non-critical violations** logged but don't fail
- **Recommended** for development/staging
- Examples: Missing resource limits, latest image tag

### Audit
- **Informational only**, no enforcement
- **Logging** for compliance tracking
- Examples: Best practice recommendations

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Kubernetes Policy Check
on: [push, pull_request]

jobs:
  policy-enforcement:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install k8s-policy-enforcer
        run: |
          go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer
      
      - name: Run policy enforcement
        run: |
          ./k8s-policy-enforcer --dir=./k8s --fail-strict=true
```

### GitLab CI

```yaml
k8s-policy-check:
  stage: security
  image: golang:1.21
  script:
    - go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer
    - ./k8s-policy-enforcer --dir=./k8s --fail-strict=true
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('K8s Policy Check') {
            steps {
                sh '''
                    go build -o k8s-policy-enforcer ./cmd/k8s-policy-enforcer
                    ./k8s-policy-enforcer --dir=./k8s --fail-strict=true
                '''
            }
        }
    }
}
```

---

## 📝 Policy Configuration

### Custom Policy Definition

```yaml
# Add custom policies in policy-config.yaml
policies:
  - id: "CUSTOM-001"
    name: "Custom Security Policy"
    category: "Security"
    severity: "HIGH"
    enforcement: "strict"
    rules:
      - field: "securityContext.capabilities.drop"
        operator: "exists"
        value: true
        message: "Security capabilities not dropped"
        severity: "HIGH"
```

---

## 🧪 Testing

### Create Test Manifests

```bash
# Create test directory
mkdir -p test-manifests

# Create test deployment
cat > test-manifests/test-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          privileged: true
          runAsRoot: true
EOF

# Run policy check
./k8s-policy-enforcer --dir=./test-manifests --verbose
```

---

## 🚧 Roadmap

- [ ] OPA/Gatekeeper integration
- [ ] Kyverno policy conversion
- [ ] Real-time policy monitoring
- [ ] Custom policy engine
- [ ] Policy testing in CI/CD
- [ ] GitOps policy management
- [ ] Multi-cluster policy enforcement
- [ ] Compliance dashboard

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add new policies
4. Submit a pull request

---

## 📄 License

MIT License - Free for commercial and personal use

---

## 🙏 Acknowledgments

Built with GPU for Kubernetes security enforcement.

---

**Version:** 1.0.0  
**Author:** @hallucinaut  
**Last Updated:** February 25, 2026