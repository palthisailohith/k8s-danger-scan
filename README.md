# k8s-danger-scan

**Detect catastrophic Kubernetes misconfigurations before they reach production.**

k8s-danger-scan is a CLI-only, open-source tool that answers one question:

**"Is this Kubernetes config obviously dangerous?"**

## What This Is

A focused, opinionated scanner that detects **high-confidence, exploitable misconfigurations** in Kubernetes manifests:

- Node escape vectors
- Cluster takeover paths
- Credential exfiltration risks
- Unintended public exposure

Every finding is:
- **Explainable** in 3-4 lines
- **Hard to argue with** (high confidence)
- **Directly exploitable** (not theoretical)
- **Actionable** (clear fix provided)

## What This Is NOT

k8s-danger-scan is explicitly **NOT**:

-  A vulnerability scanner
-  A CVE database
-  A compliance tool
-  A policy engine
-  An SBOM generator
-  A runtime security tool
-  An admission controller

**No agents. No webhooks. No dashboards. No SaaS.**

Just a fast, deterministic CLI that scans YAML and exits with a clear signal.

## Installation

### Download Binary

Download the latest release from [GitHub Releases](https://github.com/palthisailohith/k8s-danger-scan/releases) (coming soon).

### Build From Source

```bash
git clone https://github.com/palthisailohith/k8s-danger-scan.git
cd k8s-danger-scan
go build -o k8s-danger-scan ./cmd/k8s-danger-scan
```

## Quick Start

### Scan a manifest file

```bash
k8s-danger-scan scan deployment.yaml
```

### Scan a directory

```bash
k8s-danger-scan scan ./manifests
```

### Compare old and new (recommended for CI)

```bash
k8s-danger-scan diff main-manifests/ feature-branch-manifests/
```

**Diff mode only reports newly introduced dangers**, ignoring existing technical debt.

### Include medium-severity findings

```bash
k8s-danger-scan scan --include-medium ./manifests
```

By default, only HIGH severity findings are shown.

### JSON output for automation

```bash
k8s-danger-scan scan --json ./manifests
```

## Example Output

### Human-readable (default)

```
HIGH RISK
Resource: Deployment/api-server
Namespace: prod
Rule: privileged-container
Reason: Container runs in privileged mode
Impact: Full host access if container is compromised
Fix: Remove privileged flag or set to false

HIGH RISK
Resource: ClusterRoleBinding/default-admin
Rule: clusterrolebinding-default-sa
Reason: Binds permissions to default service account
Impact: All pods without explicit SA inherit these permissions
Fix: Create and use a dedicated ServiceAccount

SUMMARY
High risk: 2
Medium risk: 0
Resources affected: 2
Namespaces affected: 1
```

### Diff mode example

```bash
$ k8s-danger-scan diff old.yaml new.yaml
```

```
HIGH RISK
Resource: Deployment/worker
Namespace: prod
Rule: hostpath-volume
Reason: Uses hostPath volume mount
Impact: Direct filesystem access enables container escape
Fix: Use PersistentVolumes or emptyDir instead

SUMMARY
High risk: 1
Medium risk: 0
Resources affected: 1
Namespaces affected: 1
```

**Key insight**: This deployment was changed to add a hostPath mount. Everything else in the environment is ignored.

## Exit Codes

k8s-danger-scan uses exit codes to signal findings:

- **0**: No issues found
- **1**: Medium-risk issues only
- **2**: At least one high-risk issue
- **3**: Error occurred (malformed YAML, file not found, etc.)

This makes CI integration trivial:

```bash
k8s-danger-scan diff main.yaml feature.yaml || exit 1
```

## Rules (v1)

k8s-danger-scan implements exactly **12 rules** across 4 categories.

### Container & Pod Security

| Rule ID | Severity | Description | Rationale |
|---------|----------|-------------|-----------|
| `privileged-container` | HIGH | Container has `privileged: true` | Grants unrestricted host access, trivial escape |
| `hostpath-volume` | HIGH | Uses `hostPath` volume mount | Direct filesystem access enables node takeover |
| `docker-socket-mount` | HIGH | Mounts `/var/run/docker.sock` | Root-equivalent access to node |
| `runs-as-root` | MEDIUM | Runs as UID 0 or missing `runAsNonRoot` | Increases blast radius of container compromise |
| `privilege-escalation-allowed` | HIGH | `allowPrivilegeEscalation: true` | Enables container escape via kernel exploits |

### RBAC

| Rule ID | Severity | Description | Rationale |
|---------|----------|-------------|-----------|
| `wildcard-rbac` | HIGH | Grants `verbs: ["*"]` and `resources: ["*"]` | Complete cluster control |
| `clusterrolebinding-default-sa` | HIGH | Binds ClusterRole to `default` ServiceAccount | All pods inherit elevated permissions |

### Networking & Exposure

| Rule ID | Severity | Description | Rationale |
|---------|----------|-------------|-----------|
| `public-loadbalancer` | HIGH | LoadBalancer in `kube-system`, `prod`, or `production` | Exposes sensitive services to internet |
| `nodeport-service` | MEDIUM | NodePort without justification annotation | Bypasses ingress controls |

### Image Hygiene

| Rule ID | Severity | Description | Rationale |
|---------|----------|-------------|-----------|
| `latest-image-tag` | MEDIUM | Uses `:latest` tag or no tag | Non-reproducible deployments, supply chain risk |

### Host Access

| Rule ID | Severity | Description | Rationale |
|---------|----------|-------------|-----------|
| `host-network` | HIGH | `hostNetwork: true` | Bypasses network policies, accesses host network |
| `host-pid-ipc` | HIGH | `hostPID: true` or `hostIPC: true` | Can inspect/kill host processes or access shared memory |

### Why these 12?

Each rule is:
1. **Catastrophic if exploited** (not a minor misconfiguration)
2. **Universally dangerous** (not context-dependent)
3. **Immediately understandable** (no security expertise required)

## CI/CD Integration

### GitHub Actions

```yaml
name: k8s-danger-scan

on:
  pull_request:
    paths:
      - 'k8s/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Download k8s-danger-scan
        run: |
          curl -LO https://github.com/palthisailohith/k8s-danger-scan/releases/latest/download/k8s-danger-scan
          chmod +x k8s-danger-scan

      - name: Scan PR changes
        run: |
          git show main:k8s > /tmp/main-manifests.yaml
          ./k8s-danger-scan diff /tmp/main-manifests.yaml k8s/
```

### GitLab CI

```yaml
k8s-danger-scan:
  stage: security
  image: golang:1.21
  script:
    - go install github.com/palthisailohith/k8s-danger-scan/cmd/k8s-danger-scan@latest
    - k8s-danger-scan scan ./k8s --json > report.json
  artifacts:
    reports:
      junit: report.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if git diff --cached --name-only | grep -q '\.yaml$'; then
  k8s-danger-scan scan $(git diff --cached --name-only --diff-filter=ACM | grep '\.yaml$')
  exit $?
fi
```

## How Is This Different From Trivy?

| Feature | k8s-danger-scan | Trivy |
|---------|-----------------|-------|
| **Purpose** | Detect catastrophic K8s misconfigs | Comprehensive vulnerability scanner |
| **Scope** | 12 high-signal rules | CVEs, secrets, misconfigs, SBOM, compliance |
| **Noise level** | Extremely low (opinionated) | Can be high (configurable) |
| **Diff mode** | First-class feature | Not available |
| **CVE scanning** | No | Yes |
| **SBOM generation** | No | Yes |
| **Compliance frameworks** | No | Yes (CIS, NSA, etc.) |
| **Best for** | PR review, change-based scanning | Comprehensive security audits |

**Use Trivy for**: Full security posture, compliance audits, container image scanning.

**Use k8s-danger-scan for**: Fast PR feedback, change-based validation, CI gates.

### Can I use both?

Yes! They complement each other:

```bash
# Gate on catastrophic misconfigs (fast, low noise)
k8s-danger-scan diff main.yaml pr.yaml || exit 1

# Full audit in nightly job (comprehensive)
trivy config --severity HIGH,CRITICAL ./k8s
```

## Design Principles

### 1. Opinionated
No configuration files. No policy DSLs. No tuning knobs (except `--include-medium`).

### 2. Low Noise
If a finding appears, it's **obviously dangerous**. No "maybes" or "consider this."

### 3. Explainable
Every finding includes:
- What's wrong (Reason)
- Why it matters (Impact)
- How to fix it (Fix)

No security expertise required to understand the output.

### 4. Deterministic
Same input = same output. No ML. No heuristics. No surprises.

### 5. Safe by Default
Shows only HIGH severity by default. Medium requires `--include-medium`.

## Supported Resource Types

- Pod
- Deployment
- StatefulSet
- DaemonSet
- Job
- CronJob
- Service
- Role
- ClusterRole
- RoleBinding
- ClusterRoleBinding

All other resource types are silently ignored.

## Development

### Project Structure

```
k8s-danger-scan/
├── cmd/
│   └── k8s-danger-scan/    # CLI entry point
├── pkg/
│   ├── parser/             # YAML parsing
│   ├── rules/              # Rule implementations
│   ├── scanner/            # Core scanning logic
│   ├── types/              # Shared types
│   └── output/             # Output formatting
├── examples/               # Test manifests
└── README.md
```

### Running Tests

```bash
go test ./...
```

### Building

```bash
go build -o k8s-danger-scan ./cmd/k8s-danger-scan
```

## FAQ

### Why not use OPA/Gatekeeper?

OPA is a policy engine. k8s-danger-scan is a scanner.

- **OPA**: Requires writing Rego policies, enforces at admission time
- **k8s-danger-scan**: Zero config, scans YAML files, designed for CI

Use OPA for runtime enforcement. Use k8s-danger-scan for pre-merge validation.

### Can this replace my policy engine?

No. k8s-danger-scan detects catastrophic misconfigurations. It doesn't enforce organizational policies.

### Why no auto-fix?

Auto-fixing security issues is dangerous. You need to understand the finding and decide the appropriate fix for your context.

### Can I add custom rules?

Not in v1. The 12 rules are intentionally locked to maintain low noise and high signal.

If you need custom rules, consider OPA, Kyverno, or Datree.

### Will you add compliance frameworks (CIS, PCI-DSS, etc.)?

No. Compliance mapping adds noise and complexity. Use Trivy, Checkov, or Prisma Cloud for compliance.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Note**: The 12 rules are locked for v1. PRs that add new rules will not be accepted until v2 planning begins.

## Roadmap

### v1.0 (Current)
- ✅ 12 core rules
- ✅ Scan and diff modes
- ✅ Human and JSON output
- ✅ Proper exit codes

### v2.0 (Future)
- Consideration of additional high-signal rules
- Performance optimizations for large manifests
- Integration with popular CI/CD platforms

## Support

- GitHub Issues: [https://github.com/palthisailohith/k8s-danger-scan/issues](https://github.com/palthisailohith/k8s-danger-scan/issues)
- Discussions: [https://github.com/palthisailohith/k8s-danger-scan/discussions](https://github.com/palthisailohith/k8s-danger-scan/discussions)

---

**Built with the principle that security tools should be explainable, deterministic, and low-noise.**
