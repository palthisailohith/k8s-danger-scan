# k8s-danger-scan

Catastrophic Kubernetes misconfigs? This CLI catches them **before** your cluster becomes tomorrow’s headline.

One mean question it asks:  
**"Did this change just make everything way worse?"**

Only screams about the truly dumb stuff:  
privileged pods, wildcard RBAC, hostPath to /etc, docker.sock mounts, accidental public LoadBalancers in prod, etc.

No CVEs. No agents. No dashboards. No SaaS. No 400 "medium" alerts from 2019 debt.  
Just danger explained like you're five (but you're not).

## Why bother?

Other scanners bury you in noise until you disable them forever.  
This one ignores your ancient sins and **only flags new landmines** from your diff.  
Perfect for PR reviews, "Is this safe to apply?" panic moments, or finally auditing that frozen cluster nobody has touched in years.

## Install – binaries (no Go needed)

Pick your poison:

```bash
# Linux amd64 (most servers)
curl -LO https://github.com/palthisailohith/k8s-danger-scan/releases/latest/download/k8s-danger-scan_linux_amd64
chmod +x k8s-danger-scan_linux_amd64
sudo mv k8s-danger-scan_linux_amd64 /usr/local/bin/k8s-danger-scan

# macOS Apple Silicon
curl -LO https://github.com/palthisailohith/k8s-danger-scan/releases/latest/download/k8s-danger-scan_darwin_arm64
chmod +x k8s-danger-scan_darwin_arm64
sudo mv k8s-danger-scan_darwin_arm64 /usr/local/bin/k8s-danger-scan

# Old-school? Build it:
git clone https://github.com/palthisailohith/k8s-danger-scan.git
cd k8s-danger-scan
go build -o k8s-danger-scan ./cmd/k8s-danger-scan
```

Try it in 10 seconds:
```bash
# Scan file or dir (HIGH risks only – because who has time?)
k8s-danger-scan scan deployment.yaml
k8s-danger-scan scan ./k8s-manifests/

# Diff mode – only NEW stupidity (recommended!)
k8s-danger-scan diff main-branch.yaml my-pr.yaml

# Brave? See mediums too
k8s-danger-scan scan --include-medium ./k8s/

# CI-friendly JSON
k8s-danger-scan diff main.yaml pr.yaml --json
```

When it saves your a*s (example output):
HIGH RISK
Resource: Deployment/api
Namespace: prod
Rule: privileged-container
Reason: Container runs in privileged mode
Impact: If this gets compromised → full host takeover
Fix: Delete that privileged: true line, seriously

SUMMARY
High risk: 1
Medium risk: 0
Resources affected: 1
Namespaces affected: prod

Exit codes:

0 = clean
1 = mediums only (meh)
2 = high risk → break the build here
3 = error (bad YAML?)


Rules: Exactly 12 mean ones (locked for v1)

privileged-container (HIGH)
hostpath-volume (HIGH)
docker-socket-mount (HIGH)
runs-as-root (MEDIUM)
privilege-escalation-allowed (HIGH)
wildcard-rbac (HIGH)
clusterrolebinding-default-sa (HIGH)
public-loadbalancer (HIGH)
nodeport-service (MEDIUM)
latest-image-tag (MEDIUM)
host-network (HIGH)
host-pid-ipc (HIGH)

For more info on the tool, refer docs :))
