# k8s-danger-scan (sounds a little odd, but dramatic, eh.)

Catastrophic Kubernetes misconfigs? Yeah, this CLI catches them **before** your cluster becomes tomorrow's headline.

One brutal question it asks:  
**"Did this change just make everything way worse?"**

Only screams about the truly stupid stuff: privileged pods, wildcard RBAC giving god-mode, hostPath to /etc, docker.sock mounts, accidental public LoadBalancers in prod.  
No CVEs, no 400 "medium" alerts from ancient debt, no agents, no SaaS upsell. Just danger, explained like you're five (but you're not).

## Why this exists (short version)
Other scanners bury you in noise so deep you disable them.  
This one ignores your 2019 sins and **only flags new landmines** from diffs.  
Great for PR reviews, "is this safe to apply?" moments, or finally auditing that stagnant cluster nobody touches.

## Install – binaries so you don't need Go installed
Pick your architecture :

# Linux amd64 (most servers)
curl -LO https://github.com/palthisailohith/k8s-danger-scan/releases/latest/download/k8s-danger-scan_linux_amd64
chmod +x k8s-danger-scan_linux_amd64
sudo mv k8s-danger-scan_linux_amd64 /usr/local/bin/k8s-danger-scan

# macOS Apple Silicon
curl -LO https://github.com/palthisailohith/k8s-danger-scan/releases/latest/download/k8s-danger-scan_darwin_arm64
chmod +x k8s-danger-scan_darwin_arm64
sudo mv k8s-danger-scan_darwin_arm64 /usr/local/bin/k8s-danger-scan

# Feeling old-school? Build it
git clone https://github.com/palthisailohith/k8s-danger-scan.git && cd k8s-danger-scan && go build -o k8s-danger-scan ./cmd/k8s-danger-scan


Try it in 10 seconds:

Scan stuff (only HIGH by default – because who has time?)
1. This command used to scan for any misconfigs in yaml's.
k8s-danger-scan scan deployment.yaml
k8s-danger-scan scan ./k8s-manifests/

2. Diff is used to compare your PR and the main branch.
k8s-danger-scan diff main-branch.yaml my-pr.yaml

3.Brave? See the mediums too
k8s-danger-scan scan --include-medium ./k8s/

4.CI loves JSON
k8s-danger-scan diff main.yaml pr.yaml --json

What it looks like when it saves your a*s:

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


Rules? Exactly 12 mean ones (locked for v1)
Privileged, hostPath, docker.sock, run-as-root (medium), allowPrivilegeEscalation, wildcard verbs/resources, default SA bindings, public LB in prod/kube-system, NodePort (medium), :latest (medium), hostNetwork, hostPID/IPC.
Full list + why-they-suck → docs/rules.md

