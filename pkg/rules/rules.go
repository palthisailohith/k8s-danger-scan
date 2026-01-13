package rules

import (
	"fmt"
	"strings"

	"github.com/palthisailohith/k8s-danger-scan/pkg/parser"
	"github.com/palthisailohith/k8s-danger-scan/pkg/types"
)

// Rule is a function that checks a resource and returns findings
type Rule func(resource parser.K8sResource) []types.Finding

// AllRules returns all implemented rules
func AllRules() []Rule {
	return []Rule{
		CheckPrivilegedContainer,
		CheckHostPath,
		CheckDockerSocket,
		CheckRunsAsRoot,
		CheckPrivilegeEscalation,
		CheckWildcardRBAC,
		CheckClusterRoleBindingDefaultSA,
		CheckPublicLoadBalancer,
		CheckNodePort,
		CheckLatestTag,
		CheckHostNetwork,
		CheckHostPIDIPC,
	}
}

// CheckPrivilegedContainer checks for privileged containers
func CheckPrivilegedContainer(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		securityContext, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			continue
		}

		if privileged, ok := securityContext["privileged"].(bool); ok && privileged {
			return []types.Finding{{
				RuleID:    "privileged-container",
				Severity:  types.High,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Container runs in privileged mode",
				Impact:    "Full host access if container is compromised",
				Fix:       "Remove privileged flag or set to false",
			}}
		}
	}

	return nil
}

// CheckHostPath checks for hostPath volumes
func CheckHostPath(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return nil
	}

	for _, v := range volumes {
		volume, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		if _, hasHostPath := volume["hostPath"]; hasHostPath {
			return []types.Finding{{
				RuleID:    "hostpath-volume",
				Severity:  types.High,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Uses hostPath volume mount",
				Impact:    "Direct filesystem access enables container escape",
				Fix:       "Use PersistentVolumes or emptyDir instead",
			}}
		}
	}

	return nil
}

// CheckDockerSocket checks for Docker socket mounts
func CheckDockerSocket(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return nil
	}

	for _, v := range volumes {
		volume, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		if hostPath, ok := volume["hostPath"].(map[string]interface{}); ok {
			if path, ok := hostPath["path"].(string); ok {
				if strings.Contains(path, "/var/run/docker.sock") {
					return []types.Finding{{
						RuleID:    "docker-socket-mount",
						Severity:  types.High,
						Kind:      resource.Kind,
						Name:      resource.Metadata.Name,
						Namespace: resource.Metadata.Namespace,
						Reason:    "Mounts Docker socket from host",
						Impact:    "Grants root-equivalent access to the node",
						Fix:       "Remove Docker socket mount",
					}}
				}
			}
		}
	}

	return nil
}

// CheckRunsAsRoot checks if containers run as root
func CheckRunsAsRoot(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	// Check pod-level security context
	podSecurityContext, hasPodSC := podSpec["securityContext"].(map[string]interface{})
	podRunAsNonRoot := false
	podRunAsUser := -1

	if hasPodSC {
		if runAsNonRoot, ok := podSecurityContext["runAsNonRoot"].(bool); ok && runAsNonRoot {
			podRunAsNonRoot = true
		}
		if runAsUser, ok := podSecurityContext["runAsUser"].(int); ok {
			podRunAsUser = runAsUser
		}
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		securityContext, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			// No container-level securityContext, check pod-level
			if !podRunAsNonRoot && podRunAsUser != 0 {
				return []types.Finding{{
					RuleID:    "runs-as-root",
					Severity:  types.Medium,
					Kind:      resource.Kind,
					Name:      resource.Metadata.Name,
					Namespace: resource.Metadata.Namespace,
					Reason:    "Container runs as root user (UID 0)",
					Impact:    "Increases blast radius of container compromise",
					Fix:       "Set runAsNonRoot: true or runAsUser to non-zero UID",
				}}
			}
			continue
		}

		// Check container-level securityContext
		runAsNonRoot := podRunAsNonRoot
		if val, ok := securityContext["runAsNonRoot"].(bool); ok {
			runAsNonRoot = val
		}

		runAsUser := podRunAsUser
		if val, ok := securityContext["runAsUser"].(int); ok {
			runAsUser = val
		}

		if !runAsNonRoot && (runAsUser == 0 || runAsUser == -1) {
			return []types.Finding{{
				RuleID:    "runs-as-root",
				Severity:  types.Medium,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Container runs as root user (UID 0)",
				Impact:    "Increases blast radius of container compromise",
				Fix:       "Set runAsNonRoot: true or runAsUser to non-zero UID",
			}}
		}
	}

	return nil
}

// CheckPrivilegeEscalation checks for privilege escalation allowance
func CheckPrivilegeEscalation(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		securityContext, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			continue
		}

		if allowPE, ok := securityContext["allowPrivilegeEscalation"].(bool); ok && allowPE {
			return []types.Finding{{
				RuleID:    "privilege-escalation-allowed",
				Severity:  types.High,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Allows privilege escalation within container",
				Impact:    "Enables container escape via kernel exploits",
				Fix:       "Set allowPrivilegeEscalation: false",
			}}
		}
	}

	return nil
}

// CheckWildcardRBAC checks for wildcard RBAC permissions
func CheckWildcardRBAC(resource parser.K8sResource) []types.Finding {
	if resource.Kind != "Role" && resource.Kind != "ClusterRole" {
		return nil
	}

	for _, rule := range resource.Rules {
		hasWildcardVerbs := false
		hasWildcardResources := false

		for _, verb := range rule.Verbs {
			if verb == "*" {
				hasWildcardVerbs = true
				break
			}
		}

		for _, res := range rule.Resources {
			if res == "*" {
				hasWildcardResources = true
				break
			}
		}

		if hasWildcardVerbs && hasWildcardResources {
			return []types.Finding{{
				RuleID:    "wildcard-rbac",
				Severity:  types.High,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Grants wildcard permissions (verbs: *, resources: *)",
				Impact:    "Complete cluster control for any principal with this role",
				Fix:       "Specify explicit verbs and resources",
			}}
		}
	}

	return nil
}

// CheckClusterRoleBindingDefaultSA checks for ClusterRoleBinding to default service accounts
func CheckClusterRoleBindingDefaultSA(resource parser.K8sResource) []types.Finding {
	if resource.Kind != "ClusterRoleBinding" && resource.Kind != "RoleBinding" {
		return nil
	}

	for _, subject := range resource.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == "default" {
			return []types.Finding{{
				RuleID:    "clusterrolebinding-default-sa",
				Severity:  types.High,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "Binds permissions to default service account",
				Impact:    "All pods without explicit SA inherit these permissions",
				Fix:       "Create and use a dedicated ServiceAccount",
			}}
		}
	}

	return nil
}

// CheckPublicLoadBalancer checks for LoadBalancer services in sensitive namespaces
func CheckPublicLoadBalancer(resource parser.K8sResource) []types.Finding {
	if resource.Kind != "Service" {
		return nil
	}

	sensitiveNamespaces := map[string]bool{
		"kube-system": true,
		"prod":        true,
		"production":  true,
	}

	if !sensitiveNamespaces[resource.Metadata.Namespace] {
		return nil
	}

	if svcType, ok := resource.Spec["type"].(string); ok && svcType == "LoadBalancer" {
		return []types.Finding{{
			RuleID:    "public-loadbalancer",
			Severity:  types.High,
			Kind:      resource.Kind,
			Name:      resource.Metadata.Name,
			Namespace: resource.Metadata.Namespace,
			Reason:    fmt.Sprintf("LoadBalancer service in %s namespace", resource.Metadata.Namespace),
			Impact:    "Exposes internal services directly to the internet",
			Fix:       "Use ClusterIP with Ingress, or add explicit justification",
		}}
	}

	return nil
}

// CheckNodePort checks for NodePort services without justification
func CheckNodePort(resource parser.K8sResource) []types.Finding {
	if resource.Kind != "Service" {
		return nil
	}

	if svcType, ok := resource.Spec["type"].(string); ok && svcType == "NodePort" {
		// Check for justification annotation
		if _, hasAnnotation := resource.Metadata.Annotations["danger-scan/nodeport-justified"]; !hasAnnotation {
			return []types.Finding{{
				RuleID:    "nodeport-service",
				Severity:  types.Medium,
				Kind:      resource.Kind,
				Name:      resource.Metadata.Name,
				Namespace: resource.Metadata.Namespace,
				Reason:    "NodePort service without justification annotation",
				Impact:    "Bypasses ingress controls and exposes port on all nodes",
				Fix:       "Use ClusterIP/LoadBalancer or add annotation: danger-scan/nodeport-justified",
			}}
		}
	}

	return nil
}

// CheckLatestTag checks for :latest image tags
func CheckLatestTag(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}

	for _, c := range containers {
		container, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		if image, ok := container["image"].(string); ok {
			if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
				return []types.Finding{{
					RuleID:    "latest-image-tag",
					Severity:  types.Medium,
					Kind:      resource.Kind,
					Name:      resource.Metadata.Name,
					Namespace: resource.Metadata.Namespace,
					Reason:    "Uses :latest or untagged image",
					Impact:    "Non-reproducible deployments and potential supply chain risk",
					Fix:       "Pin to specific image digest or semantic version",
				}}
			}
		}
	}

	return nil
}

// CheckHostNetwork checks for hostNetwork usage
func CheckHostNetwork(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	if hostNetwork, ok := podSpec["hostNetwork"].(bool); ok && hostNetwork {
		return []types.Finding{{
			RuleID:    "host-network",
			Severity:  types.High,
			Kind:      resource.Kind,
			Name:      resource.Metadata.Name,
			Namespace: resource.Metadata.Namespace,
			Reason:    "Uses host network namespace",
			Impact:    "Bypasses network policies and accesses host network",
			Fix:       "Remove hostNetwork or set to false",
		}}
	}

	return nil
}

// CheckHostPIDIPC checks for hostPID or hostIPC usage
func CheckHostPIDIPC(resource parser.K8sResource) []types.Finding {
	podSpec, ok := parser.GetPodSpec(resource)
	if !ok {
		return nil
	}

	if hostPID, ok := podSpec["hostPID"].(bool); ok && hostPID {
		return []types.Finding{{
			RuleID:    "host-pid-ipc",
			Severity:  types.High,
			Kind:      resource.Kind,
			Name:      resource.Metadata.Name,
			Namespace: resource.Metadata.Namespace,
			Reason:    "Uses host PID namespace",
			Impact:    "Can inspect and kill processes on the host",
			Fix:       "Remove hostPID or set to false",
		}}
	}

	if hostIPC, ok := podSpec["hostIPC"].(bool); ok && hostIPC {
		return []types.Finding{{
			RuleID:    "host-pid-ipc",
			Severity:  types.High,
			Kind:      resource.Kind,
			Name:      resource.Metadata.Name,
			Namespace: resource.Metadata.Namespace,
			Reason:    "Uses host IPC namespace",
			Impact:    "Can access shared memory and semaphores on host",
			Fix:       "Remove hostIPC or set to false",
		}}
	}

	return nil
}
