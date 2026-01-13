package parser

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// K8sResource represents a parsed Kubernetes resource
type K8sResource struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   Metadata               `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
	Rules      []Rule                 `yaml:"rules,omitempty"`      // For Role/ClusterRole
	RoleRef    *RoleRef               `yaml:"roleRef,omitempty"`    // For RoleBinding/ClusterRoleBinding
	Subjects   []Subject              `yaml:"subjects,omitempty"`   // For RoleBinding/ClusterRoleBinding
	Raw        map[string]interface{} // Full raw resource
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type Rule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

type RoleRef struct {
	APIGroup string `yaml:"apiGroup"`
	Kind     string `yaml:"kind"`
	Name     string `yaml:"name"`
}

type Subject struct {
	Kind      string `yaml:"kind"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

// ParseFiles parses one or more YAML files
func ParseFiles(paths ...string) ([]K8sResource, error) {
	var resources []K8sResource

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s: %w", path, err)
		}

		if info.IsDir() {
			// Recursively parse directory
			err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
					res, err := parseFile(p)
					if err != nil {
						// Log warning but continue
						fmt.Fprintf(os.Stderr, "Warning: failed to parse %s: %v\n", p, err)
						return nil
					}
					resources = append(resources, res...)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			// Parse single file
			res, err := parseFile(path)
			if err != nil {
				return nil, err
			}
			resources = append(resources, res...)
		}
	}

	return resources, nil
}

// parseFile parses a single YAML file (may contain multiple documents)
func parseFile(path string) ([]K8sResource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParseYAML(data)
}

// ParseYAML parses YAML data containing one or more Kubernetes resources
func ParseYAML(data []byte) ([]K8sResource, error) {
	var resources []K8sResource

	// Split by YAML document separator
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	for {
		var raw map[string]interface{}
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAML: %w", err)
		}

		// Skip empty documents
		if len(raw) == 0 {
			continue
		}

		// Parse into K8sResource
		resource, err := parseResource(raw)
		if err != nil {
			return nil, err
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// parseResource converts raw YAML to K8sResource
func parseResource(raw map[string]interface{}) (K8sResource, error) {
	// Re-marshal and unmarshal for clean parsing
	data, err := yaml.Marshal(raw)
	if err != nil {
		return K8sResource{}, fmt.Errorf("failed to marshal resource: %w", err)
	}

	var resource K8sResource
	if err := yaml.Unmarshal(data, &resource); err != nil {
		return K8sResource{}, fmt.Errorf("failed to unmarshal resource: %w", err)
	}

	resource.Raw = raw
	return resource, nil
}

// IsSupportedKind checks if the resource kind is supported
func IsSupportedKind(kind string) bool {
	supported := map[string]bool{
		"Pod":                true,
		"Deployment":         true,
		"StatefulSet":        true,
		"DaemonSet":          true,
		"Job":                true,
		"CronJob":            true,
		"Service":            true,
		"Role":               true,
		"ClusterRole":        true,
		"RoleBinding":        true,
		"ClusterRoleBinding": true,
	}
	return supported[kind]
}

// GetPodSpec extracts the pod spec from various resource types
func GetPodSpec(resource K8sResource) (map[string]interface{}, bool) {
	if resource.Kind == "Pod" {
		return resource.Spec, true
	}

	// For Deployment, StatefulSet, DaemonSet, Job
	if template, ok := resource.Spec["template"].(map[string]interface{}); ok {
		if spec, ok := template["spec"].(map[string]interface{}); ok {
			return spec, true
		}
	}

	// For CronJob
	if jobTemplate, ok := resource.Spec["jobTemplate"].(map[string]interface{}); ok {
		if spec, ok := jobTemplate["spec"].(map[string]interface{}); ok {
			if template, ok := spec["template"].(map[string]interface{}); ok {
				if podSpec, ok := template["spec"].(map[string]interface{}); ok {
					return podSpec, true
				}
			}
		}
	}

	return nil, false
}
