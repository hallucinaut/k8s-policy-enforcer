package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"sigs.k8s.io/yaml"
)

var (
	infoColor    = color.New(color.FgBlue)
	warnColor    = color.New(color.FgYellow)
	errorColor   = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor  = color.New(color.FgCyan)
)

// SeverityLevel returns a numeric level for severity comparison.
// Lower values indicate higher severity.
func SeverityLevel(s string) int {
	switch s {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

// Policy represents a Kubernetes policy.
type Policy struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Severity    string       `json:"severity"`
	Enforcement string       `json:"enforcement"` // strict, warn, audit
	Rules       []PolicyRule `json:"rules"`
}

// PolicyRule represents a single rule within a policy.
type PolicyRule struct {
	Field      string        `json:"field"`
	Operator   string        `json:"operator"`
	Value      interface{}   `json:"value"`
	Message    string        `json:"message"`
	Severity   string        `json:"severity"`
	Categories []string      `json:"categories"`
}

// Violation represents a policy violation.
type Violation struct {
	PolicyID    string        `json:"policy_id"`
	PolicyName  string        `json:"policy_name"`
	Description string        `json:"description"`
	Category    string        `json:"category"`
	Severity    string        `json:"severity"`
	Enforcement string        `json:"enforcement"`
	Resource    string        `json:"resource"`
	Kind        string        `json:"kind"`
	Name        string        `json:"name"`
	Namespace   string        `json:"namespace"`
	Field       string        `json:"field"`
	Value       interface{}   `json:"value"`
	Remediation string        `json:"remediation"`
	Reason      string        `json:"reason"`
	Timestamp   time.Time     `json:"timestamp"`
}

// PolicyResult holds the result of policy evaluation.
type PolicyResult struct {
	PolicyID    string      `json:"policy_id"`
	PolicyName  string      `json:"policy_name"`
	Passed      bool        `json:"passed"`
	Violations  []Violation `json:"violations"`
	Resources   int         `json:"resources"`
	Enforcement string      `json:"enforcement"`
}

// PolicyEnforcementResult holds the overall enforcement result.
type PolicyEnforcementResult struct {
	Namespace        string            `json:"namespace"`
	TotalPolicies    int               `json:"total_policies"`
	TotalViolations  int               `json:"total_violations"`
	Results          []PolicyResult    `json:"results"`
	Violations       []Violation       `json:"violations"`
	ComplianceRate   float64           `json:"compliance_rate"`
}

// KubernetesPolicyEnforcer performs policy enforcement for Kubernetes.
type KubernetesPolicyEnforcer struct {
	policies     map[string][]Policy
	violations   []Violation
	results      []PolicyResult
	failOnStrict bool
	failOnWarn   bool
	verbose      bool
	dryRun       bool
	namespace    string
}

// NewKubernetesPolicyEnforcer creates a new KubernetesPolicyEnforcer.
func NewKubernetesPolicyEnforcer(failOnStrict, failOnWarn, verbose, dryRun bool) *KubernetesPolicyEnforcer {
	return &KubernetesPolicyEnforcer{
		policies:     make(map[string][]Policy),
		violations:   make([]Violation, 0),
		results:      make([]PolicyResult, 0),
		failOnStrict: failOnStrict,
		failOnWarn:   failOnWarn,
		verbose:      verbose,
		dryRun:       dryRun,
		namespace:    "*",
	}
}

// getStringValue extracts a string value from a nested map using dot notation.
func getStringValue(resource map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := interface{}(resource)

	for i, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[part]; exists {
				// If this is the last part and it's a string, return it
				if i == len(parts)-1 {
					if str, ok := val.(string); ok {
						return str
					}
					return ""
				}
				// Otherwise continue traversing into nested maps
				current = val
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	if str, ok := current.(string); ok {
		return str
	}
	return ""
}

// InitializePolicies initializes all Kubernetes policies.
func (kpe *KubernetesPolicyEnforcer) InitializePolicies() {
	// Security Context Policies
	kpe.policies["security-context"] = []Policy{
		{
			ID:          "K8S-SEC-001",
			Name:        "No Privileged Containers",
			Description: "Containers should not run in privileged mode",
			Category:    "Security",
			Severity:    "CRITICAL",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "securityContext.privileged",
					Operator:  "equals",
					Value:     true,
					Message:   "Container runs in privileged mode",
					Severity:  "CRITICAL",
					Categories: []string{"security", "container"},
				},
			},
		},
		{
			ID:          "K8S-SEC-002",
			Name:        "Run as Non-Root",
			Description: "Containers should run as non-root user",
			Category:    "Security",
			Severity:    "HIGH",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "securityContext.runAsNonRoot",
					Operator:  "notEquals",
					Value:     true,
					Message:   "Container does not enforce runAsNonRoot",
					Severity:  "HIGH",
					Categories: []string{"security", "container"},
				},
			},
		},
		{
			ID:          "K8S-SEC-003",
			Name:        "Read-Only Root Filesystem",
			Description: "Container root filesystem should be read-only",
			Category:    "Security",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "securityContext.readOnlyRootFilesystem",
					Operator:  "equals",
					Value:     false,
					Message:   "Root filesystem is writable",
					Severity:  "MEDIUM",
					Categories: []string{"security", "container"},
				},
			},
		},
		{
			ID:          "K8S-SEC-004",
			Name:        "No Allow Privilege Escalation",
			Description: "Containers should not allow privilege escalation",
			Category:    "Security",
			Severity:    "HIGH",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "securityContext.allowPrivilegeEscalation",
					Operator:  "equals",
					Value:     true,
					Message:   "Privilege escalation is allowed",
					Severity:  "HIGH",
					Categories: []string{"security", "container"},
				},
			},
		},
	}

	// Network Policies
	kpe.policies["network"] = []Policy{
		{
			ID:          "K8S-NET-001",
			Name:        "Network Policies Required",
			Description: "Network policies should be defined for namespaces",
			Category:    "Network",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "kind",
					Operator:  "equals",
					Value:     "NetworkPolicy",
					Message:   "No NetworkPolicy resource found in manifest",
					Severity:  "MEDIUM",
					Categories: []string{"network", "security"},
				},
			},
		},
	}

	// Resource Policies
	kpe.policies["resources"] = []Policy{
		{
			ID:          "K8S-RES-001",
			Name:        "Resource Limits Required",
			Description: "Containers must have resource limits defined",
			Category:    "Resources",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "resources.limits",
					Operator:  "exists",
					Value:     true,
					Message:   "Resource limits not defined",
					Severity:  "MEDIUM",
					Categories: []string{"resources", "performance"},
				},
			},
		},
		{
			ID:          "K8S-RES-002",
			Name:        "Resource Requests Required",
			Description: "Containers must have resource requests defined",
			Category:    "Resources",
			Severity:    "LOW",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "resources.requests",
					Operator:  "exists",
					Value:     true,
					Message:   "Resource requests not defined",
					Severity:  "LOW",
					Categories: []string{"resources", "performance"},
				},
			},
		},
	}

	// Pod Policies
	kpe.policies["pods"] = []Policy{
		{
			ID:          "K8S-POD-001",
			Name:        "No Host Network",
			Description: "Pods should not use host network",
			Category:    "Pods",
			Severity:    "HIGH",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "hostNetwork",
					Operator:  "equals",
					Value:     true,
					Message:   "Pod uses host network",
					Severity:  "HIGH",
					Categories: []string{"pods", "network"},
				},
			},
		},
		{
			ID:          "K8S-POD-002",
			Name:        "No Host PID",
			Description: "Pods should not use host PID namespace",
			Category:    "Pods",
			Severity:    "HIGH",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "hostPID",
					Operator:  "equals",
					Value:     true,
					Message:   "Pod uses host PID namespace",
					Severity:  "HIGH",
					Categories: []string{"pods", "security"},
				},
			},
		},
		{
			ID:          "K8S-POD-003",
			Name:        "No Host IPC",
			Description: "Pods should not use host IPC namespace",
			Category:    "Pods",
			Severity:    "HIGH",
			Enforcement: "strict",
			Rules: []PolicyRule{
				{
					Field:     "hostIPC",
					Operator:  "equals",
					Value:     true,
					Message:   "Pod uses host IPC namespace",
					Severity:  "HIGH",
					Categories: []string{"pods", "security"},
				},
			},
		},
		{
			ID:          "K8S-POD-004",
			Name:        "Automount Service Account Token",
			Description: "Automount service account token should be disabled",
			Category:    "Pods",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "automountServiceAccountToken",
					Operator:  "equals",
					Value:     true,
					Message:   "Service account token auto-mounted",
					Severity:  "MEDIUM",
					Categories: []string{"pods", "security"},
				},
			},
		},
	}

	// Image Policies
	kpe.policies["images"] = []Policy{
		{
			ID:          "K8S-IMG-001",
			Name:        "No Latest Tag",
			Description: "Container images should not use 'latest' tag",
			Category:    "Images",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "imageTag",
					Operator:  "equals",
					Value:     "latest",
					Message:   "Image uses 'latest' tag",
					Severity:  "MEDIUM",
					Categories: []string{"images", "security"},
				},
			},
		},
		{
			ID:          "K8S-IMG-002",
			Name:        "Image Pull Policy",
			Description: "Image pull policy should be set",
			Category:    "Images",
			Severity:    "LOW",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "imagePullPolicy",
					Operator:  "exists",
					Value:     true,
					Message:   "Image pull policy not specified",
					Severity:  "LOW",
					Categories: []string{"images", "security"},
				},
			},
		},
	}

	// Service Account Policies
	kpe.policies["service-accounts"] = []Policy{
		{
			ID:          "K8S-SA-001",
			Name:        "No Default Service Account",
			Description: "Pods should not use default service account",
			Category:    "Service Accounts",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "serviceAccountName",
					Operator:  "equals",
					Value:     "default",
					Message:   "Pod uses default service account",
					Severity:  "MEDIUM",
					Categories: []string{"service-accounts", "security"},
				},
			},
		},
	}
}

// LoadK8sManifests loads Kubernetes manifests from a directory.
func (kpe *KubernetesPolicyEnforcer) LoadK8sManifests(dirPath string) error {
	infoColor.Printf("Loading Kubernetes manifests from: %s\n", dirPath)

	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		fileExt := strings.ToLower(filepath.Ext(path))
		if fileExt != ".yaml" && fileExt != ".yml" {
			return nil
		}

		if err := kpe.loadManifest(path); err != nil {
			warnColor.Printf("Failed to load %s: %v\n", path, err)
		}

		return nil
	})
}

// loadManifest loads and parses a single Kubernetes manifest file.
func (kpe *KubernetesPolicyEnforcer) loadManifest(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Split by YAML document separator
	rawDocs := strings.Split(string(content), "\n---\n")

	for _, rawDoc := range rawDocs {
		rawDoc = strings.TrimSpace(rawDoc)
		if rawDoc == "" {
			continue
		}

		var resource map[string]interface{}
		if err := yaml.Unmarshal([]byte(rawDoc), &resource); err != nil {
			warnColor.Printf("Skipping invalid YAML in %s: %v\n", filePath, err)
			continue
		}

		kind := getStringValue(resource, "kind")
		name := getStringValue(resource, "metadata.name")
		namespace := getStringValue(resource, "metadata.namespace")
		if namespace == "" {
			namespace = "default"
		}

		// Apply namespace filter
		if kpe.namespace != "*" && namespace != kpe.namespace {
			continue
		}

		kpe.evaluatePolicies(kind, name, namespace, resource, filePath)
	}

	return nil
}

// workloadKinds returns the set of Kubernetes kinds that contain pod specs.
func workloadKinds() map[string]bool {
	return map[string]bool{
		"Deployment":    true,
		"StatefulSet":   true,
		"DaemonSet":     true,
		"ReplicaSet":    true,
		"Job":           true,
		"CronJob":       true,
	}
}

// extractContainers extracts container specs from a workload resource.
func (kpe *KubernetesPolicyEnforcer) extractContainers(resource map[string]interface{}) []map[string]interface{} {
	kind := getStringValue(resource, "kind")

	if workloadKinds()[kind] {
		// For Deployments, StatefulSets, etc., get containers from spec.template.spec.containers
		containers := kpe.getFieldValue(resource, "spec.template.spec.containers")
		var result []map[string]interface{}
		if containerList, ok := containers.([]interface{}); ok {
			for _, c := range containerList {
				if cm, ok := c.(map[string]interface{}); ok {
					result = append(result, cm)
				}
			}
		}

		// Also check init containers
		initContainers := kpe.getFieldValue(resource, "spec.template.spec.initContainers")
		if initList, ok := initContainers.([]interface{}); ok {
			for _, c := range initList {
				if cm, ok := c.(map[string]interface{}); ok {
					result = append(result, cm)
				}
			}
		}

		return result
	}

	// For Pod resources, get containers directly from spec.containers
	if kind == "Pod" {
		containers := kpe.getFieldValue(resource, "spec.containers")
		var result []map[string]interface{}
		if containerList, ok := containers.([]interface{}); ok {
			for _, c := range containerList {
				if cm, ok := c.(map[string]interface{}); ok {
					result = append(result, cm)
				}
			}
		}

		initContainers := kpe.getFieldValue(resource, "spec.initContainers")
		if initList, ok := initContainers.([]interface{}); ok {
			for _, c := range initList {
				if cm, ok := c.(map[string]interface{}); ok {
					result = append(result, cm)
				}
			}
		}

		return result
	}

	// For other resources (Service, ConfigMap, etc.), return nil
	return nil
}

// evaluatePolicies evaluates all policies against a resource.
func (kpe *KubernetesPolicyEnforcer) evaluatePolicies(kind, name, namespace string, resource map[string]interface{}, filePath string) {
	// Extract containers from workload resources for container-level policy checks
	containers := kpe.extractContainers(resource)

	for _, policy := range kpe.policies["security-context"] {
		if len(containers) > 0 {
			for _, container := range containers {
				result := kpe.evaluatePolicy(policy, kind, name, namespace, container, filePath)
				kpe.results = append(kpe.results, result)
			}
		} else {
			// If no containers extracted, evaluate against the resource itself
			result := kpe.evaluatePolicy(policy, kind, name, namespace, resource, filePath)
			kpe.results = append(kpe.results, result)
		}
	}

	for _, policy := range kpe.policies["images"] {
		if len(containers) > 0 {
			for _, container := range containers {
				result := kpe.evaluatePolicy(policy, kind, name, namespace, container, filePath)
				kpe.results = append(kpe.results, result)
			}
		} else {
			result := kpe.evaluatePolicy(policy, kind, name, namespace, resource, filePath)
			kpe.results = append(kpe.results, result)
		}
	}

	for _, policy := range kpe.policies["resources"] {
		if len(containers) > 0 {
			for _, container := range containers {
				result := kpe.evaluatePolicy(policy, kind, name, namespace, container, filePath)
				kpe.results = append(kpe.results, result)
			}
		} else {
			result := kpe.evaluatePolicy(policy, kind, name, namespace, resource, filePath)
			kpe.results = append(kpe.results, result)
		}
	}

	// Pod-level policies are evaluated against the pod spec (not individual containers)
	for _, policy := range kpe.policies["pods"] {
		podSpec := resource
		if len(containers) > 0 {
			// Extract the pod spec for container-level fields
			podSpec = getPodSpec(resource)
		}
		result := kpe.evaluatePolicy(policy, kind, name, namespace, podSpec, filePath)
		kpe.results = append(kpe.results, result)
	}

	// Service account policies are evaluated against the pod spec
	for _, policy := range kpe.policies["service-accounts"] {
		podSpec := resource
		if len(containers) > 0 {
			podSpec = getPodSpec(resource)
		}
		result := kpe.evaluatePolicy(policy, kind, name, namespace, podSpec, filePath)
		kpe.results = append(kpe.results, result)
	}

	// Network policies are evaluated against the resource itself
	for _, policy := range kpe.policies["network"] {
		result := kpe.evaluatePolicy(policy, kind, name, namespace, resource, filePath)
		kpe.results = append(kpe.results, result)
	}
}

// getPodSpec extracts the pod spec from a workload resource.
func getPodSpec(resource map[string]interface{}) map[string]interface{} {
	kind := getStringValue(resource, "kind")

	if kind == "Pod" {
		return resource
	}

	// For workloads, extract the pod template spec
	if _, ok := resource["spec"]; ok {
		spec := resource["spec"].(map[string]interface{})
		if tmpl, ok := spec["template"]; ok {
			tmplMap := tmpl.(map[string]interface{})
			if podSpec, ok := tmplMap["spec"]; ok {
				return podSpec.(map[string]interface{})
			}
		}
	}

	// For CronJob, the spec is nested differently
	if kind == "CronJob" {
		if _, ok := resource["spec"]; ok {
			spec := resource["spec"].(map[string]interface{})
			if jobTemplate, ok := spec["jobTemplate"]; ok {
				jtMap := jobTemplate.(map[string]interface{})
				if jtSpec, ok := jtMap["spec"]; ok {
					jtSpecMap := jtSpec.(map[string]interface{})
					if tmpl, ok := jtSpecMap["template"]; ok {
						tmplMap := tmpl.(map[string]interface{})
						if podSpec, ok := tmplMap["spec"]; ok {
							return podSpec.(map[string]interface{})
						}
					}
				}
			}
		}
	}

	return resource
}

// evaluatePolicy evaluates a single policy against a resource.
func (kpe *KubernetesPolicyEnforcer) evaluatePolicy(policy Policy, kind, name, namespace string, resource map[string]interface{}, filePath string) PolicyResult {
	result := PolicyResult{
		PolicyID:    policy.ID,
		PolicyName:  policy.Name,
		Passed:      true,
		Violations:  make([]Violation, 0),
		Resources:   1,
		Enforcement: policy.Enforcement,
	}

	for _, rule := range policy.Rules {
		value := kpe.getFieldValue(resource, rule.Field)

		violated := kpe.checkCondition(value, rule.Operator, rule.Value)
		if violated {
			result.Passed = false

			violation := Violation{
				PolicyID:    policy.ID,
				PolicyName:  policy.Name,
				Description: policy.Description,
				Category:    policy.Category,
				Severity:    rule.Severity,
				Enforcement: policy.Enforcement,
				Resource:    filePath,
				Kind:        kind,
				Name:        name,
				Namespace:   namespace,
				Field:       rule.Field,
				Value:       value,
				Remediation: kpe.generateRemediation(policy, rule),
				Reason:      rule.Message,
				Timestamp:   time.Now(),
			}

			result.Violations = append(result.Violations, violation)
			kpe.violations = append(kpe.violations, violation)

			if kpe.verbose {
				kpe.printViolation(violation)
			}
		}
	}

	return result
}

// getFieldValue extracts a field value from a nested map using dot notation.
// Supports array indices in the path (e.g., "containers.0.securityContext.privileged").
func (kpe *KubernetesPolicyEnforcer) getFieldValue(resource map[string]interface{}, field string) interface{} {
	parts := strings.Split(field, ".")
	current := interface{}(resource)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			if val, exists := v[part]; exists {
				current = val
			} else {
				return nil
			}
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil
			}
			current = v[idx]
		default:
			return nil
		}
	}

	return current
}

// checkCondition checks if a condition is met.
func (kpe *KubernetesPolicyEnforcer) checkCondition(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "equals":
		if actual == nil {
			return false
		}
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)

	case "notEquals":
		if actual == nil {
			return true
		}
		return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected)

	case "exists":
		// Violation when field does NOT exist
		return actual == nil

	case "count":
		if arr, ok := actual.([]interface{}); ok {
			count := len(arr)
			if countVal, ok := expected.(float64); ok {
				return count == int(countVal)
			}
		}
		return false
	}

	return false
}

// generateRemediation generates remediation instructions.
func (kpe *KubernetesPolicyEnforcer) generateRemediation(policy Policy, rule PolicyRule) string {
	remediations := map[string]string{
		"securityContext.privileged":                    "Set securityContext.privileged to false",
		"securityContext.runAsNonRoot":                  "Set securityContext.runAsNonRoot to true",
		"securityContext.readOnlyRootFilesystem":        "Set securityContext.readOnlyRootFilesystem to true",
		"securityContext.allowPrivilegeEscalation":      "Set securityContext.allowPrivilegeEscalation to false",
		"hostNetwork":                                   "Set hostNetwork to false",
		"hostPID":                                       "Set hostPID to false",
		"hostIPC":                                       "Set hostIPC to false",
		"automountServiceAccountToken":                  "Set automountServiceAccountToken to false",
		"imageTag":                                      "Specify a specific image tag instead of 'latest'",
		"resources.limits":                              "Add resource limits (cpu, memory)",
		"resources.requests":                            "Add resource requests (cpu, memory)",
	}

	if remediation, ok := remediations[rule.Field]; ok {
		return remediation
	}

	return fmt.Sprintf("Review and fix: %s", rule.Message)
}

// printViolation prints a single violation.
func (kpe *KubernetesPolicyEnforcer) printViolation(violation Violation) {
	switch violation.Severity {
	case "CRITICAL", "HIGH":
		errorColor.Printf("[%s] %s - %s/%s\n", violation.Severity, violation.PolicyName, violation.Kind, violation.Name)
	default:
		warnColor.Printf("[%s] %s - %s/%s\n", violation.Severity, violation.PolicyName, violation.Kind, violation.Name)
	}
}

// PrintReport prints the policy enforcement report.
func (kpe *KubernetesPolicyEnforcer) PrintReport() {
	infoColor.Println(strings.Repeat("=", 80))
	infoColor.Println("KUBERNETES POLICY ENFORCEMENT REPORT")
	infoColor.Println(strings.Repeat("=", 80))

	// Count violations by severity
	severityCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	enforcementCounts := map[string]int{"strict": 0, "warn": 0, "audit": 0}

	for _, violation := range kpe.violations {
		severityCounts[violation.Severity]++
		enforcementCounts[violation.Enforcement]++
	}

	totalPolicies := len(kpe.policies)
	totalChecks := 0
	passedChecks := 0

	for _, result := range kpe.results {
		totalChecks++
		if result.Passed {
			passedChecks++
		}
	}

	var complianceRate float64
	if totalChecks > 0 {
		complianceRate = float64(passedChecks) / float64(totalChecks) * 100
	} else {
		complianceRate = 100
	}

	successColor.Printf("Total policies defined:    %d\n", totalPolicies)
	successColor.Printf("Total checks performed:    %d\n", totalChecks)
	successColor.Printf("Checks passed:             %d\n", passedChecks)
	warnColor.Printf("Total violations:          %d\n", len(kpe.violations))
	successColor.Printf("Compliance rate:           %.1f%%\n", complianceRate)

	infoColor.Println("Violations by Severity:")
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, severity := range severityOrder {
		count := severityCounts[severity]
		if count > 0 {
			infoColor.Printf("  %s: %d\n", severity, count)
		}
	}

	infoColor.Println("Violations by Enforcement:")
	for _, enforcement := range []string{"strict", "warn", "audit"} {
		count := enforcementCounts[enforcement]
		if count > 0 {
			noticeColor.Printf("  %s: %d\n", enforcement, count)
		}
	}

	// Print detailed violations
	if len(kpe.violations) > 0 {
		infoColor.Println("Detailed Violations:")

		// Sort by severity level (CRITICAL first), then alphabetically
		sort.SliceStable(kpe.violations, func(i, j int) bool {
			iLevel := SeverityLevel(kpe.violations[i].Severity)
			jLevel := SeverityLevel(kpe.violations[j].Severity)
			if iLevel != jLevel {
				return iLevel < jLevel
			}
			return kpe.violations[i].PolicyID < kpe.violations[j].PolicyID
		})

		for i, violation := range kpe.violations {
			if i > 0 && kpe.violations[i-1].PolicyID == violation.PolicyID {
				continue
			}

			switch violation.Severity {
			case "CRITICAL", "HIGH":
				errorColor.Printf("[%s] %s\n", violation.Severity, violation.PolicyName)
			default:
				warnColor.Printf("[%s] %s\n", violation.Severity, violation.PolicyName)
			}

			infoColor.Printf("  Policy ID: %s\n", violation.PolicyID)
			infoColor.Printf("  Category: %s\n", violation.Category)
			infoColor.Printf("  Resource: %s/%s (Namespace: %s)\n", violation.Kind, violation.Name, violation.Namespace)
			infoColor.Printf("  File: %s\n", violation.Resource)
			infoColor.Printf("  Field: %s\n", violation.Field)
			infoColor.Printf("  Value: %v\n", violation.Value)
			infoColor.Printf("  Reason: %s\n", violation.Reason)
			infoColor.Printf("  Remediation: %s\n", violation.Remediation)
			infoColor.Println(strings.Repeat("-", 60))
		}
	}

	infoColor.Println(strings.Repeat("=", 80))

	// Check for failures
	failures := 0
	if kpe.failOnStrict && enforcementCounts["strict"] > 0 {
		errorColor.Printf("\nPolicy enforcement FAILED: %d strict violations\n", enforcementCounts["strict"])
		failures++
	}

	if kpe.failOnWarn && enforcementCounts["warn"] > 0 {
		errorColor.Printf("Policy enforcement FAILED: %d warning violations\n", enforcementCounts["warn"])
		failures++
	}

	if len(kpe.violations) > 0 && severityCounts["CRITICAL"] > 0 {
		errorColor.Printf("Policy enforcement FAILED: %d critical violations\n", severityCounts["CRITICAL"])
		failures++
	}

	if kpe.dryRun {
		warnColor.Println("This was a DRY RUN. No policies were enforced.")
	} else if failures == 0 {
		successColor.Println("Policy enforcement complete!")
	}

	if failures > 0 {
		os.Exit(1)
	}
}

func main() {
	// Define flags
	manifestDir := flag.String("dir", ".", "Directory containing Kubernetes manifests")
	failOnStrict := flag.Bool("fail-strict", true, "Fail if strict violations found")
	failOnWarn := flag.Bool("fail-warn", false, "Fail if warning violations found")
	namespace := flag.String("namespace", "*", "Namespace to evaluate (* for all)")
	dryRun := flag.Bool("dry-run", false, "Dry run mode")
	verbose := flag.Bool("verbose", false, "Verbose output")
	showHelp := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		return
	}

	// Create enforcer
	enforcer := NewKubernetesPolicyEnforcer(*failOnStrict, *failOnWarn, *verbose, *dryRun)
	enforcer.InitializePolicies()
	enforcer.namespace = *namespace

	// Load and evaluate manifests
	if err := enforcer.LoadK8sManifests(*manifestDir); err != nil {
		errorColor.Printf("Error loading manifests: %v\n", err)
		os.Exit(1)
	}

	// Print report
	enforcer.PrintReport()
}
