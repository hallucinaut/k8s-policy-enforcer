package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	infoColor = color.New(color.FgBlue)
	warnColor = color.New(color.FgYellow)
	errorColor = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor = color.New(color.FgCyan)
)

// Policy represents a Kubernetes policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Enforcement string            `json:"enforcement"` // strict, warn, audit
	Rules       []PolicyRule      `json:"rules"`
}

// PolicyRule represents a single rule within a policy
type PolicyRule struct {
	Field       string        `json:"field"`
	Operator    string        `json:"operator"`
	Value       interface{}   `json:"value"`
	Message     string        `json:"message"`
	Severity    string        `json:"severity"`
	Categories  []string      `json:"categories"`
}

// Violation represents a policy violation
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

// PolicyResult holds the result of policy evaluation
type PolicyResult struct {
	PolicyID      string         `json:"policy_id"`
	PolicyName    string         `json:"policy_name"`
	Passed        bool           `json:"passed"`
	Violations    []Violation    `json:"violations"`
	Resources     int            `json:"resources"`
	Enforcement   string         `json:"enforcement"`
}

// PolicyEnforcementResult holds the overall enforcement result
type PolicyEnforcementResult struct {
	Namespace      string                `json:"namespace"`
	TotalPolicies int                   `json:"total_policies"`
	TotalViolations int                  `json:"total_violations"`
	Results        []PolicyResult        `json:"results"`
	Violations     []Violation           `json:"violations"`
	ComplianceRate float64               `json:"compliance_rate"`
}

// KubernetesPolicyEnforcer performs policy enforcement for Kubernetes
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

// NewKubernetesPolicyEnforcer creates a new KubernetesPolicyEnforcer
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

// getStringValue extracts a string value from a nested map
func getStringValue(resource map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := interface{}(resource)

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[part]; exists {
				if str, ok := val.(string); ok {
					current = str
				} else {
					return ""
				}
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

// InitializePolicies initializes all Kubernetes policies
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
					Field:     "securityContext.runAsRoot",
					Operator:  "equals",
					Value:     true,
					Message:   "Container runs as root user",
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
					Field:     "networkPolicies",
					Operator:  "count",
					Value:     0,
					Message:   "No network policies defined",
					Severity:  "MEDIUM",
					Categories: []string{"network", "security"},
				},
			},
		},
		{
			ID:          "K8S-NET-002",
			Name:        "Default Deny Ingress",
			Description: "Default deny ingress policy should exist",
			Category:    "Network",
			Severity:    "HIGH",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "defaultDenyIngress",
					Operator:  "exists",
					Value:     true,
					Message:   "No default deny ingress policy",
					Severity:  "HIGH",
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
		{
			ID:          "K8S-SA-002",
			Name:        "Service Account Token Auto-mount",
			Description: "Service account token auto-mount should be disabled",
			Category:    "Service Accounts",
			Severity:    "MEDIUM",
			Enforcement: "warn",
			Rules: []PolicyRule{
				{
					Field:     "automountServiceAccountToken",
					Operator:  "equals",
					Value:     true,
					Message:   "Service account token auto-mounted",
					Severity:  "MEDIUM",
					Categories: []string{"service-accounts", "security"},
				},
			},
		},
	}
}

// LoadK8sManifests loads Kubernetes manifests from a directory
func (kpe *KubernetesPolicyEnforcer) LoadK8sManifests(dirPath string) error {
	noticeColor.Printf("🔍 Loading Kubernetes manifests from: %s\n", dirPath)

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
			warnColor.Printf("⚠️  Failed to load %s: %v\n", path, err)
		}

		return nil
	})
}

// loadManifest loads and parses a single Kubernetes manifest
func (kpe *KubernetesPolicyEnforcer) loadManifest(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Simple YAML parsing for K8s resources
	manifests := strings.Split(string(content), "---")

	for _, manifest := range manifests {
		manifest = strings.TrimSpace(manifest)
		if manifest == "" {
			continue
		}

		var resource map[string]interface{}
		if err := kpe.parseYAML([]byte(manifest), &resource); err != nil {
			continue
		}

		kind := getStringValue(resource, "kind")
		name := getStringValue(resource, "metadata.name")
		namespace := getStringValue(resource, "metadata.namespace")
		if namespace == "" {
			namespace = "default"
		}

		kpe.evaluatePolicies(kind, name, namespace, resource, filePath)
	}

	return nil
}

// evaluatePolicies evaluates all policies against a resource
func (kpe *KubernetesPolicyEnforcer) evaluatePolicies(kind, name, namespace string, resource map[string]interface{}, filePath string) {
	for _, policies := range kpe.policies {
		for _, policy := range policies {
			result := kpe.evaluatePolicy(policy, kind, name, namespace, resource, filePath)
			kpe.results = append(kpe.results, result)
		}
	}
}

// evaluatePolicy evaluates a single policy against a resource
func (kpe *KubernetesPolicyEnforcer) evaluatePolicy(policy Policy, kind, name, namespace string, resource map[string]interface{}, filePath string) PolicyResult {
	result := PolicyResult{
		PolicyID:      policy.ID,
		PolicyName:    policy.Name,
		Passed:        true,
		Violations:    make([]Violation, 0),
		Resources:     1,
		Enforcement:   policy.Enforcement,
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

// getFieldValue extracts a field value from a nested map
func (kpe *KubernetesPolicyEnforcer) getFieldValue(resource map[string]interface{}, field string) interface{} {
	parts := strings.Split(field, ".")
	current := interface{}(resource)

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[part]; exists {
				current = val
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	return current
}

// checkCondition checks if a condition is met
func (kpe *KubernetesPolicyEnforcer) checkCondition(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "equals":
		if actual == nil {
			return false
		}
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)

	case "notEquals":
		if actual == nil {
			return false
		}
		return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected)

	case "exists":
		return actual != nil

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

// parseYAML parses YAML content (simplified implementation)
func (kpe *KubernetesPolicyEnforcer) parseYAML(content []byte, config *map[string]interface{}) error {
	lines := strings.Split(string(content), "\n")
	currentMap := make(map[string]interface{})

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if strings.HasPrefix(value, "-") {
			// List item
			itemValue := strings.TrimSpace(strings.TrimPrefix(value, "-"))
			currentMap[key] = append(currentMap[key].([]string), itemValue)
		} else {
			// Simple key-value
			var parsedValue interface{}

			if value == "true" {
				parsedValue = true
			} else if value == "false" {
				parsedValue = false
			} else if value == "null" || value == "~" {
				parsedValue = nil
			} else if value == "0" || value == "1" {
				parsedValue, _ = fmt.Sscanf(value, "%d", new(int))
			} else {
				parsedValue = strings.Trim(value, "\"'")
			}

			currentMap[key] = parsedValue
		}
	}

	*config = currentMap
	return nil
}

// generateRemediation generates remediation instructions
func (kpe *KubernetesPolicyEnforcer) generateRemediation(policy Policy, rule PolicyRule) string {
	remediations := map[string]string{
		"securityContext.privileged": "Set securityContext.privileged to false",
		"securityContext.runAsRoot":  "Set securityContext.runAsNonRoot to true",
		"securityContext.readOnlyRootFilesystem": "Set securityContext.readOnlyRootFilesystem to true",
		"securityContext.allowPrivilegeEscalation": "Set securityContext.allowPrivilegeEscalation to false",
		"hostNetwork":                "Set hostNetwork to false",
		"hostPID":                    "Set hostPID to false",
		"hostIPC":                    "Set hostIPC to false",
		"automountServiceAccountToken": "Set automountServiceAccountToken to false",
		"imageTag":                   "Specify a specific image tag instead of 'latest'",
		"resources.limits":           "Add resource limits (cpu, memory)",
		"resources.requests":         "Add resource requests (cpu, memory)",
	}

	if remediation, ok := remediations[rule.Field]; ok {
		return remediation
	}

	return fmt.Sprintf("Review and fix: %s", rule.Message)
}

// printViolation prints a violation
func (kpe *KubernetesPolicyEnforcer) printViolation(violation Violation) {
	severityEmoji := map[string]string{
		"CRITICAL": "🔴",
		"HIGH":     "🟠",
		"MEDIUM":   "🟡",
		"LOW":      "🟢",
	}

	emoji := severityEmoji[violation.Severity]
	if violation.Severity == "CRITICAL" || violation.Severity == "HIGH" {
		errorColor.Printf("%s [%s] %s - %s/%s\n", emoji, violation.Severity, violation.PolicyName, violation.Kind, violation.Name)
	} else {
		warnColor.Printf("%s [%s] %s - %s/%s\n", emoji, violation.Severity, violation.PolicyName, violation.Kind, violation.Name)
	}
}

// PrintReport prints the policy enforcement report
func (kpe *KubernetesPolicyEnforcer) PrintReport() {
	infoColor.Println("\n" + strings.Repeat("=", 80))
	infoColor.Println("📊 KUBERNETES POLICY ENFORCEMENT REPORT")
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

	successColor.Printf("✅ Total policies defined:    %d\n", totalPolicies)
	successColor.Printf("✅ Total checks performed:    %d\n", totalChecks)
	successColor.Printf("✅ Checks passed:             %d\n", passedChecks)
	warnColor.Printf("⚠️  Total violations:          %d\n", len(kpe.violations))
	successColor.Printf("📊 Compliance rate:           %.1f%%\n", complianceRate)

	infoColor.Println("\n🔍 Violations by Severity:")
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, severity := range severityOrder {
		count := severityCounts[severity]
		if count > 0 {
			emoji := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
			infoColor.Printf("  %s %s: %d\n", emoji, severity, count)
		}
	}

	infoColor.Println("\n🔍 Violations by Enforcement:")
	for enforcement, count := range enforcementCounts {
		if count > 0 {
			noticeColor.Printf("  • %s: %d\n", enforcement, count)
		}
	}

	// Print detailed violations
	if len(kpe.violations) > 0 {
		infoColor.Println("\n📋 Detailed Violations:\n")

		sort.Slice(kpe.violations, func(i, j int) bool {
			return kpe.violations[i].Severity < kpe.violations[j].Severity
		})

		for i, violation := range kpe.violations {
			if i > 0 && kpe.violations[i-1].PolicyID == violation.PolicyID {
				continue
			}

			emoji := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[violation.Severity]

			if violation.Severity == "CRITICAL" || violation.Severity == "HIGH" {
				errorColor.Printf("%s [%s] %s\n", emoji, violation.Severity, violation.PolicyName)
			} else {
				warnColor.Printf("%s [%s] %s\n", emoji, violation.Severity, violation.PolicyName)
			}

			infoColor.Printf("    Policy ID: %s\n", violation.PolicyID)
			infoColor.Printf("    Category: %s\n", violation.Category)
			infoColor.Printf("    Resource: %s/%s (Namespace: %s)\n", violation.Kind, violation.Name, violation.Namespace)
			infoColor.Printf("    File: %s\n", violation.Resource)
			infoColor.Printf("    Field: %s\n", violation.Field)
			infoColor.Printf("    Value: %v\n", violation.Value)
			infoColor.Printf("    Reason: %s\n", violation.Remediation)
			infoColor.Printf("    Remediation: %s\n", violation.Remediation)
			infoColor.Println(strings.Repeat("-", 60))
		}
	}

	infoColor.Println(strings.Repeat("=", 80))

	// Check for failures
	failures := 0
	if kpe.failOnStrict && enforcementCounts["strict"] > 0 {
		errorColor.Printf("\n❌ Policy enforcement FAILED: %d strict violations\n", enforcementCounts["strict"])
		failures++
	}

	if kpe.failOnWarn && enforcementCounts["warn"] > 0 {
		errorColor.Printf("❌ Policy enforcement FAILED: %d warning violations\n", enforcementCounts["warn"])
		failures++
	}

	if kpe.violations != nil && kpe.violations[0].Severity == "CRITICAL" {
		errorColor.Printf("❌ Policy enforcement FAILED: %d critical violations\n", severityCounts["CRITICAL"])
		failures++
	}

	if failures > 0 {
		os.Exit(1)
	}

	if kpe.dryRun {
		warnColor.Println("\n⚠️  This was a DRY RUN. No policies were enforced.\n")
	} else {
		successColor.Println("\n✅ Policy enforcement complete!\n")
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
		errorColor.Printf("❌ Error loading manifests: %v\n", err)
		os.Exit(1)
	}

	// Print report
	enforcer.PrintReport()
}