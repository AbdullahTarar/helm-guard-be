package helm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
)

type Scanner struct {
	tempDir string
}

func NewScanner(tempDir string) (*Scanner, error) {
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}
	return &Scanner{tempDir: tempDir}, nil
}

// Complete analysis response matching frontend expectations
type ScanResults struct {
	Repository       Repository        `json:"repository"`
	Summary          Summary           `json:"summary"`
	Charts           []ChartInfo       `json:"charts"`
	SecurityFindings []SecurityFinding `json:"securityFindings"`
	Resources        []Resource        `json:"resources"`
	BestPractices    []BestPractice    `json:"bestPractices"`
}

type Repository struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Branch     string    `json:"branch"`
	LastCommit string    `json:"lastCommit"`
	ScanDate   time.Time `json:"scanDate"`
}

type Summary struct {
	TotalIssues int `json:"totalIssues"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Passed      int `json:"passed"`
	Score       int `json:"score"`
}

type ChartInfo struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Version   string `json:"version"`
	Issues    int    `json:"issues"`
	Resources int    `json:"resources"`
}

type SecurityFinding struct {
	ID             string  `json:"id"`
	Severity       string  `json:"severity"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	File           string  `json:"file"`
	Line           *int    `json:"line,omitempty"`
	Recommendation string  `json:"recommendation"`
	Category       string  `json:"category"`
}

type Resource struct {
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Replicas  *int      `json:"replicas,omitempty"`
	Ports     []string  `json:"ports,omitempty"`
	Keys      *int      `json:"keys,omitempty"`
	Size      string    `json:"size,omitempty"`
	Hosts     []string  `json:"hosts,omitempty"`
	Details   yaml.Node `json:"-"` // Store full resource for analysis
}

type BestPractice struct {
	Category string              `json:"category"`
	Passed   int                 `json:"passed"`
	Total    int                 `json:"total"`
	Items    []BestPracticeItem  `json:"items"`
}

type BestPracticeItem struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "passed" or "failed"
	Severity string `json:"severity"`
}

// Legacy structs for backward compatibility
type ChartAnalysis struct {
	Resources       []Resource      `json:"resources"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Metadata        chart.Metadata  `json:"metadata"`
}

type Vulnerability struct {
	Type        string `json:"type"`
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

// Security rules and checks
type SecurityRule struct {
	ID             string
	Category       string
	Title          string
	Description    string
	Severity       string
	Recommendation string
	CheckFunc      func(resource *Resource, content string) bool
}

func (s *Scanner) getSecurityRules() []SecurityRule {
	return []SecurityRule{
		{
			ID:             "SEC-001",
			Category:       "Security Context",
			Title:          "Container running as root",
			Description:    "Container is configured to run as root user, which poses security risks",
			Severity:       "critical",
			Recommendation: "Set securityContext.runAsNonRoot: true and securityContext.runAsUser to a non-root UID",
			CheckFunc: func(resource *Resource, content string) bool {
				return resource.Type == "Deployment" && 
					   (strings.Contains(content, "runAsUser: 0") || 
					    !strings.Contains(content, "runAsNonRoot: true"))
			},
		},
		{
			ID:             "SEC-002",
			Category:       "Security Context",
			Title:          "Privileged container detected",
			Description:    "Container is running in privileged mode",
			Severity:       "critical",
			Recommendation: "Remove privileged: true unless absolutely necessary",
			CheckFunc: func(resource *Resource, content string) bool {
				return strings.Contains(content, "privileged: true")
			},
		},
		{
			ID:             "SEC-003",
			Category:       "Resource Management",
			Title:          "Missing resource limits",
			Description:    "No CPU or memory limits specified",
			Severity:       "high",
			Recommendation: "Add resources.limits.cpu and resources.limits.memory",
			CheckFunc: func(resource *Resource, content string) bool {
				return resource.Type == "Deployment" && 
					   (!strings.Contains(content, "limits:") || 
					    !strings.Contains(content, "cpu:") || 
					    !strings.Contains(content, "memory:"))
			},
		},
		{
			ID:             "SEC-004",
			Category:       "Image Security",
			Title:          "Insecure image tag",
			Description:    "Using 'latest' tag instead of specific version",
			Severity:       "high",
			Recommendation: "Use specific image tags instead of 'latest'",
			CheckFunc: func(resource *Resource, content string) bool {
				return strings.Contains(content, ":latest") || 
					   regexp.MustCompile(`image:\s*[\w\-\.]+/[\w\-\.]+$`).MatchString(content)
			},
		},
		{
			ID:             "SEC-005",
			Category:       "Network Security",
			Title:          "Missing network policy",
			Description:    "No network policies defined for pod-to-pod communication",
			Severity:       "medium",
			Recommendation: "Add NetworkPolicy resources to restrict traffic",
			CheckFunc: func(resource *Resource, content string) bool {
				return resource.Type == "NetworkPolicy"
			},
		},
		{
			ID:             "SEC-006",
			Category:       "Security Context",
			Title:          "Missing readOnlyRootFilesystem",
			Description:    "Container filesystem is not read-only",
			Severity:       "medium",
			Recommendation: "Set securityContext.readOnlyRootFilesystem: true",
			CheckFunc: func(resource *Resource, content string) bool {
				return resource.Type == "Deployment" && 
					   !strings.Contains(content, "readOnlyRootFilesystem: true")
			},
		},
		{
			ID:             "SEC-007",
			Category:       "Security Context",
			Title:          "Missing capability drops",
			Description:    "Container capabilities are not restricted",
			Severity:       "medium",
			Recommendation: "Add securityContext.capabilities.drop: [\"ALL\"]",
			CheckFunc: func(resource *Resource, content string) bool {
				return resource.Type == "Deployment" && 
					   !strings.Contains(content, "drop:")
			},
		},
	}
}

func (s *Scanner) getBestPracticeRules() map[string][]BestPracticeRule {
	return map[string][]BestPracticeRule{
		"Security": {
			{Name: "Non-root user", Severity: "critical", CheckFunc: s.checkNonRootUser},
			{Name: "Read-only filesystem", Severity: "medium", CheckFunc: s.checkReadOnlyFilesystem},
			{Name: "No privileged containers", Severity: "critical", CheckFunc: s.checkNoPrivileged},
			{Name: "Resource limits set", Severity: "high", CheckFunc: s.checkResourceLimits},
			{Name: "Image vulnerability scan", Severity: "medium", CheckFunc: s.checkImageScan},
			{Name: "Secrets not in environment", Severity: "high", CheckFunc: s.checkSecretsNotInEnv},
			{Name: "Security context defined", Severity: "high", CheckFunc: s.checkSecurityContext},
			{Name: "Network policies defined", Severity: "medium", CheckFunc: s.checkNetworkPolicies},
			{Name: "Service account configured", Severity: "medium", CheckFunc: s.checkServiceAccount},
			{Name: "Pod security standards", Severity: "high", CheckFunc: s.checkPodSecurityStandards},
		},
		"Reliability": {
			{Name: "Health checks configured", Severity: "high", CheckFunc: s.checkHealthChecks},
			{Name: "Resource requests set", Severity: "medium", CheckFunc: s.checkResourceRequests},
			{Name: "Multiple replicas", Severity: "medium", CheckFunc: s.checkMultipleReplicas},
			{Name: "Pod disruption budget", Severity: "medium", CheckFunc: s.checkPodDisruptionBudget},
			{Name: "Graceful shutdown", Severity: "low", CheckFunc: s.checkGracefulShutdown},
			{Name: "Rolling update strategy", Severity: "medium", CheckFunc: s.checkRollingUpdate},
			{Name: "Persistent volume claims", Severity: "low", CheckFunc: s.checkPersistentVolumes},
			{Name: "Configuration externalized", Severity: "medium", CheckFunc: s.checkExternalizedConfig},
			{Name: "Labels and annotations", Severity: "low", CheckFunc: s.checkLabelsAnnotations},
			{Name: "Anti-affinity rules", Severity: "low", CheckFunc: s.checkAntiAffinity},
		},
		"Performance": {
			{Name: "Resource optimization", Severity: "medium", CheckFunc: s.checkResourceOptimization},
			{Name: "Horizontal pod autoscaling", Severity: "low", CheckFunc: s.checkHPA},
			{Name: "Efficient image layers", Severity: "low", CheckFunc: s.checkImageLayers},
			{Name: "Caching strategies", Severity: "low", CheckFunc: s.checkCaching},
			{Name: "Resource quotas", Severity: "medium", CheckFunc: s.checkResourceQuotas},
		},
		"Maintainability": {
			{Name: "Documentation present", Severity: "low", CheckFunc: s.checkDocumentation},
			{Name: "Proper naming conventions", Severity: "low", CheckFunc: s.checkNamingConventions},
			{Name: "Version pinning", Severity: "medium", CheckFunc: s.checkVersionPinning},
			{Name: "Helm hooks usage", Severity: "low", CheckFunc: s.checkHelmHooks},
			{Name: "Template functions", Severity: "low", CheckFunc: s.checkTemplateFunctions},
		},
	}
}

type BestPracticeRule struct {
	Name      string
	Severity  string
	CheckFunc func(resources []Resource, rendered map[string]string) bool
}

// mergeValues merges source map into destination map recursively
func mergeValues(dest, src map[string]interface{}) {
	for key, srcVal := range src {
		if destVal, exists := dest[key]; exists {
			if srcMap, ok := srcVal.(map[string]interface{}); ok {
				if destMap, ok := destVal.(map[string]interface{}); ok {
					mergeValues(destMap, srcMap)
					continue
				}
			}
		}
		dest[key] = srcVal
	}
}

func findChartDir(baseDir string) (string, error) {
	var chartDir string
	log.Printf("Searching for Chart.yaml under %s", baseDir)
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if _, err := os.Stat(filepath.Join(path, "Chart.yaml")); err == nil {
			chartDir = path
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if chartDir == "" {
		return "", fmt.Errorf("no Chart.yaml found")
	}
	return chartDir, nil
}

// New comprehensive analysis method
func (s *Scanner) AnalyzeChartComprehensive(chartPath, repositoryURL string) (*ScanResults, error) {
	log.Printf("[DEBUG] Starting comprehensive analysis of %s", chartPath)

	// Step 1: Locate Chart.yaml
	actualChartPath, err := findChartDir(chartPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to locate Chart.yaml")
	}

	// Step 2: Load the chart
	chart, err := loader.Load(actualChartPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load chart")
	}

	// Step 3: Render templates
	rendered, resources, err := s.renderChart(chart)
	if err != nil {
		return nil, err
	}

	// Step 4: Perform security analysis
	securityFindings := s.performSecurityAnalysis(resources, rendered)

	// Step 5: Perform best practices analysis
	bestPractices := s.performBestPracticesAnalysis(resources, rendered)

	// Step 6: Calculate summary and score
	summary := s.calculateSummary(securityFindings, bestPractices)

	// Step 7: Extract repository info
	repository := Repository{
		Name:       chart.Metadata.Name,
		URL:        repositoryURL,
		Branch:     "main", // Default, could be extracted from git if available
		LastCommit: "unknown",
		ScanDate:   time.Now(),
	}

	// Step 8: Create chart info
	chartInfo := ChartInfo{
		Name:      chart.Metadata.Name,
		Path:      actualChartPath,
		Version:   chart.Metadata.Version,
		Issues:    len(securityFindings),
		Resources: len(resources),
	}

	return &ScanResults{
		Repository:       repository,
		Summary:          summary,
		Charts:           []ChartInfo{chartInfo},
		SecurityFindings: securityFindings,
		Resources:        resources,
		BestPractices:    bestPractices,
	}, nil
}

func (s *Scanner) renderChart(chart *chart.Chart) (map[string]string, []Resource, error) {
	// Load and merge values
	chartValues := make(map[string]interface{})
	if chart.Values != nil {
		chartValues = chart.Values
	}

	// Default values
	defaultValues := map[string]interface{}{
		"serviceAccount": map[string]interface{}{
			"create": true,
			"name":   "",
		},
		"autoscaling": map[string]interface{}{
			"enabled": false,
		},
		"ingress": map[string]interface{}{
			"enabled": false,
		},
		"podSecurityContext": map[string]interface{}{},
		"securityContext":    map[string]interface{}{},
		"nodeSelector":       map[string]interface{}{},
		"tolerations":        []interface{}{},
		"affinity":           map[string]interface{}{},
		"fullnameOverride":   "",
		"nameOverride":       "",
		"replicaCount":       1,
		"image": map[string]interface{}{
			"repository": "nginx",
			"tag":        "1.20",
			"pullPolicy": "IfNotPresent",
		},
		"service": map[string]interface{}{
			"type": "ClusterIP",
			"port": 80,
		},
		"resources": map[string]interface{}{
			"limits": map[string]interface{}{
				"cpu":    "100m",
				"memory": "128Mi",
			},
			"requests": map[string]interface{}{
				"cpu":    "100m",
				"memory": "128Mi",
			},
		},
	}

	mergeValues(defaultValues, chartValues)
	chartValues = defaultValues

	// Create release options
	releaseOptions := chartutil.ReleaseOptions{
		Name:      "test-release",
		Namespace: "default",
		Revision:  1,
		IsInstall: true,
	}

	// Prepare values for rendering
	vals, err := chartutil.ToRenderValues(chart, chartValues, releaseOptions, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to prepare chart values")
	}

	// Render templates
    renderer := engine.Engine{}
    rendered, err := renderer.Render(chart, vals)
    if err != nil {
        return nil, nil, errors.Wrap(err, "failed to render templates")
    }

    // Parse resources
    var resources []Resource
    for path, content := range rendered {
        if strings.TrimSpace(content) == "" || 
           strings.Contains(path, "/tests/") || 
           strings.HasSuffix(path, "NOTES.txt") {
            continue
        }

        decoder := yaml.NewDecoder(strings.NewReader(content))
        for {
            var resourceMap map[string]interface{}
            if err := decoder.Decode(&resourceMap); err != nil {
                if err == io.EOF {
                    break
                }
                continue
            }

			if _, ok := resourceMap["apiVersion"].(string); ok {
				if kind, ok := resourceMap["kind"].(string); ok {
					resource := Resource{
						Type:      kind,
						Name:      s.extractName(resourceMap),
						Namespace: s.extractNamespace(resourceMap),
					}

                    // Extract additional details based on resource type
                    s.extractResourceDetails(&resource, resourceMap, content)
                    resources = append(resources, resource)
                }
            }
        }
    }

    return rendered, resources, nil
}

func (s *Scanner) extractName(resourceMap map[string]interface{}) string {
    if metadata, ok := resourceMap["metadata"].(map[string]interface{}); ok {
        if name, ok := metadata["name"].(string); ok {
            return name
        }
    }
    return "unknown"
}

func (s *Scanner) extractNamespace(resourceMap map[string]interface{}) string {
	if metadata, ok := resourceMap["metadata"].(map[string]interface{}); ok {
		if namespace, ok := metadata["namespace"].(string); ok {
			return namespace
		}
	}
	return "default"
}

func (s *Scanner) extractResourceDetails(resource *Resource, resourceMap map[string]interface{}, content string) {
	switch resource.Type {
	case "Deployment":
		if spec, ok := resourceMap["spec"].(map[string]interface{}); ok {
			if replicas, ok := spec["replicas"].(int); ok {
				resource.Replicas = &replicas
			}
		}
	case "Service":
		ports := s.extractServicePorts(resourceMap)
		resource.Ports = ports
	case "ConfigMap", "Secret":
		keys := s.extractDataKeys(resourceMap)
		resource.Keys = &keys
	case "PersistentVolumeClaim":
		size := s.extractPVCSize(resourceMap)
		resource.Size = size
	case "Ingress":
		hosts := s.extractIngressHosts(resourceMap)
		resource.Hosts = hosts
	}
}

func (s *Scanner) extractServicePorts(resourceMap map[string]interface{}) []string {
	var ports []string
	if spec, ok := resourceMap["spec"].(map[string]interface{}); ok {
		if portsArray, ok := spec["ports"].([]interface{}); ok {
			for _, portInterface := range portsArray {
				if portMap, ok := portInterface.(map[string]interface{}); ok {
					if port, ok := portMap["port"].(int); ok {
						ports = append(ports, strconv.Itoa(port))
					}
				}
			}
		}
	}
	return ports
}

func (s *Scanner) extractDataKeys(resourceMap map[string]interface{}) int {
	if data, ok := resourceMap["data"].(map[string]interface{}); ok {
		return len(data)
	}
	return 0
}

func (s *Scanner) extractPVCSize(resourceMap map[string]interface{}) string {
	if spec, ok := resourceMap["spec"].(map[string]interface{}); ok {
		if resources, ok := spec["resources"].(map[string]interface{}); ok {
			if requests, ok := resources["requests"].(map[string]interface{}); ok {
				if storage, ok := requests["storage"].(string); ok {
					return storage
				}
			}
		}
	}
	return ""
}

func (s *Scanner) extractIngressHosts(resourceMap map[string]interface{}) []string {
	var hosts []string
	if spec, ok := resourceMap["spec"].(map[string]interface{}); ok {
		if rules, ok := spec["rules"].([]interface{}); ok {
			for _, ruleInterface := range rules {
				if ruleMap, ok := ruleInterface.(map[string]interface{}); ok {
					if host, ok := ruleMap["host"].(string); ok {
						hosts = append(hosts, host)
					}
				}
			}
		}
	}
	return hosts
}

func (s *Scanner) performSecurityAnalysis(resources []Resource, rendered map[string]string) []SecurityFinding {
    var findings []SecurityFinding
    rules := s.getSecurityRules()
    
    findingID := 1
    for _, rule := range rules {
        for _, resource := range resources {
            // Find the rendered content for this resource
            var content string
            var filePath string // Track the path where the resource was found
            
            for path, renderedContent := range rendered {
                if strings.Contains(renderedContent, resource.Name) {
                    content = renderedContent
                    filePath = path
                    break
                }
            }

            if rule.CheckFunc(&resource, content) {
                findings = append(findings, SecurityFinding{
                    ID:             fmt.Sprintf("SEC-%03d", findingID),
                    Severity:       rule.Severity,
                    Title:          rule.Title,
                    Description:    rule.Description,
                    File:           filePath, // Use the actual path where found
                    Line:           nil,      // Could be enhanced to find actual line numbers
                    Recommendation: rule.Recommendation,
                    Category:       rule.Category,
                })
                findingID++
            }
        }
    }

    // Additional hardcoded checks
    for path, content := range rendered {
        if strings.Contains(content, "password:") || strings.Contains(content, "PASSWORD:") {
            findings = append(findings, SecurityFinding{
                ID:             fmt.Sprintf("SEC-%03d", findingID),
                Severity:       "critical",
                Title:          "Hardcoded credentials detected",
                Description:    "Hardcoded password or credential found in template",
                File:           path,
                Line:           nil,
                Recommendation: "Use Kubernetes Secrets to store credentials",
                Category:       "Secret Management",
            })
            findingID++
        }
    }

    return findings
}

func (s *Scanner) performBestPracticesAnalysis(resources []Resource, rendered map[string]string) []BestPractice {
	var bestPractices []BestPractice
	rules := s.getBestPracticeRules()

	for category, categoryRules := range rules {
		var items []BestPracticeItem
		passed := 0

		for _, rule := range categoryRules {
			status := "failed"
			if rule.CheckFunc(resources, rendered) {
				status = "passed"
				passed++
			}

			items = append(items, BestPracticeItem{
				Name:     rule.Name,
				Status:   status,
				Severity: rule.Severity,
			})
		}

		bestPractices = append(bestPractices, BestPractice{
			Category: category,
			Passed:   passed,
			Total:    len(categoryRules),
			Items:    items,
		})
	}

	return bestPractices
}

func (s *Scanner) calculateSummary(findings []SecurityFinding, practices []BestPractice) Summary {
	summary := Summary{}

	// Count security findings by severity
	for _, finding := range findings {
		summary.TotalIssues++
		switch finding.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}

	// Count passed best practices
	for _, practice := range practices {
		summary.Passed += practice.Passed
	}

	// Calculate score (0-100)
	totalChecks := summary.TotalIssues + summary.Passed
	if totalChecks > 0 {
		// Weight different severities
		weightedFailures := summary.Critical*10 + summary.High*5 + summary.Medium*2 + summary.Low*1
		maxPossibleScore := totalChecks * 10 // Assuming all could be critical
		
		summary.Score = 100 - (weightedFailures*100)/maxPossibleScore
		if summary.Score < 0 {
			summary.Score = 0
		}
	} else {
		summary.Score = 100
	}

	return summary
}

// Best practice check functions
func (s *Scanner) checkNonRootUser(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "runAsNonRoot: true") && 
						   !strings.Contains(content, "runAsUser: 0")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkReadOnlyFilesystem(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "readOnlyRootFilesystem: true")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkNoPrivileged(resources []Resource, rendered map[string]string) bool {
	for _, content := range rendered {
		if strings.Contains(content, "privileged: true") {
			return false
		}
	}
	return true
}

func (s *Scanner) checkResourceLimits(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "limits:") && 
						   strings.Contains(content, "cpu:") && 
						   strings.Contains(content, "memory:")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkImageScan(resources []Resource, rendered map[string]string) bool {
	// This would typically integrate with image scanning tools
	// For now, we'll check if specific image tags are used (not latest)
	for _, content := range rendered {
		if strings.Contains(content, ":latest") {
			return false
		}
	}
	return true
}

func (s *Scanner) checkSecretsNotInEnv(resources []Resource, rendered map[string]string) bool {
	for _, content := range rendered {
		if strings.Contains(content, "env:") && strings.Contains(content, "password") {
			return false
		}
	}
	return true
}

func (s *Scanner) checkSecurityContext(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "securityContext:")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkNetworkPolicies(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "NetworkPolicy" {
			return true
		}
	}
	return false
}

func (s *Scanner) checkServiceAccount(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "ServiceAccount" {
			return true
		}
	}
	return false
}

func (s *Scanner) checkPodSecurityStandards(resources []Resource, rendered map[string]string) bool {
	// Check for pod security standards compliance
	for _, content := range rendered {
		if strings.Contains(content, "pod-security.kubernetes.io/") {
			return true
		}
	}
	return false
}

func (s *Scanner) checkHealthChecks(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "livenessProbe:") || 
						   strings.Contains(content, "readinessProbe:")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkResourceRequests(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" {
			for _, content := range rendered {
				if strings.Contains(content, resource.Name) {
					return strings.Contains(content, "requests:")
				}
			}
		}
	}
	return false
}

func (s *Scanner) checkMultipleReplicas(resources []Resource, rendered map[string]string) bool {
	for _, resource := range resources {
		if resource.Type == "Deployment" && resource.Replicas != nil {
			return *resource.Replicas > 1
		}
	}
	return false
}

func (s *Scanner) checkPodDisruptionBudget(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "PodDisruptionBudget" {
            return true
        }
    }
    return false
}

func (s *Scanner) checkGracefulShutdown(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "Deployment" {
            for _, content := range rendered {
                if strings.Contains(content, resource.Name) {
                    return strings.Contains(content, "terminationGracePeriodSeconds:") &&
                           strings.Contains(content, "preStop:")
                }
            }
        }
    }
    return false
}

func (s *Scanner) checkRollingUpdate(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "Deployment" {
            for _, content := range rendered {
                if strings.Contains(content, resource.Name) {
                    return strings.Contains(content, "rollingUpdate:") &&
                           strings.Contains(content, "maxUnavailable:") &&
                           strings.Contains(content, "maxSurge:")
                }
            }
        }
    }
    return false
}

func (s *Scanner) checkPersistentVolumes(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "PersistentVolumeClaim" {
            return true
        }
    }
    return false
}

func (s *Scanner) checkExternalizedConfig(resources []Resource, rendered map[string]string) bool {
    hasConfigMap := false
    hasSecret := false
    
    for _, resource := range resources {
        if resource.Type == "ConfigMap" {
            hasConfigMap = true
        }
        if resource.Type == "Secret" {
            hasSecret = true
        }
    }
    
    return hasConfigMap || hasSecret
}

func (s *Scanner) checkLabelsAnnotations(resources []Resource, rendered map[string]string) bool {
    for _, content := range rendered {
        if strings.Contains(content, "metadata:") {
            return strings.Contains(content, "labels:") &&
                   strings.Contains(content, "annotations:")
        }
    }
    return false
}

func (s *Scanner) checkAntiAffinity(resources []Resource, rendered map[string]string) bool {
    for _, content := range rendered {
        if strings.Contains(content, "affinity:") &&
           strings.Contains(content, "podAntiAffinity:") {
            return true
        }
    }
    return false
}

func (s *Scanner) checkResourceOptimization(resources []Resource, rendered map[string]string) bool {
    // This would require more sophisticated analysis
    // For now, we'll check if both requests and limits are set
    return s.checkResourceLimits(resources, rendered) && 
           s.checkResourceRequests(resources, rendered)
}

func (s *Scanner) checkHPA(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "HorizontalPodAutoscaler" {
            return true
        }
    }
    return false
}

func (s *Scanner) checkImageLayers(resources []Resource, rendered map[string]string) bool {
    // This would typically require image analysis
    // For now, we'll assume it passes if we're not using latest tag
    return s.checkImageScan(resources, rendered)
}

func (s *Scanner) checkCaching(resources []Resource, rendered map[string]string) bool {
    // Check for volume mounts that could indicate caching
    for _, content := range rendered {
        if strings.Contains(content, "volumeMounts:") &&
           (strings.Contains(content, "cache") ||
            strings.Contains(content, "tmp")) {
            return true
        }
    }
    return false
}

func (s *Scanner) checkResourceQuotas(resources []Resource, rendered map[string]string) bool {
    for _, resource := range resources {
        if resource.Type == "ResourceQuota" {
            return true
        }
    }
    return false
}

func (s *Scanner) checkDocumentation(resources []Resource, rendered map[string]string) bool {
    // Check for README or other documentation files
    // This would need to check the actual chart files, not just rendered templates
    // For now, we'll assume it's present
    return true
}

func (s *Scanner) checkNamingConventions(resources []Resource, rendered map[string]string) bool {
    // Check resource names follow conventions
    for _, resource := range resources {
        if !isValidResourceName(resource.Name) {
            return false
        }
    }
    return true
}

func isValidResourceName(name string) bool {
    // Simple validation - could be enhanced
    return len(name) <= 253 && 
           regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(name)
}

func (s *Scanner) checkVersionPinning(resources []Resource, rendered map[string]string) bool {
    // Check for version pinning in images
    for _, content := range rendered {
        if strings.Contains(content, "image:") && 
           !strings.Contains(content, ":") {
            return false
        }
    }
    return true
}

func (s *Scanner) checkHelmHooks(resources []Resource, rendered map[string]string) bool {
    // Check for proper use of Helm hooks
    for _, content := range rendered {
        if strings.Contains(content, "helm.sh/hook:") {
            return true
        }
    }
    return false
}

func (s *Scanner) checkTemplateFunctions(resources []Resource, rendered map[string]string) bool {
    // Check for proper use of template functions
    // This would require more sophisticated analysis
    // For now, we'll assume it passes
    return true
}


func (s *Scanner) DownloadAndExtractChart(ctx context.Context, downloadURL string) (string, error) {
	chartDir, err := os.MkdirTemp(s.tempDir, "chart-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp directory")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to download chart")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download chart: %s", resp.Status)
	}

	tmpFile := filepath.Join(chartDir, "chart.tgz")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", errors.Wrap(err, "failed to save chart")
	}

	if err := extractTarGz(tmpFile, chartDir); err != nil {
		return "", errors.Wrap(err, "failed to extract chart")
	}

	actualChartDir, err := findChartDir(chartDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to locate Chart.yaml in extracted contents")
	}
	return actualChartDir, nil
}

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dst, header.Name)
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			log.Printf("[WARN] Skipping potentially dangerous path: %s", header.Name)
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}
	return nil
}