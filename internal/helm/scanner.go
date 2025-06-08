package helm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

type ChartAnalysis struct {
	Resources    []Resource      `json:"resources"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Metadata     chart.Metadata `json:"metadata"`
}

type Resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

type Vulnerability struct {
	Type        string `json:"type"`
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Path        string `json:"path"`
}

func (s *Scanner) AnalyzeChart(chartPath string) (*ChartAnalysis, error) {
	// Load the chart
	chart, err := loader.Load(chartPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load chart")
	}

	// Create default values
	values := chartutil.Values{}
	for _, f := range chart.Raw {
		if f.Name == "values.yaml" {
			if err := yaml.Unmarshal(f.Data, &values); err != nil {
				return nil, errors.Wrap(err, "failed to parse values.yaml")
			}
		}
	}

	// Render the templates
	renderer := engine.Engine{}
	rendered, err := renderer.Render(chart, values)
	if err != nil {
		return nil, errors.Wrap(err, "failed to render templates")
	}

	var resources []Resource
	var vulnerabilities []Vulnerability

	for path, content := range rendered {
		if strings.TrimSpace(content) == "" {
			continue
		}

		decoder := yaml.NewDecoder(strings.NewReader(content))
		for {
			var resource Resource
			if err := decoder.Decode(&resource); err != nil {
				if err == io.EOF {
					break
				}
				continue
			}

			if resource.APIVersion != "" && resource.Kind != "" {
				resources = append(resources, resource)
			}
		}

		if strings.Contains(content, "password: ") {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "security",
				RuleID:      "SEC002",
				Severity:    "critical",
				Description: "Hardcoded password detected",
				Path:        path,
			})
		}
	}

	vulnerabilities = append(vulnerabilities, s.checkResourceVulnerabilities(chart, resources)...)

	return &ChartAnalysis{
		Resources:      resources,
		Vulnerabilities: vulnerabilities,
		Metadata:       *chart.Metadata,
	}, nil
}


// Renamed to be more specific
func (s *Scanner) checkResourceVulnerabilities(chart *chart.Chart, resources []Resource) []Vulnerability {
    var vulnerabilities []Vulnerability

    // Check chart metadata
    if chart.Metadata.Deprecated {
        vulnerabilities = append(vulnerabilities, Vulnerability{
            Type:        "metadata",
            RuleID:      "DEP001",
            Severity:    "warning",
            Description: "This chart is marked as deprecated",
            Path:        "Chart.yaml",
        })
    }

    // Check resource-specific issues
    for _, resource := range resources {
        if resource.Kind == "Pod" {
            vulnerabilities = append(vulnerabilities, Vulnerability{
                Type:        "security",
                RuleID:      "SEC001",
                Severity:    "high",
                Description: "Direct Pod definitions are discouraged",
                Path:        resource.Kind + "/" + resource.Name,
            })
        }

        if resource.APIVersion == "extensions/v1beta1" || 
           resource.APIVersion == "apps/v1beta1" || 
           resource.APIVersion == "apps/v1beta2" {
            vulnerabilities = append(vulnerabilities, Vulnerability{
                Type:        "deprecation",
                RuleID:      "DEP002",
                Severity:    "medium",
                Description: fmt.Sprintf("API version %s is deprecated", resource.APIVersion),
                Path:        resource.Kind + "/" + resource.Name,
            })
        }
    }
    
    return vulnerabilities
}
func (s *Scanner) DownloadAndExtractChart(ctx context.Context, downloadURL string) (string, error) {
	// Create a temporary directory for this chart
	chartDir, err := os.MkdirTemp(s.tempDir, "chart-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp directory")
	}

	// Download the chart
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to download chart")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download chart: %s", resp.Status)
	}

	// Save the chart to a temporary file
	tmpFile := filepath.Join(chartDir, "chart.tgz")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return "", errors.Wrap(err, "failed to save chart")
	}

	// Extract the chart
	if err := extractTarGz(tmpFile, chartDir); err != nil {
		return "", errors.Wrap(err, "failed to extract chart")
	}

	// Find the chart directory (GitHub archives have an extra top-level directory)
	files, err := os.ReadDir(chartDir)
	if err != nil {
		return "", errors.Wrap(err, "failed to read temp directory")
	}

	for _, file := range files {
		if file.IsDir() && strings.HasPrefix(file.Name(), "chart") {
			return filepath.Join(chartDir, file.Name()), nil
		}
	}

	return "", fmt.Errorf("failed to find chart directory in archive")
}

func extractTarGz(src, dst string) error {
	// Implement tar.gz extraction here
	// You can use archive/tar and compress/gzip packages
	// This is a simplified placeholder
	return nil
}