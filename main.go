package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/tom1299/trivy-processor/utils"
)

type VulnerabilityReport struct {
	Metadata struct {
		Labels struct {
			ContainerName string `json:"trivy-operator.container.name"`
			ResourceKind  string `json:"trivy-operator.resource.kind"`
			ResourceName  string `json:"trivy-operator.resource.name"`
			Namespace     string `json:"trivy-operator.resource.namespace"`
		} `json:"labels"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
}

// Convert byte array to JSON
func convertToJSON(data []byte) (VulnerabilityReport, error) {
	var report VulnerabilityReport
	err := json.Unmarshal(data, &report)
	return report, err
}

// Construct report name
func constructReportName(report VulnerabilityReport) string {
	return fmt.Sprintf("vulnerability-report-%s-%s-%s",
		report.Metadata.Labels.Namespace,
		report.Metadata.Labels.ResourceKind,
		report.Metadata.Labels.ResourceName)
}

func generateSemanticVersion(report VulnerabilityReport) (string, error) {
	// Parse the creation timestamp
	t, err := time.Parse(time.RFC3339, report.Metadata.CreationTimestamp)
	if err != nil {
		return "", err
	}

	// Extract the date components
	major := 25
	minor := int(t.Month())
	patch := t.Day()

	// Optionally include additional metadata (e.g., hour and minute)
	preRelease := fmt.Sprintf("%02d%02d", t.Hour(), t.Minute())

	// Combine to form a valid semantic version
	version := fmt.Sprintf("%d.%d.%d-%s", major, minor, patch, preRelease)

	return version, nil
}

func main() {
	e := echo.New()
	e.Debug = true
	e.Logger.SetLevel(0)

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Create context
	ctx := utils.CreateContext()

	// Routes
	e.POST("/report", func(c echo.Context) error {
		return handleReport(c, ctx, e.Logger)
	})

	// Start server
	e.Logger.Info(e.Start(":8080"))
}

func handleReport(c echo.Context, ctx *utils.Context, logger echo.Logger) error {
	var jsonData map[string]interface{}
	if err := c.Bind(&jsonData); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	report, err := json.Marshal(jsonData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to process JSON"})
	}

	// Send the report to GitLab
	if err := sendReportToGitLab(*ctx, report, logger); err != nil {
		logger.Errorf("Error sending report to GitLab: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send report to GitLab"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "Report received"})
}

func sendReportToGitLab(c utils.Context, report []byte, logger echo.Logger) error {
	url, ok := c.Config["GitlabUrl"].(string)
	if !ok {
		return fmt.Errorf("GitLab URL is not configured")
	}

	json_report, err := convertToJSON(report)
	if err != nil {
		return fmt.Errorf("failed to convert report to JSON: %v", err)
	}
	reportVersion, err := generateSemanticVersion(json_report)
	if err != nil {
		return fmt.Errorf("failed to generate semantic version: %v", err)
	}
	reportName := constructReportName(json_report)

	packageURL := fmt.Sprintf("%spackages/generic/trivy-reports/%s/%s.json", url, reportVersion, reportName)

	logger.Infof("Sending report to GitLab: %s", packageURL)

	additionalHeaders, _ := c.Config["GitlabAdditionalHeaders"].(string)
	headers := make(map[string]string)
	for _, header := range strings.Split(additionalHeaders, ",") {
		parts := strings.SplitN(header, "=", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	req, err := http.NewRequest("PUT", packageURL, strings.NewReader(string(report)))
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "multipart/form-data")

	client := utils.NewLoggingHTTPClient(logger)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status code: %d", resp.StatusCode)

	}

	triggerPipelineURL := fmt.Sprintf("%spipeline", url)

	triggerPayload := map[string]interface{}{
		"ref": "main",
		"variables": []map[string]string{
			{"key": "REPORT_VERSION", "value": reportVersion},
			{"key": "REPORT_NAME", "value": reportName},
		},
	}

	logger.Infof("Triggering pipeline for report: %s using url: %s", reportName, triggerPipelineURL)

	payloadBytes, err := json.Marshal(triggerPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger payload: %v", err)
	}

	triggerReq, err := http.NewRequest("POST", triggerPipelineURL, strings.NewReader(string(payloadBytes)))
	if err != nil {

		return fmt.Errorf("failed to create pipeline trigger request: %v", err)
	}
	for key, value := range headers {
		triggerReq.Header.Set(key, value)
	}

	triggerReq.Header.Set("Content-Type", "application/json")

	triggerResp, err := client.Do(triggerReq)
	if err != nil {
		return fmt.Errorf("failed to trigger pipeline: %v", err)
	}
	defer triggerResp.Body.Close()

	if triggerResp.StatusCode < 200 || triggerResp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status code when triggering pipeline: %d", triggerResp.StatusCode)
	}

	logger.Infof("Pipeline triggered successfully for report: %s", reportName)

	return nil
}
