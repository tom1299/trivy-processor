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
	timestamp, _ := time.Parse(time.RFC3339, report.Metadata.CreationTimestamp)
	formattedTimestamp := timestamp.Format("20060102150405")
	return fmt.Sprintf("vulnerability-report-%s-%s-%s-%s:1.0.0-%s",
		report.Metadata.Labels.Namespace,
		report.Metadata.Labels.ResourceKind,
		report.Metadata.Labels.ResourceName,
		report.Metadata.Labels.ContainerName,
		formattedTimestamp)
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

	reportVersion := "v1.0.0-" + utils.GenerateUniqueID(string(report))
	url = fmt.Sprintf(url, reportVersion)
	logger.Infof("Sending report to GitLab: %s", url)

	additionalHeaders, _ := c.Config["GitlabAdditionalHeaders"].(string)
	headers := make(map[string]string)
	for _, header := range strings.Split(additionalHeaders, ",") {
		parts := strings.SplitN(header, "=", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(report)))
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := utils.NewLoggingHTTPClient(logger)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	} else {
		return fmt.Errorf("failed to send report to GitLab: %s", resp.Status)
	}
}
