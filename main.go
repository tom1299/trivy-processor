package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/tom1299/trivy-processor/utils"
)

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Create context
	ctx := utils.CreateContext()

	// Routes
	e.PUT("/report", func(c echo.Context) error {
		return handleReport(c, ctx)
	})

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}

func handleReport(c echo.Context, ctx *utils.Context) error {
	var jsonData map[string]interface{}
	if err := c.Bind(&jsonData); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// Marshal the JSON data to a byte array
	report, err := json.Marshal(jsonData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to process JSON"})
	}

	// Print the JSON to stdout
	fmt.Fprintln(os.Stdout, string(report))

	// Send the report to GitLab
	if err := sendReportToGitLab(c, report); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send report to GitLab"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "Report received"})
}

func sendReportToGitLab(c echo.Context, report []byte) error {
	// Get the additional headers from the context
	additionalHeaders := c.Get("trivyProcessorGitLabAdditionalHeaders").(string)
	headers := make(map[string]string)
	for _, header := range strings.Split(additionalHeaders, ",") {
		parts := strings.SplitN(header, "=", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	// Get the URL from the context
	url := c.Get("trivyProcessorGitLabURL").(string)

	// Create a new request
	req, err := http.NewRequest("POST", url, strings.NewReader(string(report)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send report to GitLab, status code: %d", resp.StatusCode)
	}

	return nil
}
