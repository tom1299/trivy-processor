package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Context struct {
	Config map[string]interface{}
}

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.PUT("/report", handleReport)

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}

func handleReport(c echo.Context) error {
	var jsonData map[string]interface{}
	if err := c.Bind(&jsonData); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	// Print the JSON to stdout
	report, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to process JSON"})
	}

	logReport(report, &Context{})
	sendReportToGitLab(report, &Context{})

	return c.JSON(http.StatusOK, map[string]string{"status": "Report received"})
}

func logReport(report []byte, context *Context) {
	fmt.Fprintln(os.Stdout, string(report))
}

func sendReportToGitLab(report []byte, context *Context) error {
	additionalHeaders := context.Config["trivyProcessorGitLabAdditionalHeaders"].(string)
	headers := make(map[string]string)
	for _, header := range strings.Split(additionalHeaders, ",") {
		parts := strings.SplitN(header, "=", 2)
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	url := context.Config["trivyProcessorGitLabURL"].(string)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(report)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

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
