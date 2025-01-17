package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

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
	jsonReport, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to process JSON"})
	}
	fmt.Fprintln(os.Stdout, string(jsonReport))

	return c.JSON(http.StatusOK, map[string]string{"status": "Report received"})
}
