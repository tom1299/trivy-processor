#!/bin/bash

URL="http://localhost:8080/report"
curl -X POST -H "Content-Type: application/json" -d @"./trivy-operator-sample-report.json" "$URL"