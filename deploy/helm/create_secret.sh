#!/bin/bash

NAMESPACE="trivy-operator"
SECRET_NAME="trivy-processor"
SECRETS_DIR="./secrets"

kubectl create secret generic $SECRET_NAME --namespace=$NAMESPACE --from-file=$SECRETS_DIR
