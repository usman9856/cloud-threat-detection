#!/bin/bash
# cleanup.sh - Destroys the whole P5 stack with Terraform, then lists what is left.
# DESTRUCTIVE: asks for confirmation first. Only touches this project's Terraform state.
# Last updated: 2026-11-15
cd "$(dirname "$0")/.."
R=us-east-1
read -p "Destroy the P5 stack? Type yes: " ANSWER
[ "$ANSWER" = "yes" ] || { echo "Cancelled."; exit 1; }
terraform -chdir=terraform destroy
echo "== Left over (should be empty) =="
aws lambda list-functions --region $R --query "Functions[?starts_with(FunctionName,'p5-')].FunctionName"
aws cloudtrail describe-trails --region $R --query "trailList[].Name"
aws events list-rules --region $R --query "Rules[].Name"
