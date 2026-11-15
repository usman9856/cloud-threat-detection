#!/bin/bash
# teardown-manual.sh - One-off: deletes the live P5 resources by name because the Terraform state was lost.
# DESTRUCTIVE: asks for confirmation. Only touches p5-* resources in us-east-1. Delete this file after use.
# Last updated: 2026-11-15
export MSYS_NO_PATHCONV=1
R=us-east-1
ACC=$(aws sts get-caller-identity --query Account --output text)
read -p "Delete the live P5 resources in account ending ${ACC: -4}? Type yes: " A
[ "$A" = "yes" ] || { echo "Cancelled."; exit 1; }

IDS=$(aws events list-targets-by-rule --rule p5-logging-tampered --region $R --query "Targets[].Id" --output text)
[ -n "$IDS" ] && aws events remove-targets --rule p5-logging-tampered --ids $IDS --region $R
aws events delete-rule --name p5-logging-tampered --region $R
aws lambda delete-function --function-name p5-remediate-logging --region $R
aws logs delete-log-group --log-group-name /aws/lambda/p5-remediate-logging --region $R
aws iam delete-role-policy --role-name p5-remediate-logging --policy-name least-privilege
aws iam delete-role --role-name p5-remediate-logging
aws cloudtrail delete-trail --name p5-lab-trail --region $R
aws s3 rb s3://p5-trail-logs-$ACC --force
aws sns delete-topic --topic-arn arn:aws:sns:$R:$ACC:p5-alerts --region $R

echo "== Left over (all should be empty) =="
aws lambda list-functions --region $R --query "Functions[?starts_with(FunctionName,'p5-')].FunctionName" --output text
aws events list-rules --region $R --query "Rules[?starts_with(Name,'p5-')].Name" --output text
aws cloudtrail describe-trails --region $R --query "trailList[].Name" --output text
aws sns list-topics --region $R --query "Topics[?contains(TopicArn,'p5')].TopicArn" --output text
aws iam list-roles --query "Roles[?starts_with(RoleName,'p5')].RoleName" --output text
aws s3 ls | grep p5-
