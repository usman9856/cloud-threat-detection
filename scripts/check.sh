#!/bin/bash
# check.sh - Is the P5 stack deployed? Shows Lambda, trail, rule and current UTC time.
# Safe: read-only, changes nothing.
# Last updated: 2026-11-15
cd "$(dirname "$0")/.."
R=us-east-1
LAMBDA=p5-remediate-logging
echo "== Lambda ==";  aws lambda get-function --function-name $LAMBDA --region $R --query Configuration.FunctionName
echo "== Trail ==";   aws cloudtrail describe-trails --region $R --query "trailList[].Name"
echo "== Rules ==";   aws events list-rules --region $R --query "Rules[].Name"
echo "== Time (UTC) =="; date -u
