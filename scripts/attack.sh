#!/bin/bash
# attack.sh - Scenario 1: stops logging on the lab trail, then watches whether auto-remediation turns it back on.
# Only touches the lab trail p5-lab-trail. Polls every 30s for up to 10 minutes.
# Last updated: 2026-11-15
R=us-east-1
TRAIL=p5-lab-trail
aws cloudtrail stop-logging --name $TRAIL --region $R
echo "Attack sent at $(date -u +%T) UTC"
for i in $(seq 1 20); do
  sleep 30
  S=$(aws cloudtrail get-trail-status --name $TRAIL --region $R --query IsLogging --output text)
  echo "$(date -u +%T) IsLogging=$S"
  [ "$S" = "True" ] && echo "REMEDIATED" && exit 0
done
echo "NOT remediated after 10 minutes"
