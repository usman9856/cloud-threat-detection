#!/bin/bash
# attack-stoplogging.sh - Scenario 1 attack: stops logging on the lab trail, then measures how long
# the automatic fix takes. Only touches p5-lab-trail. Polls every 3s for up to 2 minutes.
export MSYS_NO_PATHCONV=1
R=us-east-1
TRAIL=p5-lab-trail
status() { aws cloudtrail get-trail-status --name $TRAIL --region $R --query IsLogging --output text; }
echo "Before: IsLogging=$(status)"
START=$(date +%s)
echo "$(date -u +%T) UTC  ATTACK: StopLogging on $TRAIL"
aws cloudtrail stop-logging --name $TRAIL --region $R
for i in $(seq 1 40); do
  sleep 3
  S=$(status)
  echo "$(date -u +%T) UTC  IsLogging=$S"
  if [ "$S" = "True" ]; then
    echo "REMEDIATED about $(( $(date +%s) - START ))s after the attack"
    exit 0
  fi
done
echo "NOT remediated after 2 minutes"
