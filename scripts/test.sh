#!/bin/bash
# test.sh - Replay test for scenario 1: sends the sample StopLogging event straight to the
# Lambda, shows its response, then shows whether the trail is logging again.
# Needs the stack deployed. Changes only the lab trail.
# Last updated: 2026-11-15
cd "$(dirname "$0")/.."
R=us-east-1
LAMBDA=p5-remediate-logging
TRAIL=p5-lab-trail
aws lambda invoke --function-name $LAMBDA --region $R --payload fileb://tests/events/stop-logging.json out.json
echo "== Lambda response =="; cat out.json; echo
echo "== IsLogging (expect true) =="
aws cloudtrail get-trail-status --name $TRAIL --region $R --query IsLogging
rm -f out.json
