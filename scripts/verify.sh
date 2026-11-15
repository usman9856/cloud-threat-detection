#!/bin/bash
# verify.sh - Shows each stage of the P5 scenario 1 chain: logging state, EventBridge rule counters,
# Lambda invocations, Lambda log lines, and SNS subscription status. Read-only, changes nothing.
# Last updated: 2026-11-15
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
R=us-east-1
LAMBDA=p5-remediate-logging
TRAIL=p5-lab-trail
RULE=p5-logging-tampered
START=$(date -u -d '2 hours ago' +%FT%TZ)
END=$(date -u +%FT%TZ)
metric() { aws cloudwatch get-metric-statistics --namespace "$1" --metric-name "$2" --dimensions Name="$3",Value="$4" \
  --start-time $START --end-time $END --period 7200 --statistics Sum --region $R --query "Datapoints[].Sum" --output text; }

echo "== Now (UTC) =="; date -u
echo "== 1. Trail logging now (True = on / remediated) =="
aws cloudtrail get-trail-status --name $TRAIL --region $R --query IsLogging --output text
echo "== 2. StopLogging events recorded by CloudTrail (last 2h) =="
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --region $R \
  --start-time $START --query "Events[].EventTime" --output text
echo "== 3. Rule matched (TriggeredRules; blank = none) =="; metric AWS/Events TriggeredRules RuleName $RULE
echo "== 4. Rule failed to invoke target (FailedInvocations; blank = none) =="; metric AWS/Events FailedInvocations RuleName $RULE
echo "== 5. Lambda invocations (blank = none) =="; metric AWS/Lambda Invocations FunctionName $LAMBDA
echo "== 6. Lambda log (last 20 lines) =="
aws logs tail /aws/lambda/$LAMBDA --since 2h --region $R 2>&1 | tail -20
echo "== 7. SNS subscriptions =="
TOPIC=$(aws sns list-topics --region $R --query "Topics[?contains(TopicArn,'p5')].TopicArn" --output text)
echo "$TOPIC"
[ -n "$TOPIC" ] && aws sns list-subscriptions-by-topic --topic-arn $TOPIC --region $R --query "Subscriptions[].[Protocol,SubscriptionArn]" --output text
