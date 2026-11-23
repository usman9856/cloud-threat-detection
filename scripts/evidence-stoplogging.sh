#!/usr/bin/env bash
# Read-only evidence view for the StopLogging scenario. Changes nothing.
export MSYS_NO_PATHCONV=1
REGION="us-east-1"
TRAIL="p5-lab-trail"
RULE="p5-logging-tampered"
FN="p5-remediate-logging"
TOPIC="p5-alerts"
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)

metric() {
  aws cloudwatch get-metric-statistics --region "$REGION" \
    --namespace "$1" --metric-name "$2" --dimensions "Name=$3,Value=$4" \
    --start-time "$START" --end-time "$END" --period 3600 --statistics Sum \
    --query 'sum(Datapoints[].Sum)' --output text
}

echo "=== 1. TRAIL STATE ==="
aws cloudtrail get-trail-status --region "$REGION" --name "$TRAIL" \
  --query '{IsLogging:IsLogging}' --output text

echo
echo "=== 2. CLOUDTRAIL StopLogging RECORDS (latest 5) ==="
aws cloudtrail lookup-events --region "$REGION" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --max-results 5 \
  --query 'Events[].[EventTime,EventId,Username]' --output text

echo
echo "=== 3. RULE AND LAMBDA COUNTERS (last 24h) ==="
echo "Rule matched (TriggeredRules): $(metric AWS/Events TriggeredRules RuleName "$RULE")"
echo "Rule failed (FailedInvocations): $(metric AWS/Events FailedInvocations RuleName "$RULE")"
echo "Lambda invocations:            $(metric AWS/Lambda Invocations FunctionName "$FN")"
echo "Lambda errors:                 $(metric AWS/Lambda Errors FunctionName "$FN")"

echo
echo "=== 4. LAMBDA INCIDENT RECORD (latest) ==="
aws logs filter-log-events --region "$REGION" \
  --log-group-name "/aws/lambda/$FN" \
  --filter-pattern "secondsToDetect" \
  --query 'events[-1].message' --output text

echo
echo "=== 5. CONFIRMED EMAIL SUBSCRIPTIONS ==="
ARN=$(aws sns list-topics --region "$REGION" \
  --query "Topics[?contains(TopicArn,'$TOPIC')].TopicArn | [0]" --output text)
aws sns list-subscriptions-by-topic --region "$REGION" --topic-arn "$ARN" \
  --query "length(Subscriptions[?SubscriptionArn!='PendingConfirmation'])" --output text
