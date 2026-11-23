#!/bin/bash
# log-action.sh - Records a manual follow-up for an alert and emails a follow-up.
# Usage: ./scripts/log-action.sh <eventId> "what you checked and did"
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
[ $# -ge 2 ] || { echo 'Usage: ./scripts/log-action.sh <eventId> "what you did"'; exit 1; }
EVENT="$1"; shift; NOTE="$*"
WHO=$(aws sts get-caller-identity --query Arn --output text)
NOW=$(date -u +%FT%TZ)
TOPIC=$(terraform -chdir=terraform output -raw alert_topic_arn)
mkdir -p evidence
printf '%s | event %s | %s | %s\n' "$NOW" "$EVENT" "$WHO" "$NOTE" >> evidence/manual-actions.log
MSG=$(printf 'P5 REVIEW LOGGED\n\nEvent ID:   %s\nLogged by:  %s\nLogged at:  %s\n\nWhat was done:\n  %s\n' "$EVENT" "$WHO" "$NOW" "$NOTE")
aws sns publish --topic-arn "$TOPIC" --region us-east-1 --subject "P5 Review Logged: ${EVENT:0:8}" --message "$MSG" --query MessageId --output text
echo "Logged to evidence/manual-actions.log and follow-up email sent."
