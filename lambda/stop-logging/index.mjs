// Scenario 1: logging tampered (MITRE T1562.008).
//   StopLogging -> restart logging if the trail is in lab scope, always alert.
//   DeleteTrail -> alert only (StartLogging cannot undo a delete).
// AWS SDK v3 ships with the Node.js Lambda runtime, so nothing is bundled.
import { CloudTrailClient, GetTrailStatusCommand, StartLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const cloudtrail = new CloudTrailClient({});
const sns = new SNSClient({});

// Event may carry a trail name or a full ARN.
export function trailNameFrom(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.startsWith("arn:") ? value.split("trail/").pop() : value;
}

export function inScope(name, env = process.env) {
  if (!name) return false;
  if (name === env.LAB_TRAIL_NAME) return true;
  const prefixes = (env.SCOPE_PREFIXES ?? "").split(",").map((p) => p.trim()).filter(Boolean);
  return prefixes.some((p) => name.startsWith(p));
}

export async function handler(event) {
  const d = event?.detail ?? {};
  const eventName = d.eventName;
  const trail = trailNameFrom(d.requestParameters?.name);
  const who = d.userIdentity?.arn ?? d.userIdentity?.type ?? "unknown";
  const scoped = inScope(trail);
  const canFix = process.env.REMEDIATE !== "false";

  let action;
  if (d.errorCode) {
    action = `none (call was rejected: ${d.errorCode})`;
  } else if (eventName !== "StopLogging") {
    action = "none (alert only by design)";
  } else if (!scoped) {
    action = "none (trail out of lab scope)";
  } else if (!canFix) {
    action = "none (REMEDIATE=false)";
  } else {
    try {
      const status = await cloudtrail.send(new GetTrailStatusCommand({ Name: trail }));
      if (status.IsLogging) {
        action = "none (already logging)";
      } else {
        await cloudtrail.send(new StartLoggingCommand({ Name: trail }));
        action = "StartLogging called";
      }
    } catch (err) {
      action = `remediation FAILED: ${err.name}`;
      console.error(JSON.stringify({ msg: "remediation failed", trail, error: err.message }));
    }
  }

  const summary = {
    eventName,
    trail,
    principal: who,
    sourceIp: d.sourceIPAddress,
    eventTime: d.eventTime,
    eventId: d.eventID,
    action,
  };
  console.log(JSON.stringify({ msg: "detection", ...summary }));

  await sns.send(
    new PublishCommand({
      TopicArn: process.env.SNS_TOPIC_ARN,
      Subject: `P5 ALERT: ${eventName} on ${trail ?? "unknown trail"}`.slice(0, 100),
      Message: JSON.stringify(summary, null, 2),
    })
  );

  return summary;
}
