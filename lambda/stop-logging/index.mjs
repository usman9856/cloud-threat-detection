// Scenario 1: logging tampered (MITRE T1562.008).
//   StopLogging -> restart logging if the trail is in lab scope, always alert.
//   DeleteTrail -> alert only (StartLogging cannot undo a delete).
// Logs one structured incident record: what, where, who, how fast, what we did, what to do next.
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

// What each attack means and what a person should do about it.
const CATALOG = {
  StopLogging: {
    severity: "HIGH",
    service: "AWS CloudTrail",
    attack: "Audit logging disabled (StopLogging)",
    mitre: "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
    why: "With logging off, later actions in the account go unrecorded. Attackers do this first to hide what comes next.",
    nextSteps: [
      "Confirm the principal and source IP are expected (your own admin user and address)",
      "If unexpected: deactivate the access key shown in actor.accessKey, then review everything this principal did in CloudTrail event history",
      "Check whether other security settings were changed in the same window",
      "Remove cloudtrail:StopLogging from identities that do not need it",
    ],
  },
  DeleteTrail: {
    severity: "CRITICAL",
    service: "AWS CloudTrail",
    attack: "Audit trail deleted (DeleteTrail)",
    mitre: "T1562.008 Impair Defenses: Disable or Modify Cloud Logs",
    why: "The trail is gone, so nothing is being recorded and the system cannot undo this by itself.",
    nextSteps: [
      "Recreate the trail now (terraform apply), because nothing is being recorded",
      "Confirm the principal and source IP are expected",
      "If unexpected: deactivate the access key shown in actor.accessKey and review this principal's activity",
      "Restrict cloudtrail:DeleteTrail to a break-glass role",
    ],
  },
};

function fallback(eventName) {
  return {
    severity: "MEDIUM",
    service: "unknown",
    attack: `Unrecognised event (${eventName ?? "none"})`,
    mitre: "unmapped",
    why: "No catalog entry for this event.",
    nextSteps: ["Review the raw event in CloudTrail using the eventId"],
  };
}

function maskKey(id) {
  if (!id) return null;
  return id.length > 8 ? `${id.slice(0, 4)}...${id.slice(-4)}` : id;
}

async function isLogging(trail) {
  try {
    const s = await cloudtrail.send(new GetTrailStatusCommand({ Name: trail }));
    return s.IsLogging === true;
  } catch {
    return null;
  }
}

export async function handler(event) {
  const d = event?.detail ?? {};
  const eventName = d.eventName;
  const trail = trailNameFrom(d.requestParameters?.name);
  const who = d.userIdentity?.arn ?? d.userIdentity?.type ?? "unknown";
  const scoped = inScope(trail);
  const canFix = process.env.REMEDIATE !== "false";

  let action;
  let loggingBefore = null;
  let loggingAfter = null;
  let failed = false;

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
      loggingBefore = status.IsLogging === true;
      if (loggingBefore) {
        action = "none (already logging)";
        loggingAfter = true;
      } else {
        await cloudtrail.send(new StartLoggingCommand({ Name: trail }));
        action = "StartLogging called";
        loggingAfter = await isLogging(trail);
      }
    } catch (err) {
      failed = true;
      action = `remediation FAILED: ${err.name}`;
      console.error(JSON.stringify({ msg: "remediation failed", trail, error: err.message }));
    }
  }

  const detectedAt = new Date();
  const attackAt = d.eventTime ? new Date(d.eventTime) : null;
  const secondsToDetect =
    attackAt && !Number.isNaN(attackAt.getTime()) ? Math.round((detectedAt - attackAt) / 1000) : null;

  const info = CATALOG[eventName] ?? fallback(eventName);
  const severity = failed ? "CRITICAL" : info.severity;

  const incident = {
    severity,
    service: info.service,
    target: trail,
    attack: info.attack,
    mitre: info.mitre,
    why: info.why,
    actor: {
      principal: who,
      sourceIp: d.sourceIPAddress,
      accessKey: maskKey(d.userIdentity?.accessKeyId),
      userAgent: d.userAgent,
    },
    when: { attack: d.eventTime, detected: detectedAt.toISOString(), secondsToDetect },
    response: { action, loggingBefore, loggingAfter },
    nextSteps: info.nextSteps,
    eventId: d.eventID,
  };

  let alertSent = false;
  let alertError;
  try {
    await sns.send(
      new PublishCommand({
        TopicArn: process.env.SNS_TOPIC_ARN,
        Subject: `P5 Attack Detected [${severity}]: ${eventName} on ${trail ?? "unknown trail"}`.slice(0, 100),
        Message: formatAlert(incident),
      })
    );
    alertSent = true;
  } catch (err) {
    alertError = err;
    console.error(JSON.stringify({ msg: "alert failed", error: err.message }));
  }

  console.log(
    JSON.stringify({ msg: "detection", ...incident, response: { ...incident.response, alertSent } })
  );

  if (alertError) throw alertError;

  return {
    eventName,
    trail,
    principal: who,
    sourceIp: d.sourceIPAddress,
    eventTime: d.eventTime,
    eventId: d.eventID,
    action,
  };
}

// Plain-text version of the incident record, used for the alert email only.
function formatAlert(i) {
  const tool = (i.actor.userAgent ?? "unknown").split(" ")[0];
  const state = (v) => (v === true ? "on" : v === false ? "off" : "unknown");
  const secs = i.when.secondsToDetect === null ? "" : `  (${i.when.secondsToDetect}s later)`;
  const steps = i.nextSteps.map((s, n) => `  ${n + 1}. ${s}`).join("\n");
  return [
    "P5 ATTACK DETECTED",
    `Threat level:     [${i.severity}]`,
    `Threat activity:  ${i.attack}`,
    `Service:          ${i.service}`,
    `Target:           ${i.target ?? "unknown"}`,
    `MITRE:            ${i.mitre}`,
    "",
    "ATTACK SOURCE (identified from the CloudTrail record)",
    `  Principal:   ${i.actor.principal}`,
    `  Source IP:   ${i.actor.sourceIp ?? "unknown"}`,
    `  Access key:  ${i.actor.accessKey ?? "n/a"}`,
    `  Tool:        ${tool}`,
    "",
    "TIMELINE",
    `  Attack:      ${i.when.attack ?? "unknown"}`,
    `  Detected:    ${i.when.detected.slice(0, 19)}Z${secs}`,
    "",
    "AUTOMATED COUNTERMEASURES (completed by the system)",
    "  1. Threat detected:   EventBridge rule matched the CloudTrail event",
    "  2. Defense triggered: Lambda p5-remediate-logging ran",
    `  3. Action taken:      ${i.response.action}`,
    `  4. Result:            logging ${state(i.response.loggingBefore)} -> ${state(i.response.loggingAfter)}`,
    "  5. Alert issued:      this email",
    "",
    "INCIDENT REVIEW (recommended follow-up)",
    steps,
    "",
    "RECORD YOUR REVIEW (sends a follow-up email):",
    `  ./scripts/log-action.sh ${i.eventId} "what you checked and did"`,
    "",
    `Event ID: ${i.eventId}`,
  ].join("\n");
}
