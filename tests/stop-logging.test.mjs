import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mockClient } from "aws-sdk-client-mock";
import { CloudTrailClient, GetTrailStatusCommand, StartLoggingCommand } from "@aws-sdk/client-cloudtrail";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import { handler, trailNameFrom } from "../lambda/stop-logging/index.mjs";

const base = JSON.parse(readFileSync(new URL("./events/stop-logging.json", import.meta.url), "utf8"));
const ct = mockClient(CloudTrailClient);
const sns = mockClient(SNSClient);

const withDetail = (patch) => ({ ...base, detail: { ...base.detail, ...patch } });

beforeEach(() => {
  ct.reset();
  sns.reset();
  sns.on(PublishCommand).resolves({});
  process.env.SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:p5-alerts";
  process.env.LAB_TRAIL_NAME = "p5-lab-trail";
  process.env.SCOPE_PREFIXES = "stratus-red-team-";
  process.env.REMEDIATE = "true";
});

test("StopLogging on lab trail: restarts logging and alerts", async () => {
  ct.on(GetTrailStatusCommand).resolves({ IsLogging: false });
  ct.on(StartLoggingCommand).resolves({});
  const out = await handler(base);
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 1);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
  assert.equal(out.action, "StartLogging called");
});

test("idempotent: already logging means no StartLogging, still alerts", async () => {
  ct.on(GetTrailStatusCommand).resolves({ IsLogging: true });
  const out = await handler(base);
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 0);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
  assert.match(out.action, /already logging/);
});

test("Stratus-prefixed trail is in scope", async () => {
  ct.on(GetTrailStatusCommand).resolves({ IsLogging: false });
  ct.on(StartLoggingCommand).resolves({});
  await handler(withDetail({ requestParameters: { name: "stratus-red-team-ctstop-abc" } }));
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 1);
});

test("out-of-scope trail: alert only, never touched", async () => {
  const out = await handler(withDetail({ requestParameters: { name: "someone-elses-trail" } }));
  assert.equal(ct.commandCalls(GetTrailStatusCommand).length, 0);
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 0);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
  assert.match(out.action, /out of lab scope/);
});

test("DeleteTrail: alert only", async () => {
  const out = await handler(withDetail({ eventName: "DeleteTrail" }));
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 0);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
  assert.match(out.action, /alert only/);
});

test("rejected call (errorCode): no remediation, still alerts", async () => {
  const out = await handler(withDetail({ errorCode: "AccessDenied" }));
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 0);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
  assert.match(out.action, /rejected/);
});

test("REMEDIATE=false: alert only", async () => {
  process.env.REMEDIATE = "false";
  const out = await handler(base);
  assert.equal(ct.commandCalls(StartLoggingCommand).length, 0);
  assert.match(out.action, /REMEDIATE=false/);
});

test("remediation failure is reported, alert still sent", async () => {
  ct.on(GetTrailStatusCommand).resolves({ IsLogging: false });
  ct.on(StartLoggingCommand).rejects(Object.assign(new Error("denied"), { name: "AccessDeniedException" }));
  const out = await handler(base);
  assert.match(out.action, /remediation FAILED/);
  assert.equal(sns.commandCalls(PublishCommand).length, 1);
});

test("trailNameFrom handles names and ARNs", () => {
  assert.equal(trailNameFrom("p5-lab-trail"), "p5-lab-trail");
  assert.equal(trailNameFrom("arn:aws:cloudtrail:us-east-1:123456789012:trail/p5-lab-trail"), "p5-lab-trail");
  assert.equal(trailNameFrom(undefined), null);
});
