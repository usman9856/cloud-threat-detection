#!/bin/bash
# logs-stoplogging.sh - Prints the Lambda's CloudWatch logs readably: one run at a time, JSON fields on
# separate lines, coloured level markers and severity. Nothing is summarised or removed.
# Usage: ./scripts/logs-stoplogging.sh [hours] [app]
#   hours = how far back to look (default 2)
#   app   = show only our own INFO/WARN/ERROR lines (hide START/END/REPORT bookkeeping)
# Read-only. Timestamps are UTC.
# Last updated: 2026-11-15 (severity + boolean colouring for the structured detection format)
export MSYS_NO_PATHCONV=1
R=us-east-1
LAMBDA=p5-remediate-logging
HOURS=${1:-2}
MODE=${2:-all}
START_MS=$(( $(date -u -d "$HOURS hours ago" +%s) * 1000 ))
aws logs filter-log-events --log-group-name /aws/lambda/$LAMBDA --region $R --start-time $START_MS \
  --query "events[].[timestamp,message]" --output json | HOURS=$HOURS MODE=$MODE node -e '
const C = {r:"\x1b[0m", dim:"\x1b[90m", red:"\x1b[31m", green:"\x1b[32m", yellow:"\x1b[33m", blue:"\x1b[34m", cyan:"\x1b[36m", bold:"\x1b[1m"};
const sevCol = {CRITICAL: C.red, HIGH: C.red, MEDIUM: C.yellow, LOW: C.green};
const appOnly = process.env.MODE === "app";
const pad = "        ";
let d = "";
process.stdin.on("data", c => d += c).on("end", () => {
  const ev = JSON.parse(d || "[]").sort((a, b) => a[0] - b[0]);
  if (!ev.length) { console.log("No log events in the last " + process.env.HOURS + " hour(s)."); return; }
  const paint = l => {
    let s = l.replace(/^(\s*)("[^"]+")(:)/, "$1" + C.cyan + "$2" + C.r + "$3");
    s = s.replace(/("severity": )"(\w+)"/, (m, a, v) => a + (sevCol[v] || "") + C.bold + "\"" + v + "\"" + C.r);
    s = s.replace(/(: )(true|false)(,?)$/, (m, a, v, c) => a + (v === "true" ? C.green : C.red) + v + C.r + c);
    return pad + s;
  };
  let prev = "";
  for (const [ts, raw] of ev) {
    const msg = raw.replace(/\n$/, "");
    const time = new Date(ts).toISOString().replace("T", " ").slice(0, 23) + "Z";
    const parts = msg.split("\t");
    const lvl = parts[2];
    if (["INFO", "WARN", "ERROR", "DEBUG"].includes(lvl)) {
      const col = lvl === "ERROR" ? C.red : lvl === "WARN" ? C.yellow : C.green;
      const body = parts.slice(3).join("\t");
      let obj = null;
      try { obj = JSON.parse(body); } catch (e) {}
      const sev = obj && obj.severity ? " " + (sevCol[obj.severity] || C.dim) + C.bold + "[" + obj.severity + "]" + C.r : "";
      console.log(C.dim + time + C.r + " " + col + C.bold + lvl + C.r + sev + C.dim + "  request " + parts[1] + C.r);
      console.log(obj ? JSON.stringify(obj, null, 2).split("\n").map(paint).join("\n") : pad + body);
      prev = lvl;
      continue;
    }
    if (appOnly) continue;
    const word = msg.split(" ")[0];
    if (word === "INIT_START" || (word === "START" && prev !== "INIT_START")) {
      console.log("\n" + C.dim + "-".repeat(78) + C.r);
    }
    const col = (word === "START" || word === "END") ? C.blue : C.dim;
    const segs = msg.slice(word.length).trim().split("\t");
    console.log(C.dim + time + C.r + " " + col + C.bold + word + C.r + " " + segs[0]);
    for (const s of segs.slice(1)) console.log(C.dim + pad + s + C.r);
    prev = word;
  }
  console.log("\n" + ev.length + " log events, last " + process.env.HOURS + " hour(s).");
});'
