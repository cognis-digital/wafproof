import { test } from "node:test";
import assert from "node:assert/strict";
import { Rule, Ruleset, Counts, evaluate, Entry } from "./wafproof.js";

function ruleset(): Ruleset {
  return new Ruleset([
    { id: "xss-script", category: "xss", pattern: "<script", caseInsensitive: true },
    { id: "sqli-union", category: "sqli", pattern: "union\\s+select", caseInsensitive: true },
    { id: "pt-dotdot", category: "path-traversal", pattern: "\\.\\./" },
  ]);
}

function corpus(): Entry[] {
  return [
    { id: "m1", category: "xss", label: "malicious", text: "<script>alert(1)</script>" },
    { id: "m2", category: "sqli", label: "malicious", text: "1 UNION SELECT a,b" },
    { id: "m3", category: "path-traversal", label: "malicious", text: "../../etc/passwd" },
    { id: "b1", category: "xss", label: "benign", text: "I scripted a film" },
    { id: "b2", category: "sqli", label: "benign", text: "select a union rep" },
  ];
}

test("rule matches case-insensitively", () => {
  const rs = ruleset();
  assert.equal(rs.rules[0].matches("<SCRIPT>x"), true);
  assert.equal(rs.rules[2].matches("assets/logo.png"), false);
});

test("invalid regex throws", () => {
  assert.throws(() => new Rule({ id: "bad", pattern: "(" }));
});

test("detect fires on any rule", () => {
  const rs = ruleset();
  assert.equal(rs.detect("hello ../../x"), true);
  assert.equal(rs.detect("perfectly benign text"), false);
});

test("evaluate counts", () => {
  const rs = ruleset();
  const c = evaluate((t) => rs.detect(t), corpus());
  assert.equal(c.tp, 3);
  assert.equal(c.fn, 0);
  assert.equal(c.tn, 2);
  assert.equal(c.total, 5);
});

test("metrics perfect", () => {
  const c = new Counts();
  c.tp = 3;
  c.tn = 2;
  assert.ok(Math.abs(c.recall - 1.0) < 1e-9);
  assert.ok(Math.abs(c.precision - 1.0) < 1e-9);
  assert.ok(Math.abs(c.f1 - 1.0) < 1e-9);
  assert.ok(Math.abs(c.falsePositiveRate - 0.0) < 1e-9);
});

test("metrics safe-div on empty", () => {
  const c = new Counts();
  assert.equal(c.recall, 0.0);
  assert.equal(c.precision, 0.0);
  assert.equal(c.f1, 0.0);
});

test("overbroad rule lowers precision", () => {
  const rs = new Ruleset([{ id: "broad", category: "sqli", pattern: "select", caseInsensitive: true }]);
  const c = evaluate((t) => rs.detect(t), corpus());
  assert.ok(c.fp >= 1);
  assert.ok(c.precision < 1.0);
});

test("matching attribution", () => {
  const rs = ruleset();
  const ids = rs.matching("<script>../../x").map((r) => r.id);
  assert.ok(ids.includes("xss-script"));
  assert.ok(ids.includes("pt-dotdot"));
});
