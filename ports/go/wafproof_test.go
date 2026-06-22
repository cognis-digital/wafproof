package wafproof

import (
	"math"
	"testing"
)

func sampleRuleset(t *testing.T) Ruleset {
	rs := Ruleset{
		{ID: "xss-script", Category: "xss", Pattern: "<script", CaseInsensitive: true},
		{ID: "sqli-union", Category: "sqli", Pattern: `union\s+select`, CaseInsensitive: true},
		{ID: "pt-dotdot", Category: "path-traversal", Pattern: `\.\./`},
	}
	if err := rs.Compile(); err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	return rs
}

func sampleCorpus() []Entry {
	return []Entry{
		{ID: "m1", Category: "xss", Label: "malicious", Text: "<script>alert(1)</script>"},
		{ID: "m2", Category: "sqli", Label: "malicious", Text: "1 UNION SELECT a,b"},
		{ID: "m3", Category: "path-traversal", Label: "malicious", Text: "../../etc/passwd"},
		{ID: "b1", Category: "xss", Label: "benign", Text: "I scripted a film"},
		{ID: "b2", Category: "sqli", Label: "benign", Text: "select a union rep"},
	}
}

func TestRuleMatches(t *testing.T) {
	rs := sampleRuleset(t)
	if !rs[0].Matches("<SCRIPT>x") {
		t.Error("case-insensitive script rule should match <SCRIPT>")
	}
	if rs[2].Matches("assets/logo.png") {
		t.Error("path rule should not match a clean path")
	}
}

func TestCompileInvalidRegex(t *testing.T) {
	rs := Ruleset{{ID: "bad", Pattern: "("}}
	if err := rs.Compile(); err == nil {
		t.Error("expected compile error for invalid regex")
	}
}

func TestDetectAny(t *testing.T) {
	rs := sampleRuleset(t)
	if !rs.Detect("hello ../../x") {
		t.Error("detect should fire on traversal")
	}
	if rs.Detect("perfectly benign text") {
		t.Error("detect should not fire on benign text")
	}
}

func TestEvaluateCounts(t *testing.T) {
	rs := sampleRuleset(t)
	c := Evaluate(rs.Detect, sampleCorpus())
	if c.TP != 3 {
		t.Errorf("TP = %d, want 3", c.TP)
	}
	if c.FN != 0 {
		t.Errorf("FN = %d, want 0", c.FN)
	}
	if c.TN != 2 {
		t.Errorf("TN = %d, want 2", c.TN)
	}
	if c.Total() != 5 {
		t.Errorf("total = %d, want 5", c.Total())
	}
}

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestMetrics(t *testing.T) {
	c := Counts{TP: 3, FP: 0, FN: 0, TN: 2}
	if !almost(c.Recall(), 1.0) {
		t.Errorf("recall = %v, want 1.0", c.Recall())
	}
	if !almost(c.Precision(), 1.0) {
		t.Errorf("precision = %v, want 1.0", c.Precision())
	}
	if !almost(c.F1(), 1.0) {
		t.Errorf("f1 = %v, want 1.0", c.F1())
	}
	if !almost(c.FalsePositiveRate(), 0.0) {
		t.Errorf("fpr = %v, want 0.0", c.FalsePositiveRate())
	}
}

func TestMetricsSafeDiv(t *testing.T) {
	var c Counts
	if c.Recall() != 0.0 || c.Precision() != 0.0 || c.F1() != 0.0 {
		t.Error("empty counts should yield 0.0 metrics, not NaN")
	}
}

func TestOverbroadLowersPrecision(t *testing.T) {
	rs := Ruleset{{ID: "broad", Category: "sqli", Pattern: "(?i)select"}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	c := Evaluate(rs.Detect, sampleCorpus())
	// "select" matches malicious m2 and benign b2 -> a false positive
	if c.FP == 0 {
		t.Error("overbroad rule should produce at least one FP")
	}
	if c.Precision() >= 1.0 {
		t.Error("precision should drop below 1.0 with an FP")
	}
}
