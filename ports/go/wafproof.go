// Package wafproof is a Go port of wafproof's CORE check: evaluate a regex
// ruleset against a labeled canary corpus and report detection-quality metrics.
//
// This is a defensive measurement tool. It NEVER sends traffic anywhere; it
// only feeds local labeled strings through a regex ruleset and counts hits.
// "malicious" is the positive class.
package wafproof

import (
	"fmt"
	"regexp"
)

// Rule is a single named regex rule. CaseInsensitive maps to the (?i) flag.
type Rule struct {
	ID              string
	Category        string
	Pattern         string
	CaseInsensitive bool
	re              *regexp.Regexp
}

// Compile compiles the rule's pattern, honoring CaseInsensitive.
func (r *Rule) Compile() error {
	pat := r.Pattern
	if r.CaseInsensitive {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return fmt.Errorf("rule %q has invalid regex: %w", r.ID, err)
	}
	r.re = re
	return nil
}

// Matches reports whether the rule's pattern is found in text.
func (r *Rule) Matches(text string) bool {
	if r.re == nil {
		return false
	}
	return r.re.MatchString(text)
}

// Ruleset is an ordered collection of rules.
type Ruleset []*Rule

// Compile compiles every rule, returning the first error encountered.
func (rs Ruleset) Compile() error {
	for _, r := range rs {
		if err := r.Compile(); err != nil {
			return err
		}
	}
	return nil
}

// Detect reports whether ANY rule matches text.
func (rs Ruleset) Detect(text string) bool {
	for _, r := range rs {
		if r.Matches(text) {
			return true
		}
	}
	return false
}

// Entry is one labeled corpus entry. Label is "malicious" or "benign".
type Entry struct {
	ID       string
	Category string
	Label    string
	Text     string
}

// Counts holds the 2x2 confusion counts. Malicious is the positive class.
type Counts struct {
	TP, FP, FN, TN int
}

// Total returns the number of classified entries.
func (c Counts) Total() int { return c.TP + c.FP + c.FN + c.TN }

func safeDiv(n, d int) float64 {
	if d == 0 {
		return 0.0
	}
	return float64(n) / float64(d)
}

// Recall is TP/(TP+FN): the detection rate.
func (c Counts) Recall() float64 { return safeDiv(c.TP, c.TP+c.FN) }

// Precision is TP/(TP+FP).
func (c Counts) Precision() float64 { return safeDiv(c.TP, c.TP+c.FP) }

// FalsePositiveRate is FP/(FP+TN).
func (c Counts) FalsePositiveRate() float64 { return safeDiv(c.FP, c.FP+c.TN) }

// F1 is the harmonic mean of precision and recall.
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	if p+r == 0 {
		return 0.0
	}
	return 2 * p * r / (p + r)
}

// Evaluate runs a detector over the corpus and tallies the confusion counts.
func Evaluate(detect func(string) bool, corpus []Entry) Counts {
	var c Counts
	for _, e := range corpus {
		flagged := detect(e.Text)
		malicious := e.Label == "malicious"
		switch {
		case malicious && flagged:
			c.TP++
		case malicious && !flagged:
			c.FN++
		case !malicious && flagged:
			c.FP++
		default:
			c.TN++
		}
	}
	return c
}
