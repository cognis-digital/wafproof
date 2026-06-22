//! Rust port of wafproof's CORE check: evaluate a regex ruleset against a
//! labeled canary corpus and report detection-quality metrics.
//!
//! Defensive measurement only. Nothing here sends traffic anywhere; it feeds
//! local labeled strings through a regex ruleset and counts hits. "malicious"
//! is the positive class.

use regex::{Regex, RegexBuilder};

/// A single named regex rule.
pub struct Rule {
    pub id: String,
    pub category: String,
    re: Regex,
}

impl Rule {
    /// Compile a rule. `case_insensitive` maps to the regex `i` flag.
    pub fn new(
        id: &str,
        category: &str,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Rule, regex::Error> {
        let re = RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .build()?;
        Ok(Rule {
            id: id.to_string(),
            category: category.to_string(),
            re,
        })
    }

    /// Does the rule's pattern occur in `text`?
    pub fn matches(&self, text: &str) -> bool {
        self.re.is_match(text)
    }
}

/// An ordered ruleset. A string is flagged if ANY rule matches.
pub struct Ruleset {
    pub rules: Vec<Rule>,
}

impl Ruleset {
    pub fn new(rules: Vec<Rule>) -> Ruleset {
        Ruleset { rules }
    }

    pub fn detect(&self, text: &str) -> bool {
        self.rules.iter().any(|r| r.matches(text))
    }

    /// Rules that match `text`, for explainability.
    pub fn matching(&self, text: &str) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.matches(text)).collect()
    }
}

/// One labeled corpus entry. `label` is "malicious" or "benign".
pub struct Entry {
    pub id: String,
    pub category: String,
    pub label: String,
    pub text: String,
}

impl Entry {
    pub fn new(id: &str, category: &str, label: &str, text: &str) -> Entry {
        Entry {
            id: id.to_string(),
            category: category.to_string(),
            label: label.to_string(),
            text: text.to_string(),
        }
    }
    pub fn is_malicious(&self) -> bool {
        self.label == "malicious"
    }
}

/// The 2x2 confusion counts. Malicious is the positive class.
#[derive(Default, Debug, Clone, Copy)]
pub struct Counts {
    pub tp: u32,
    pub fp: u32,
    pub fn_: u32,
    pub tn: u32,
}

fn safe_div(n: u32, d: u32) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

impl Counts {
    pub fn total(&self) -> u32 {
        self.tp + self.fp + self.fn_ + self.tn
    }
    pub fn recall(&self) -> f64 {
        safe_div(self.tp, self.tp + self.fn_)
    }
    pub fn precision(&self) -> f64 {
        safe_div(self.tp, self.tp + self.fp)
    }
    pub fn false_positive_rate(&self) -> f64 {
        safe_div(self.fp, self.fp + self.tn)
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

/// Run a detector over a corpus and tally the confusion counts.
pub fn evaluate<F: Fn(&str) -> bool>(detect: F, corpus: &[Entry]) -> Counts {
    let mut c = Counts::default();
    for e in corpus {
        let flagged = detect(&e.text);
        match (e.is_malicious(), flagged) {
            (true, true) => c.tp += 1,
            (true, false) => c.fn_ += 1,
            (false, true) => c.fp += 1,
            (false, false) => c.tn += 1,
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruleset() -> Ruleset {
        Ruleset::new(vec![
            Rule::new("xss-script", "xss", "<script", true).unwrap(),
            Rule::new("sqli-union", "sqli", r"union\s+select", true).unwrap(),
            Rule::new("pt-dotdot", "path-traversal", r"\.\./", false).unwrap(),
        ])
    }

    fn corpus() -> Vec<Entry> {
        vec![
            Entry::new("m1", "xss", "malicious", "<script>alert(1)</script>"),
            Entry::new("m2", "sqli", "malicious", "1 UNION SELECT a,b"),
            Entry::new("m3", "path-traversal", "malicious", "../../etc/passwd"),
            Entry::new("b1", "xss", "benign", "I scripted a film"),
            Entry::new("b2", "sqli", "benign", "select a union rep"),
        ]
    }

    #[test]
    fn rule_matches_case_insensitive() {
        let rs = ruleset();
        assert!(rs.rules[0].matches("<SCRIPT>x"));
        assert!(!rs.rules[2].matches("assets/logo.png"));
    }

    #[test]
    fn invalid_regex_errors() {
        assert!(Rule::new("bad", "x", "(", false).is_err());
    }

    #[test]
    fn detect_any() {
        let rs = ruleset();
        assert!(rs.detect("hello ../../x"));
        assert!(!rs.detect("perfectly benign text"));
    }

    #[test]
    fn evaluate_counts() {
        let rs = ruleset();
        let c = evaluate(|t| rs.detect(t), &corpus());
        assert_eq!(c.tp, 3);
        assert_eq!(c.fn_, 0);
        assert_eq!(c.tn, 2);
        assert_eq!(c.total(), 5);
    }

    #[test]
    fn metrics_perfect() {
        let c = Counts { tp: 3, fp: 0, fn_: 0, tn: 2 };
        assert!((c.recall() - 1.0).abs() < 1e-9);
        assert!((c.precision() - 1.0).abs() < 1e-9);
        assert!((c.f1() - 1.0).abs() < 1e-9);
        assert!(c.false_positive_rate().abs() < 1e-9);
    }

    #[test]
    fn metrics_safe_div() {
        let c = Counts::default();
        assert_eq!(c.recall(), 0.0);
        assert_eq!(c.precision(), 0.0);
        assert_eq!(c.f1(), 0.0);
    }

    #[test]
    fn overbroad_lowers_precision() {
        let rs = Ruleset::new(vec![Rule::new("broad", "sqli", "select", true).unwrap()]);
        let c = evaluate(|t| rs.detect(t), &corpus());
        assert!(c.fp >= 1);
        assert!(c.precision() < 1.0);
    }

    #[test]
    fn matching_attribution() {
        let rs = ruleset();
        let hits = rs.matching("<script>../../x");
        let ids: Vec<&str> = hits.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"xss-script"));
        assert!(ids.contains(&"pt-dotdot"));
    }
}
