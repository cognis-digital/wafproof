/**
 * TypeScript port of wafproof's CORE check: evaluate a regex ruleset against a
 * labeled canary corpus and report detection-quality metrics.
 *
 * Defensive measurement only. Nothing here sends traffic anywhere; it feeds
 * local labeled strings through a regex ruleset and counts hits. "malicious" is
 * the positive class.
 */

export interface RuleSpec {
  id: string;
  category?: string;
  pattern: string;
  /** maps to the JS regex 'i' flag */
  caseInsensitive?: boolean;
}

export class Rule {
  readonly id: string;
  readonly category: string;
  readonly pattern: string;
  private readonly re: RegExp;

  constructor(spec: RuleSpec) {
    this.id = spec.id;
    this.category = spec.category ?? "uncategorized";
    this.pattern = spec.pattern;
    const flags = spec.caseInsensitive ? "i" : "";
    try {
      this.re = new RegExp(spec.pattern, flags);
    } catch (e) {
      throw new Error(`rule ${this.id} has invalid regex: ${(e as Error).message}`);
    }
  }

  matches(text: string): boolean {
    return this.re.test(text);
  }
}

export class Ruleset {
  readonly rules: Rule[];

  constructor(specs: RuleSpec[]) {
    this.rules = specs.map((s) => new Rule(s));
  }

  /** flagged if ANY rule matches */
  detect(text: string): boolean {
    return this.rules.some((r) => r.matches(text));
  }

  /** rules that match, for explainability */
  matching(text: string): Rule[] {
    return this.rules.filter((r) => r.matches(text));
  }
}

export interface Entry {
  id: string;
  category: string;
  label: "malicious" | "benign";
  text: string;
}

export class Counts {
  tp = 0;
  fp = 0;
  fn = 0;
  tn = 0;

  get total(): number {
    return this.tp + this.fp + this.fn + this.tn;
  }

  private static safeDiv(n: number, d: number): number {
    return d === 0 ? 0.0 : n / d;
  }

  get recall(): number {
    return Counts.safeDiv(this.tp, this.tp + this.fn);
  }
  get precision(): number {
    return Counts.safeDiv(this.tp, this.tp + this.fp);
  }
  get falsePositiveRate(): number {
    return Counts.safeDiv(this.fp, this.fp + this.tn);
  }
  get f1(): number {
    const p = this.precision;
    const r = this.recall;
    return p + r === 0 ? 0.0 : (2 * p * r) / (p + r);
  }
}

export type Detector = (text: string) => boolean;

/** Run a detector over a corpus and tally the confusion counts. */
export function evaluate(detect: Detector, corpus: Entry[]): Counts {
  const c = new Counts();
  for (const e of corpus) {
    const flagged = detect(e.text);
    const malicious = e.label === "malicious";
    if (malicious && flagged) c.tp++;
    else if (malicious && !flagged) c.fn++;
    else if (!malicious && flagged) c.fp++;
    else c.tn++;
  }
  return c;
}
