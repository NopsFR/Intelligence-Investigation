import { entropy } from "@/lib/analysis/bytes";

// Secret detection over source text: known credential formats by regex, plus
// a generic high-entropy assignment heuristic. Findings show a redacted
// preview only — never the full secret — and mark whether the format itself
// carries checksum/structure confidence or is a heuristic guess.

export interface SecretRule {
  id: string;
  label: string;
  pattern: RegExp;
  confidence: "high" | "medium";
}

export const SECRET_RULES: SecretRule[] = [
  { id: "aws-access-key", label: "AWS access key ID", pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g, confidence: "high" },
  { id: "aws-secret-key", label: "AWS secret access key (near aws_secret)", pattern: /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, confidence: "high" },
  { id: "gcp-api-key", label: "Google API key", pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, confidence: "high" },
  { id: "gcp-service-account", label: "GCP service account private key", pattern: /"type":\s*"service_account"/g, confidence: "high" },
  { id: "azure-connection-string", label: "Azure storage connection string", pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{20,})/gi, confidence: "high" },
  { id: "github-pat", label: "GitHub personal access token", pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, confidence: "high" },
  { id: "github-fine-grained", label: "GitHub fine-grained token", pattern: /\b(github_pat_[A-Za-z0-9_]{22,255})\b/g, confidence: "high" },
  { id: "gitlab-pat", label: "GitLab personal access token", pattern: /\b(glpat-[A-Za-z0-9_\-]{20})\b/g, confidence: "high" },
  { id: "slack-token", label: "Slack token", pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b/g, confidence: "high" },
  { id: "slack-webhook", label: "Slack webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g, confidence: "high" },
  { id: "discord-webhook", label: "Discord webhook URL", pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, confidence: "high" },
  { id: "stripe-key", label: "Stripe API key", pattern: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b/g, confidence: "high" },
  { id: "sendgrid-key", label: "SendGrid API key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, confidence: "high" },
  { id: "twilio-key", label: "Twilio API key", pattern: /\bSK[0-9a-fA-F]{32}\b/g, confidence: "medium" },
  { id: "npm-token", label: "npm access token", pattern: /\b(npm_[A-Za-z0-9]{36})\b/g, confidence: "high" },
  { id: "pypi-token", label: "PyPI API token", pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g, confidence: "high" },
  { id: "openai-key", label: "OpenAI API key", pattern: /\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,})\b/g, confidence: "high" },
  { id: "anthropic-key", label: "Anthropic API key", pattern: /\b(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,110})\b/g, confidence: "high" },
  { id: "jwt", label: "JSON Web Token", pattern: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b/g, confidence: "medium" },
  { id: "private-key", label: "Private key block", pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, confidence: "high" },
  { id: "generic-basic-auth-url", label: "Credentials embedded in a URL", pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/"'@]+:[^\s/"'@]+@[^\s"'/]+/gi, confidence: "medium" },
  { id: "slack-app-token", label: "Slack app-level token", pattern: /\b(xapp-[0-9]-[A-Za-z0-9-]{10,})\b/g, confidence: "high" },
  { id: "heroku-key", label: "Heroku API key", pattern: /\bheroku[a-z_]*\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi, confidence: "medium" },
  { id: "database-url", label: "Database connection string with embedded credentials", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/"'@]+:[^\s/"'@]+@[^\s"']+/gi, confidence: "medium" },
];

const GENERIC_ASSIGNMENT = /\b((?:[a-z_]*(?:secret|token|passwd|password|apikey|api_key|access_key|auth)[a-z_]*))\s*[:=]\s*["']([A-Za-z0-9_\-+/=]{16,100})["']/gi;

const PLACEHOLDER = /^(x{4,}|0{4,}|1{4,}|test|demo|example|changeme|your[_-]?(api[_-]?)?key|placeholder|fixme|todo|dummy|sample|redacted|secret|password|<[^>]+>|\$\{[^}]+\}|%[a-z_]+%)$/i;

export interface SecretMatch {
  ruleId: string;
  label: string;
  confidence: "high" | "medium" | "low";
  line: number;
  column: number;
  redacted: string;
  entropy?: number;
}

/** Placeholder-shaped suffixes like AKIAXXXXXXXXXXXXXXXX (a real prefix, a fake repeated body). */
function looksLikePlaceholder(value: string): boolean {
  if (PLACEHOLDER.test(value)) return true;
  const body = value.length > 6 ? value.slice(4) : value;
  return /^(.)\1{3,}$/.test(body);
}

function redact(value: string): string {
  if (value.length <= 8) return `${value[0]}${"•".repeat(Math.max(3, value.length - 1))}`;
  return `${value.slice(0, 4)}${"•".repeat(Math.min(20, value.length - 8))}${value.slice(-4)}`;
}

function lineOf(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let last = -1;
  for (let i = 0; i < index; i++) if (text[i] === "\n") {
    line++;
    last = i;
  }
  return { line, column: index - last };
}

/** Scan text for known secret formats and generically high-entropy assignments. */
export function scanSecrets(text: string, maxBytes = 4 * 1024 * 1024): SecretMatch[] {
  const clipped = text.length > maxBytes ? text.slice(0, maxBytes) : text;
  const out: SecretMatch[] = [];
  const covered: [number, number][] = [];

  for (const rule of SECRET_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`);
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(clipped)) !== null && guard++ < 10_000) {
      const value = m[1] ?? m[0];
      if (looksLikePlaceholder(value)) continue;
      const { line, column } = lineOf(clipped, m.index);
      out.push({ ruleId: rule.id, label: rule.label, confidence: rule.confidence, line, column, redacted: redact(value) });
      covered.push([m.index, m.index + m[0].length]);
      if (m[0].length === 0) re.lastIndex++;
    }
  }

  let m: RegExpExecArray | null;
  const ga = new RegExp(GENERIC_ASSIGNMENT.source, GENERIC_ASSIGNMENT.flags);
  let guard = 0;
  while ((m = ga.exec(clipped)) !== null && guard++ < 5000) {
    const value = m[2];
    if (PLACEHOLDER.test(value) || /^[a-z_-]+$/i.test(value)) continue;
    if (covered.some(([a, b]) => m!.index >= a && m!.index < b)) continue;
    const h = entropy(new TextEncoder().encode(value));
    if (h < 3.3) continue;
    const { line, column } = lineOf(clipped, m.index + m[0].indexOf(value));
    out.push({ ruleId: "generic-high-entropy", label: `High-entropy value assigned to '${m[1]}'`, confidence: "low", line, column, redacted: redact(value), entropy: h });
  }
  return out.sort((a, b) => a.line - b.line || a.column - b.column);
}

export const SECRET_ALLOWLIST_HINT = "Lines containing 'test', 'example', 'placeholder' or similar are already skipped as likely non-secrets, but review every finding — the check errs toward flagging.";
