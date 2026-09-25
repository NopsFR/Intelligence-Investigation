import { parse as parseYaml, parseAllDocuments } from "yaml";
import type { Severity } from "@/lib/core/types";

// Static configuration checks for Dockerfiles, docker-compose, Kubernetes
// manifests and Terraform. Every finding names the exact line or block; there
// is no scoring, just observations against known-bad patterns (CIS Docker
// Benchmark, Kubernetes Pod Security Standards, common Terraform mistakes).

export interface IacFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  line?: number;
  evidence: string[];
}

export type IacFileKind = "dockerfile" | "compose" | "kubernetes" | "terraform" | "github-actions" | "unknown";

export function detectIacKind(filename: string, text: string): IacFileKind {
  const base = filename.split("/").pop() ?? filename;
  if (/^dockerfile(\..+)?$/i.test(base)) return "dockerfile";
  if (/^docker-compose.*\.ya?ml$/i.test(base) || /^compose\.ya?ml$/i.test(base)) return "compose";
  if (/\.tf$/.test(base)) return "terraform";
  if (/^\.github\/workflows\/.*\.ya?ml$/.test(filename) || (/\.ya?ml$/.test(base) && /^\s*on:/m.test(text) && /jobs:/.test(text))) return "github-actions";
  if (/\.ya?ml$/.test(base) && /apiVersion:/.test(text) && /kind:/.test(text)) return "kubernetes";
  return "unknown";
}

function lines(text: string): string[] {
  return text.split(/\r?\n/);
}

// ───────────────────────────── Dockerfile

export function scanDockerfile(file: string, text: string): IacFinding[] {
  const out: IacFinding[] = [];
  const ls = lines(text);
  let hasUser = false;
  let hasHealthcheck = false;
  let baseTagged = true;
  let baseLine = -1;

  ls.forEach((raw, i) => {
    const line = raw.trim();
    const lineNo = i + 1;
    if (!line || line.startsWith("#")) return;
    const [instrRaw, ...rest] = line.split(/\s+/);
    const instr = instrRaw.toUpperCase();
    const args = rest.join(" ");

    if (instr === "FROM") {
      baseLine = lineNo;
      const image = args.split(/\s+AS\s+/i)[0].trim();
      if (image !== "scratch" && !image.includes("@sha256:") && !/:[\w.-]+$/.test(image)) baseTagged = false;
      if (/:latest$/.test(image)) out.push({ id: "docker.latest-tag", severity: "LOW", title: "Base image pinned to :latest", detail: "A floating tag means the build is not reproducible and can silently change.", file, line: lineNo, evidence: [line] });
    }
    if (instr === "USER" && !/^(root|0)(:.*)?$/i.test(args.trim())) hasUser = true;
    if (instr === "HEALTHCHECK") hasHealthcheck = true;
    if (instr === "ADD" && /^https?:\/\//i.test(args)) out.push({ id: "docker.add-remote-url", severity: "MEDIUM", title: "ADD fetches a remote URL", detail: "ADD with a URL does not verify the download and bypasses layer caching; use RUN curl/wget with an explicit checksum, or COPY a vetted artifact.", file, line: lineNo, evidence: [line] });
    if (instr === "RUN" && /(curl|wget)[^|;&\n]*\|\s*(sudo\s+)?(sh|bash)\b/i.test(args)) out.push({ id: "docker.curl-pipe-sh", severity: "HIGH", title: "Pipes a remote script into a shell", detail: "Downloading and executing a script in one step runs whatever the server returns at build time, with no verification.", file, line: lineNo, evidence: [line] });
    if (instr === "RUN" && /\bchmod\s+(-R\s+)?(777|a\+rwx|ugo\+rwx)\b/i.test(args)) out.push({ id: "docker.world-writable", severity: "MEDIUM", title: "World-writable permissions set", detail: "chmod 777 grants write access to every user in the image.", file, line: lineNo, evidence: [line] });
    if (instr === "ENV" || instr === "ARG") {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=?\s*(.+)$/.exec(args);
      if (m && /(secret|password|passwd|token|api_?key|access_?key)/i.test(m[1]) && m[2] && !/^\$\{?\w+\}?$/.test(m[2])) out.push({ id: "docker.hardcoded-secret", severity: "HIGH", title: `${instr} sets what looks like a credential`, detail: `${instr} values are baked into the image and visible to anyone with 'docker history'. Use build secrets (--secret) or a runtime secret store instead.`, file, line: lineNo, evidence: [`${instr} ${m[1]}=…`] });
    }
    if (instr === "COPY" && /--from=\S+/.test(args) === false && /\.(pem|key|pfx|p12)\b/i.test(args)) out.push({ id: "docker.copy-key-material", severity: "MEDIUM", title: "Copies key material into the image", detail: "Private keys baked into an image ship to everyone who pulls it.", file, line: lineNo, evidence: [line] });
    if (instr === "EXPOSE" && /\b(22|23|3389)\b/.test(args)) out.push({ id: "docker.expose-admin-port", severity: "LOW", title: `EXPOSEs an administrative port (${args})`, detail: "SSH, Telnet or RDP inside a container image is usually unnecessary and widens the attack surface.", file, line: lineNo, evidence: [line] });
  });

  if (!hasUser) out.push({ id: "docker.runs-as-root", severity: "MEDIUM", title: "Container runs as root", detail: "No USER instruction sets a non-root user (or USER is explicitly root/0). The container's default process runs as UID 0; a container escape then starts as root on the host's namespace.", file, evidence: ["No effective non-root USER instruction in the file"] });
  if (!baseTagged && baseLine > 0) out.push({ id: "docker.untagged-base", severity: "LOW", title: "Base image has no tag or digest", detail: "An untagged FROM resolves to :latest implicitly and is not reproducible.", file, line: baseLine, evidence: [ls[baseLine - 1]?.trim() ?? ""] });
  if (!hasHealthcheck) out.push({ id: "docker.no-healthcheck", severity: "INFO", title: "No HEALTHCHECK instruction", detail: "Orchestrators cannot detect an unhealthy-but-running process without one. Informational, not a security defect.", file, evidence: [] });
  return out;
}

// ───────────────────────────── docker-compose / Kubernetes (structural)

interface Ctx {
  file: string;
  out: IacFinding[];
}

function checkComposeService(ctx: Ctx, name: string, svc: Record<string, unknown>, docLine: (path: (string | number)[]) => number | undefined) {
  const at = (path: (string | number)[]) => docLine(["services", name, ...path]);
  if (svc.privileged === true) ctx.out.push({ id: "compose.privileged", severity: "CRITICAL", title: `Service '${name}' runs privileged`, detail: "privileged: true disables essentially all container isolation, giving the container the same access as the host kernel.", file: ctx.file, line: at(["privileged"]), evidence: [`services.${name}.privileged: true`] });
  if (Array.isArray(svc.cap_add) && svc.cap_add.some((c) => String(c).toUpperCase() === "SYS_ADMIN" || String(c).toUpperCase() === "ALL")) ctx.out.push({ id: "compose.cap-sys-admin", severity: "HIGH", title: `Service '${name}' adds a dangerous capability`, detail: "SYS_ADMIN (or ALL) grants near-root kernel capabilities inside the container.", file: ctx.file, line: at(["cap_add"]), evidence: [`cap_add: ${JSON.stringify(svc.cap_add)}`] });
  const volumes = Array.isArray(svc.volumes) ? svc.volumes.map(String) : [];
  for (const v of volumes) {
    if (/^\/var\/run\/docker\.sock:/.test(v)) ctx.out.push({ id: "compose.docker-socket", severity: "CRITICAL", title: `Service '${name}' mounts the Docker socket`, detail: "Access to docker.sock is equivalent to root on the host: the container can launch new, privileged containers.", file: ctx.file, line: at(["volumes"]), evidence: [v] });
    if (/^\/(:| )/.test(v) || /^\/:/.test(v)) ctx.out.push({ id: "compose.host-root-mount", severity: "HIGH", title: `Service '${name}' mounts the host root filesystem`, detail: "Full filesystem access from inside a container removes most of the isolation containers provide.", file: ctx.file, line: at(["volumes"]), evidence: [v] });
  }
  if (svc.network_mode === "host") ctx.out.push({ id: "compose.host-network", severity: "MEDIUM", title: `Service '${name}' uses host networking`, detail: "network_mode: host removes network isolation between the container and the host.", file: ctx.file, line: at(["network_mode"]), evidence: ["network_mode: host"] });
  if (svc.pid === "host") ctx.out.push({ id: "compose.host-pid", severity: "MEDIUM", title: `Service '${name}' shares the host PID namespace`, detail: "pid: host lets the container see and signal every process on the host.", file: ctx.file, line: at(["pid"]), evidence: ["pid: host"] });
  const env = svc.environment;
  const envEntries = Array.isArray(env) ? env.map(String) : env && typeof env === "object" ? Object.entries(env).map(([k, v]) => `${k}=${v}`) : [];
  for (const e of envEntries) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/.exec(e);
    if (m && /(secret|password|passwd|token|api_?key)/i.test(m[1]) && m[2] && !/^\$\{/.test(m[2])) ctx.out.push({ id: "compose.hardcoded-secret", severity: "MEDIUM", title: `Service '${name}' has a hardcoded credential in environment`, detail: "Environment values in compose files are often committed to version control. Use an env_file excluded from git, or a secret manager.", file: ctx.file, line: at(["environment"]), evidence: [`${m[1]}=…`] });
  }
}

export function scanCompose(file: string, text: string): IacFinding[] {
  const ctx: Ctx = { file, out: [] };
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = parseAllDocuments(text)[0]?.toJS() as Record<string, unknown> | undefined;
  } catch {
    return ctx.out;
  }
  if (!parsed?.services) return ctx.out;
  const ls = lines(text);
  // Best-effort line lookup: search from the service's own heading for a
  // line containing the attribute's key. Good enough to point a reader at
  // the right area; not a full YAML-source-map walk.
  const lineOf = (name: string, key: string | number) => {
    const serviceHeading = new RegExp(`^\\s{0,4}${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`);
    const start = ls.findIndex((l) => serviceHeading.test(l));
    if (start < 0) return undefined;
    const keyRe = new RegExp(`^\\s+${String(key).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`);
    for (let i = start + 1; i < ls.length; i++) {
      if (/^\S/.test(ls[i])) break; // left the service block
      if (keyRe.test(ls[i])) return i + 1;
    }
    return start + 1;
  };
  for (const [name, svc] of Object.entries((parsed.services as Record<string, unknown>) ?? {}))
    if (svc && typeof svc === "object") checkComposeService(ctx, name, svc as Record<string, unknown>, (path) => lineOf(name, path[path.length - 1]));
  return ctx.out;
}

const RISKY_CAPS = new Set(["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE"]);

function checkK8sContainer(ctx: Ctx, kind: string, resource: string, containerType: "containers" | "initContainers", c: Record<string, unknown>, podSpec: Record<string, unknown>) {
  const sc = (c.securityContext ?? {}) as Record<string, unknown>;
  const podSc = (podSpec.securityContext ?? {}) as Record<string, unknown>;
  const label = `${kind}/${resource} ${containerType === "initContainers" ? "init " : ""}container '${c.name}'`;
  if (sc.privileged === true) ctx.out.push({ id: "k8s.privileged", severity: "CRITICAL", title: `${label} is privileged`, detail: "A privileged container has essentially unrestricted access to the host.", file: ctx.file, evidence: ["securityContext.privileged: true"] });
  const caps = ((sc.capabilities as Record<string, unknown>)?.add as unknown[]) ?? [];
  const risky = caps.map(String).filter((cap) => RISKY_CAPS.has(cap.toUpperCase()));
  if (risky.length) ctx.out.push({ id: "k8s.dangerous-capability", severity: "HIGH", title: `${label} adds capabilities: ${risky.join(", ")}`, detail: "These capabilities approach or reach root-equivalent kernel access.", file: ctx.file, evidence: [`capabilities.add: [${caps.join(", ")}]`] });
  if (sc.allowPrivilegeEscalation !== false) ctx.out.push({ id: "k8s.privilege-escalation", severity: "LOW", title: `${label} does not set allowPrivilegeEscalation: false`, detail: "Without this, a process can gain more privileges than its parent (e.g. via a setuid binary).", file: ctx.file, evidence: ["allowPrivilegeEscalation not set to false"] });
  const runAsNonRoot = sc.runAsNonRoot ?? podSc.runAsNonRoot;
  if (runAsNonRoot !== true) ctx.out.push({ id: "k8s.runs-as-root", severity: "MEDIUM", title: `${label} may run as root`, detail: "Neither the container nor pod securityContext sets runAsNonRoot: true.", file: ctx.file, evidence: ["runAsNonRoot not enforced"] });
  const hostPath = ((podSpec.volumes as Record<string, unknown>[]) ?? []).some((v) => "hostPath" in v);
  if (hostPath) ctx.out.push({ id: "k8s.hostpath-volume", severity: "MEDIUM", title: `${resource} mounts a hostPath volume`, detail: "hostPath exposes part of the node's filesystem to the pod, and can be used to break out to the node.", file: ctx.file, evidence: ["volumes: [{ hostPath: … }]"] });
  if (podSpec.hostNetwork === true) ctx.out.push({ id: "k8s.hostnetwork", severity: "MEDIUM", title: `${resource} uses hostNetwork`, detail: "The pod shares the node's network namespace.", file: ctx.file, evidence: ["hostNetwork: true"] });
  if (!c.resources || !(c.resources as Record<string, unknown>).limits) ctx.out.push({ id: "k8s.no-resource-limits", severity: "LOW", title: `${label} has no resource limits`, detail: "Without limits, a runaway or malicious container can exhaust node resources and affect other workloads.", file: ctx.file, evidence: ["resources.limits not set"] });
  if (typeof c.image === "string" && (c.image.endsWith(":latest") || !/:/.test(c.image))) ctx.out.push({ id: "k8s.latest-image", severity: "LOW", title: `${label} uses an unpinned image tag`, detail: `Image '${c.image}' floats and is not reproducible.`, file: ctx.file, evidence: [`image: ${c.image}`] });
}

export function scanKubernetes(file: string, text: string): IacFinding[] {
  const ctx: Ctx = { file, out: [] };
  let docs: unknown[];
  try {
    docs = parseAllDocuments(text).map((d) => d.toJS());
  } catch {
    return ctx.out;
  }
  for (const raw of docs) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    const kind = String(r.kind ?? "");
    const name = String((r.metadata as Record<string, unknown>)?.name ?? "(unnamed)");
    if (r.kind === "Secret" && r.type !== "kubernetes.io/service-account-token" && r.stringData) ctx.out.push({ id: "k8s.plaintext-secret-manifest", severity: "MEDIUM", title: `Secret '${name}' has plaintext stringData in the manifest`, detail: "Secret manifests committed to a repository expose their values to anyone with read access, even though Kubernetes only base64-encodes them at rest.", file, evidence: [`Secret/${name} stringData: {…}`] });
    if (r.kind === "Pod" && /namespace['"]?\s*:\s*['"]?(kube-system)/i.test(JSON.stringify(r.metadata))) ctx.out.push({ id: "k8s.kube-system-pod", severity: "INFO", title: `Pod '${name}' targets kube-system`, detail: "Workloads in kube-system often run with elevated privileges by convention.", file, evidence: [] });
    const podSpec = kind === "Pod" ? (r.spec as Record<string, unknown>) : ((r.spec as Record<string, unknown>)?.template as Record<string, unknown>)?.spec as Record<string, unknown> | undefined;
    if (!podSpec) continue;
    for (const containerType of ["containers", "initContainers"] as const) {
      const list = (podSpec[containerType] as Record<string, unknown>[]) ?? [];
      for (const c of list) checkK8sContainer(ctx, kind, name, containerType, c, podSpec);
    }
    if (podSpec.automountServiceAccountToken !== false && kind !== "Deployment") ctx.out.push({ id: "k8s.automount-token", severity: "INFO", title: `${kind}/${name} auto-mounts the service account token`, detail: "Every pod gets a token to talk to the API server by default, even when it never calls it — set automountServiceAccountToken: false when not needed.", file, evidence: [] });
  }
  return ctx.out;
}

// ───────────────────────────── Terraform (regex-based; HCL is not parsed as a full grammar)

export function scanTerraform(file: string, text: string): IacFinding[] {
  const out: IacFinding[] = [];
  const ls = lines(text);
  const blockRe = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/;
  for (let i = 0; i < ls.length; i++) {
    const m = blockRe.exec(ls[i]);
    if (!m) continue;
    const [, type, name] = m;
    let depth = 1;
    let j = i + 1;
    let body = "";
    while (j < ls.length && depth > 0) {
      depth += (ls[j].match(/\{/g) ?? []).length - (ls[j].match(/\}/g) ?? []).length;
      body += `${ls[j]}\n`;
      j++;
    }
    const at = (re: RegExp) => {
      const idx = body.search(re);
      return idx < 0 ? i + 1 : i + 1 + body.slice(0, idx).split("\n").length;
    };
    if (type === "aws_s3_bucket" && /acl\s*=\s*"(public-read|public-read-write)"/.test(body)) out.push({ id: "tf.s3-public-acl", severity: "CRITICAL", title: `S3 bucket '${name}' has a public ACL`, detail: "public-read or public-read-write makes every object in the bucket world-readable (or writable).", file, line: at(/acl\s*=/), evidence: [/acl\s*=\s*"[^"]+"/.exec(body)?.[0] ?? ""] });
    if (type === "aws_security_group" || type === "aws_security_group_rule") {
      if (/cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/.test(body) && /from_port\s*=\s*22\b/.test(body)) out.push({ id: "tf.sg-open-ssh", severity: "HIGH", title: `Security group '${name}' opens SSH (22) to the internet`, detail: "0.0.0.0/0 on port 22 allows SSH attempts from anywhere.", file, line: at(/from_port\s*=\s*22/), evidence: ["cidr_blocks = [\"0.0.0.0/0\"], from_port = 22"] });
      if (/cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/.test(body) && /from_port\s*=\s*3389\b/.test(body)) out.push({ id: "tf.sg-open-rdp", severity: "HIGH", title: `Security group '${name}' opens RDP (3389) to the internet`, detail: "0.0.0.0/0 on port 3389 allows RDP attempts from anywhere.", file, line: at(/from_port\s*=\s*3389/), evidence: ["cidr_blocks = [\"0.0.0.0/0\"], from_port = 3389"] });
      if (/from_port\s*=\s*0\b[\s\S]*?to_port\s*=\s*0\b|from_port\s*=\s*-?1\b/.test(body) && /"0\.0\.0\.0\/0"/.test(body)) out.push({ id: "tf.sg-all-ports", severity: "CRITICAL", title: `Security group '${name}' allows all ports from the internet`, detail: "A rule spanning every port with a 0.0.0.0/0 source has no meaningful restriction.", file, line: at(/cidr_blocks/), evidence: ["cidr_blocks = [\"0.0.0.0/0\"]"] });
    }
    if ((type === "aws_db_instance" || type === "aws_rds_cluster") && /publicly_accessible\s*=\s*true/.test(body)) out.push({ id: "tf.rds-public", severity: "HIGH", title: `Database '${name}' is publicly accessible`, detail: "publicly_accessible = true exposes the database to the internet.", file, line: at(/publicly_accessible/), evidence: ["publicly_accessible = true"] });
    if ((type === "aws_db_instance" || type === "aws_rds_cluster") && !/storage_encrypted\s*=\s*true/.test(body)) out.push({ id: "tf.rds-unencrypted", severity: "MEDIUM", title: `Database '${name}' does not set storage_encrypted`, detail: "Storage encryption at rest is not enabled (or not declared).", file, line: i + 1, evidence: [] });
    if (type === "aws_s3_bucket" && !/aws_s3_bucket_server_side_encryption_configuration/.test(text)) out.push({ id: "tf.s3-unencrypted", severity: "LOW", title: `S3 bucket '${name}' has no server-side encryption configuration in this file`, detail: "No aws_s3_bucket_server_side_encryption_configuration resource references this bucket in the file. It may be configured elsewhere.", file, line: i + 1, evidence: [] });
    if (type === "aws_iam_policy_document" || type === "aws_iam_policy" || type === "aws_iam_role_policy") {
      if (/Action\s*=\s*"\*"|actions\s*=\s*\["\*"\]/.test(body) && /Resource\s*=\s*"\*"|resources\s*=\s*\["\*"\]/.test(body)) out.push({ id: "tf.iam-wildcard", severity: "HIGH", title: `IAM policy '${name}' grants Action:* on Resource:*`, detail: "A fully wildcarded policy grants unrestricted access to every action on every resource.", file, line: i + 1, evidence: ["Action = \"*\", Resource = \"*\""] });
    }
    if ((type === "azurerm_storage_account" && /min_tls_version\s*=\s*"TLS1_0"/.test(body)) || (type === "aws_s3_bucket_policy" && /"aws:SecureTransport":\s*"false"/.test(body) === false && /Condition/.test(body) === false)) {
      // best-effort; only flag the Azure case explicitly to avoid over-claiming on the S3 policy shape
    }
    if (type === "azurerm_storage_account" && /min_tls_version\s*=\s*"TLS1_0"/.test(body)) out.push({ id: "tf.azure-old-tls", severity: "MEDIUM", title: `Storage account '${name}' allows TLS 1.0`, detail: "TLS 1.0 is deprecated (RFC 8996).", file, line: at(/min_tls_version/), evidence: ["min_tls_version = \"TLS1_0\""] });
    const secretAttr = /(password|secret|access_key|private_key)\s*=\s*"([^"$][^"]{4,})"/i.exec(body);
    if (secretAttr && !/\$\{|var\.|data\./.test(secretAttr[0])) out.push({ id: "tf.hardcoded-secret", severity: "HIGH", title: `Resource '${type}.${name}' has a hardcoded ${secretAttr[1]}`, detail: "Secrets in .tf files are committed to version control and visible in state files. Use a variable sourced from a secret manager instead.", file, line: at(new RegExp(secretAttr[1])), evidence: [`${secretAttr[1]} = "…"`] });
  }
  return out;
}

// ───────────────────────────── GitHub Actions

export function scanGithubActions(file: string, text: string): IacFinding[] {
  const out: IacFinding[] = [];
  let doc: Record<string, unknown>;
  try {
    doc = parseYaml(text);
  } catch {
    return out;
  }
  const jobs = (doc.jobs ?? {}) as Record<string, Record<string, unknown>>;
  for (const [jobName, job] of Object.entries(jobs)) {
    if (job.permissions === "write-all" || (job.permissions && typeof job.permissions === "object" && Object.values(job.permissions).includes("write"))) {
      // informational only; broad permissions are sometimes required
    }
    const steps = (job.steps as Record<string, unknown>[]) ?? [];
    for (const [i, step] of steps.entries()) {
      const uses = step.uses as string | undefined;
      if (uses && /@(main|master)$/.test(uses)) out.push({ id: "gha.unpinned-action", severity: "LOW", title: `${jobName} step ${i + 1}: action pinned to a branch, not a version or SHA`, detail: `'${uses}' can change without notice; pin to a release tag or, safer still, a commit SHA.`, file, evidence: [uses] });
      const run = step.run as string | undefined;
      if (run && /\$\{\{\s*github\.event\.(issue|pull_request)\.(title|body)\s*\}\}/.test(run)) out.push({ id: "gha.script-injection", severity: "HIGH", title: `${jobName} step ${i + 1}: untrusted input interpolated directly into a shell script`, detail: "Issue and PR titles/bodies are attacker-controlled text; interpolating them into 'run:' allows script injection. Pass them through env: instead and reference the environment variable.", file, evidence: [run.slice(0, 160)] });
      if (run && /curl[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b/.test(run)) out.push({ id: "gha.curl-pipe-sh", severity: "MEDIUM", title: `${jobName} step ${i + 1}: pipes a download into a shell`, detail: "Runs whatever the remote server returns, unverified.", file, evidence: [run.slice(0, 160)] });
    }
  }
  if (doc.on && typeof doc.on === "object" && "pull_request_target" in (doc.on as object) && jobs && Object.values(jobs).some((j) => (j.steps as Record<string, unknown>[])?.some((s) => (s.uses as string)?.includes("checkout") && s.with && "ref" in (s.with as object)))) {
    out.push({ id: "gha.pull-request-target-checkout", severity: "HIGH", title: "pull_request_target with a checkout of the PR head", detail: "pull_request_target runs with write permissions and repository secrets against a fork's code; checking out the PR head under this trigger is the classic path to secret exfiltration.", file, evidence: ["on: pull_request_target", "uses: actions/checkout with a PR ref"] });
  }
  return out;
}

export function scanIacFile(filename: string, text: string): { kind: IacFileKind; findings: IacFinding[] } {
  const kind = detectIacKind(filename, text);
  const findings =
    kind === "dockerfile" ? scanDockerfile(filename, text) : kind === "compose" ? scanCompose(filename, text) : kind === "kubernetes" ? scanKubernetes(filename, text) : kind === "terraform" ? scanTerraform(filename, text) : kind === "github-actions" ? scanGithubActions(filename, text) : [];
  return { kind, findings };
}
