import { describe, expect, it } from "vitest";
import { detectIacKind, scanCompose, scanDockerfile, scanGithubActions, scanKubernetes, scanTerraform } from "./iac";
import { parseManifest, recognizeManifest } from "./manifests";
import { scanSecrets } from "./secrets";

describe("manifest parsers", () => {
  it("parses npm v3 package-lock.json packages", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/foo/node_modules/lodash": { version: "3.10.1", dev: true },
      },
    });
    const r = parseManifest("package-lock.json", lock);
    expect(r.ecosystem).toBe("npm");
    expect(r.packages).toEqual(
      expect.arrayContaining([
        { name: "lodash", version: "4.17.15", ecosystem: "npm", direct: true, dev: false, path: ["lodash"] },
        { name: "lodash", version: "3.10.1", ecosystem: "npm", direct: false, dev: true, path: ["foo", "lodash"] },
      ])
    );
  });

  it("parses requirements.txt pinned entries and skips ranges", () => {
    const r = parseManifest("requirements.txt", "django==4.2.1\nrequests>=2.0\n# comment\nflask==2.3.0\n");
    expect(r.packages.map((p) => p.name)).toEqual(["django", "flask"]);
    expect(r.warnings.some((w) => /requests/.test(w))).toBe(true);
  });

  it("parses go.sum module lines, skipping /go.mod checksum entries", () => {
    const r = parseManifest("go.sum", "github.com/pkg/errors v0.9.1 h1:xxx=\ngithub.com/pkg/errors v0.9.1/go.mod h1:yyy=\n");
    expect(r.packages).toEqual([{ name: "github.com/pkg/errors", version: "0.9.1", ecosystem: "Go", direct: true, dev: false }]);
  });

  it("parses Cargo.lock and composer.lock", () => {
    const cargo = parseManifest("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.190"\n\n[[package]]\nname = "libc"\nversion = "0.2.150"\n');
    expect(cargo.packages).toHaveLength(2);
    const composer = parseManifest("composer.lock", JSON.stringify({ packages: [{ name: "monolog/monolog", version: "v2.9.1" }], "packages-dev": [] }));
    expect(composer.packages[0]).toMatchObject({ name: "monolog/monolog", version: "2.9.1", ecosystem: "Packagist" });
  });

  it("recognizes manifest file names", () => {
    expect(recognizeManifest("backend/package-lock.json")).toMatch(/npm/);
    expect(recognizeManifest("main.go")).toBeNull();
  });
});

describe("secret scanner", () => {
  it("detects an AWS access key and redacts it", () => {
    const m = scanSecrets("const key = 'AKIAABCDEFGHIJKLMNOP';");
    expect(m).toHaveLength(1);
    expect(m[0]).toMatchObject({ ruleId: "aws-access-key", confidence: "high" });
    expect(m[0].redacted).not.toContain("ABCDEFGHIJKLMNOP");
    expect(m[0].redacted).toMatch(/•/);
  });

  it("detects a private key block", () => {
    expect(scanSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIBOg...\n-----END RSA PRIVATE KEY-----").some((s) => s.ruleId === "private-key")).toBe(true);
  });

  it("ignores placeholder values", () => {
    expect(scanSecrets('const key = "AKIAXXXXXXXXXXXXXXXX";')).toHaveLength(0);
    expect(scanSecrets('api_key = "your_api_key_here"')).toHaveLength(0);
  });

  it("flags a generic high-entropy assignment but not a low-entropy one", () => {
    const hi = scanSecrets('const secretToken = "9f8x2QpL7mZ4wR1vK6nT0eB3yU5jH8sD";');
    expect(hi.some((s) => s.ruleId === "generic-high-entropy")).toBe(true);
    const lo = scanSecrets('const passwordHint = "aaaaaaaaaaaaaaaaaaaa";');
    expect(lo.some((s) => s.ruleId === "generic-high-entropy")).toBe(false);
  });

  it("reports correct line numbers", () => {
    const m = scanSecrets("line one\nline two\nconst k = 'AKIAABCDEFGHIJKLMNOP';\n");
    expect(m[0].line).toBe(3);
  });
});

describe("Dockerfile checks", () => {
  it("flags root user, curl|sh, latest tag and hardcoded secret", () => {
    const findings = scanDockerfile(
      "Dockerfile",
      `FROM ubuntu:latest
RUN curl https://get.example.com/install.sh | sh
ENV API_TOKEN=abcdef1234567890
EXPOSE 22
`
    );
    const ids = findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["docker.latest-tag", "docker.curl-pipe-sh", "docker.hardcoded-secret", "docker.runs-as-root", "docker.expose-admin-port"]));
  });

  it("does not flag a well-formed Dockerfile", () => {
    const findings = scanDockerfile(
      "Dockerfile",
      `FROM node:20.11.0-alpine
RUN adduser -D appuser
USER appuser
HEALTHCHECK CMD wget -q --spider http://localhost:3000 || exit 1
`
    );
    expect(findings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL")).toEqual([]);
  });

  it("still flags root when USER is explicitly root", () => {
    const findings = scanDockerfile("Dockerfile", `FROM node:20.11.0-alpine\nUSER root\n`);
    expect(findings.map((f) => f.id)).toContain("docker.runs-as-root");
  });
});

describe("docker-compose checks", () => {
  it("flags privileged, docker socket mount, and hardcoded secret", () => {
    const yaml = `services:
  app:
    image: myapp:1.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DB_PASSWORD=hunter2plaintext
`;
    const findings = scanCompose("docker-compose.yml", yaml);
    const ids = findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["compose.privileged", "compose.docker-socket", "compose.hardcoded-secret"]));
    expect(findings.find((f) => f.id === "compose.privileged")?.line).toBeGreaterThan(0);
  });
});

describe("Kubernetes checks", () => {
  it("flags a privileged pod without resource limits", () => {
    const yaml = `apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        privileged: true
`;
    const findings = scanKubernetes("pod.yaml", yaml);
    const ids = findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["k8s.privileged", "k8s.no-resource-limits", "k8s.latest-image", "k8s.runs-as-root"]));
  });

  it("flags a Secret manifest with plaintext stringData", () => {
    const yaml = `apiVersion: v1\nkind: Secret\nmetadata:\n  name: creds\nstringData:\n  password: hunter2\n`;
    expect(scanKubernetes("secret.yaml", yaml).map((f) => f.id)).toContain("k8s.plaintext-secret-manifest");
  });
});

describe("Terraform checks", () => {
  it("flags a public S3 ACL and an open SSH security group", () => {
    const hcl = `resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`;
    const findings = scanTerraform("main.tf", hcl);
    expect(findings.map((f) => f.id)).toEqual(expect.arrayContaining(["tf.s3-public-acl", "tf.sg-open-ssh"]));
  });

  it("flags a hardcoded secret attribute but not a variable reference", () => {
    const hcl = `resource "aws_db_instance" "db" {
  password = "SuperSecretPassword1"
}
`;
    expect(scanTerraform("db.tf", hcl).map((f) => f.id)).toContain("tf.hardcoded-secret");
    const ok = `resource "aws_db_instance" "db" {
  password = var.db_password
}
`;
    expect(scanTerraform("db2.tf", ok).map((f) => f.id)).not.toContain("tf.hardcoded-secret");
  });
});

describe("GitHub Actions checks", () => {
  it("flags an action pinned to a branch and script injection from PR title", () => {
    const yaml = `on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: echo "\${{ github.event.pull_request.title }}"
`;
    const findings = scanGithubActions("build.yml", yaml);
    expect(findings.map((f) => f.id)).toEqual(expect.arrayContaining(["gha.unpinned-action", "gha.script-injection"]));
  });
});

describe("detectIacKind", () => {
  it("recognises files by name and content", () => {
    expect(detectIacKind("Dockerfile", "FROM x")).toBe("dockerfile");
    expect(detectIacKind("docker-compose.yml", "services: {}")).toBe("compose");
    expect(detectIacKind("main.tf", "")).toBe("terraform");
    expect(detectIacKind("deploy.yaml", "apiVersion: v1\nkind: Pod\n")).toBe("kubernetes");
    expect(detectIacKind("notes.yaml", "a: 1\n")).toBe("unknown");
  });
});
