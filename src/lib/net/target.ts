import "server-only";
import http from "node:http";
import https from "node:https";
import { ALLOWED_TARGET_PORTS, NetworkPolicyError, assertHostnameAllowed, safeLookup } from "./policy";

export interface TargetHop {
  url: string;
  status: number;
  location?: string;
  server?: string;
  latencyMs: number;
}

export interface TargetResponse {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  setCookies: string[];
  body: string;
  bodyTruncated: boolean;
  hops: TargetHop[];
  tls?: { protocol: string | null; authorized: boolean; authorizationError?: string };
}

export interface TargetRequestOptions {
  method?: "GET" | "HEAD";
  maxRedirects?: number;
  timeoutMs?: number;
  /** Bytes of body to keep; the rest of the stream is discarded. */
  maxBodyBytes?: number;
  headers?: Record<string, string>;
}

export class TargetRequestError extends Error {
  constructor(message: string, public readonly kind: "policy" | "timeout" | "network" | "tls" | "redirects", public readonly hops: TargetHop[] = []) {
    super(message);
    this.name = "TargetRequestError";
  }
}

const USER_AGENT = "NOPS-Cyber-Intelligence/1.0 (+security analysis; read-only)";

/** Validates a user-supplied URL before any network activity happens. */
export function assertTargetUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TargetRequestError("Malformed URL", "policy");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TargetRequestError(`Scheme ${url.protocol} is not allowed`, "policy");
  }
  if (url.username || url.password) {
    // Never forward embedded credentials to a third party.
    url.username = "";
    url.password = "";
  }
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  if (!ALLOWED_TARGET_PORTS.has(port)) {
    throw new TargetRequestError(`Port ${port} is outside the allowed set (${[...ALLOWED_TARGET_PORTS].join(", ")})`, "policy");
  }
  try {
    assertHostnameAllowed(url.hostname);
  } catch (err) {
    throw new TargetRequestError((err as Error).message, "policy");
  }
  return url;
}

function singleRequest(url: URL, options: Required<Pick<TargetRequestOptions, "method" | "timeoutMs" | "maxBodyBytes">> & { headers?: Record<string, string> }, deadline: number) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; truncated: boolean; tls?: TargetResponse["tls"] }>((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;
    const remaining = Math.max(1, deadline - Date.now());
    const req = client.request(
      url,
      {
        method: options.method,
        lookup: safeLookup as unknown as typeof import("node:dns").lookup,
        headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml,*/*;q=0.8", ...options.headers },
        timeout: Math.min(options.timeoutMs, remaining),
        // Certificate problems are reported, not fatal: analysing broken TLS is part of the job.
        rejectUnauthorized: false,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        const socket = res.socket as import("node:tls").TLSSocket;
        const tls =
          url.protocol === "https:" && typeof socket.getProtocol === "function"
            ? {
                protocol: socket.getProtocol(),
                authorized: socket.authorized,
                authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
              }
            : undefined;
        res.on("data", (chunk: Buffer) => {
          if (truncated) return;
          size += chunk.length;
          if (size > options.maxBodyBytes) {
            truncated = true;
            chunks.push(chunk.subarray(0, chunk.length - (size - options.maxBodyBytes)));
            res.destroy();
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), truncated, tls });
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), truncated, tls }));
        res.on("error", (err) => (truncated ? undefined : reject(err)));
      }
    );
    req.on("timeout", () => req.destroy(new TargetRequestError("The destination did not respond before the timeout", "timeout")));
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (err instanceof TargetRequestError) return reject(err);
      if (err instanceof NetworkPolicyError || err.code === "ENOTALLOWED") return reject(new TargetRequestError(err.message, "policy"));
      if (err.code?.startsWith("ERR_TLS") || err.code?.includes("CERT")) return reject(new TargetRequestError(err.message, "tls"));
      reject(new TargetRequestError(err.code ? `${err.code}: ${err.message}` : err.message, "network"));
    });
    req.end();
  });
}

/**
 * Fetches a user-supplied URL under the full SSRF policy: scheme/port/hostname
 * checks, connect-time address validation on every hop, bounded redirects with
 * each Location re-validated, a total deadline and a response-size ceiling.
 */
export async function targetRequest(raw: string, options: TargetRequestOptions = {}): Promise<TargetResponse> {
  const method = options.method ?? "GET";
  const maxRedirects = options.maxRedirects ?? 6;
  const timeoutMs = options.timeoutMs ?? 8000;
  const maxBodyBytes = options.maxBodyBytes ?? 512 * 1024;
  const deadline = Date.now() + timeoutMs * 2;
  const hops: TargetHop[] = [];

  let url = assertTargetUrl(raw);
  for (let i = 0; i <= maxRedirects; i++) {
    if (Date.now() > deadline) throw new TargetRequestError("Overall request deadline exceeded", "timeout", hops);
    const started = Date.now();
    let res;
    try {
      res = await singleRequest(url, { method, timeoutMs, maxBodyBytes, headers: options.headers }, deadline);
    } catch (err) {
      if (err instanceof TargetRequestError) throw new TargetRequestError(err.message, err.kind, hops);
      throw err;
    }
    const location = typeof res.headers.location === "string" ? res.headers.location : undefined;
    hops.push({
      url: url.toString(),
      status: res.status,
      location,
      server: typeof res.headers.server === "string" ? res.headers.server : undefined,
      latencyMs: Date.now() - started,
    });

    // maxRedirects: 0 means "report the redirect, don't follow it".
    if ([301, 302, 303, 307, 308].includes(res.status) && location && maxRedirects > 0) {
      let next: URL;
      try {
        next = assertTargetUrl(new URL(location, url).toString());
      } catch (err) {
        throw new TargetRequestError(`Redirect to ${location} blocked: ${(err as Error).message}`, "policy", hops);
      }
      url = next;
      continue;
    }

    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = v;
    const setCookie = res.headers["set-cookie"];
    return {
      url: url.toString(),
      status: res.status,
      headers,
      setCookies: Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [],
      body: res.body,
      bodyTruncated: res.truncated,
      hops,
      tls: res.tls,
    };
  }
  throw new TargetRequestError(`More than ${maxRedirects} redirects`, "redirects", hops);
}
