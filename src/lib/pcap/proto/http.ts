// HTTP/1.x message parsing over reassembled TCP streams.

export interface HttpMessage {
  kind: "request" | "response";
  method?: string;
  uri?: string;
  status?: number;
  reason?: string;
  version: string;
  headers: [string, string][];
  bodyOffset: number;
  bodyLength: number;
  /** First bytes of the (de-chunked) body, for type identification and hashing. */
  body: Uint8Array;
  bodyComplete: boolean;
}

const METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND", "MKCOL"];
const MAX_BODY = 8 * 1024 * 1024;

export function looksLikeHttp(b: Uint8Array): boolean {
  if (b.length < 8) return false;
  const head = String.fromCharCode(...b.subarray(0, 9));
  return head.startsWith("HTTP/1.") || METHODS.some((m) => head.startsWith(`${m} `));
}

export const header = (m: HttpMessage, name: string) => m.headers.find(([k]) => k.toLowerCase() === name)?.[1];

function indexOfCrlfCrlf(b: Uint8Array, from: number, limit: number): number {
  const end = Math.min(b.length - 3, from + limit);
  for (let i = from; i < end; i++) if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  return -1;
}

/** Parse consecutive HTTP messages from one direction of a TCP stream. */
export function parseHttpStream(stream: Uint8Array, max = 200): HttpMessage[] {
  const out: HttpMessage[] = [];
  let o = 0;
  const latin = (a: number, b: number) => {
    let s = "";
    for (let i = a; i < b; i++) s += String.fromCharCode(stream[i]);
    return s;
  };
  while (o < stream.length && out.length < max) {
    if (!looksLikeHttp(stream.subarray(o, o + 16))) break;
    const end = indexOfCrlfCrlf(stream, o, 64 * 1024);
    if (end < 0) break;
    const lines = latin(o, end).split("\r\n");
    const first = lines[0];
    const headers: [string, string][] = [];
    for (const l of lines.slice(1, 200)) {
      const i = l.indexOf(":");
      if (i > 0) headers.push([l.slice(0, i).trim(), l.slice(i + 1).trim()]);
    }
    const msg: HttpMessage = { kind: "request", version: "", headers, bodyOffset: end + 4, bodyLength: 0, body: new Uint8Array(0), bodyComplete: true };
    const status = /^HTTP\/(1\.[01]) (\d{3})\s*(.*)$/.exec(first);
    if (status) {
      msg.kind = "response";
      msg.version = status[1];
      msg.status = Number(status[2]);
      msg.reason = status[3];
    } else {
      const req = /^([A-Z]+) (\S+) HTTP\/(1\.[01])$/.exec(first);
      if (!req) break;
      msg.method = req[1];
      msg.uri = req[2];
      msg.version = req[3];
    }
    let p = end + 4;
    const te = header(msg, "transfer-encoding")?.toLowerCase();
    const cl = header(msg, "content-length");
    const noBody = msg.kind === "response" && (msg.status! < 200 || msg.status === 204 || msg.status === 304);
    if (noBody) {
      // no body
    } else if (te?.includes("chunked")) {
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (let guard = 0; guard < 100_000; guard++) {
        let lineEnd = p;
        while (lineEnd + 1 < stream.length && !(stream[lineEnd] === 13 && stream[lineEnd + 1] === 10)) lineEnd++;
        if (lineEnd + 1 >= stream.length) {
          msg.bodyComplete = false;
          p = stream.length;
          break;
        }
        const size = parseInt(latin(p, lineEnd).split(";")[0], 16);
        if (!Number.isFinite(size)) {
          msg.bodyComplete = false;
          p = stream.length;
          break;
        }
        p = lineEnd + 2;
        if (size === 0) {
          const trailerEnd = indexOfCrlfCrlf(stream, p - 2, 8192);
          p = trailerEnd >= 0 ? trailerEnd + 4 : Math.min(stream.length, p + 2);
          break;
        }
        const chunk = stream.subarray(p, Math.min(stream.length, p + size));
        if (total < MAX_BODY) chunks.push(chunk.subarray(0, MAX_BODY - total));
        total += chunk.length;
        p += size + 2;
        if (p > stream.length) {
          msg.bodyComplete = false;
          break;
        }
      }
      const body = new Uint8Array(Math.min(total, MAX_BODY));
      let q = 0;
      for (const c of chunks) {
        body.set(c.subarray(0, body.length - q), q);
        q += c.length;
        if (q >= body.length) break;
      }
      msg.body = body;
      msg.bodyLength = total;
    } else if (cl !== undefined && /^\d+$/.test(cl)) {
      const n = Number(cl);
      msg.bodyLength = n;
      msg.body = stream.subarray(p, Math.min(stream.length, p + Math.min(n, MAX_BODY)));
      msg.bodyComplete = p + n <= stream.length;
      p += n;
    } else if (msg.kind === "response") {
      // Body runs to connection close.
      msg.bodyLength = stream.length - p;
      msg.body = stream.subarray(p, Math.min(stream.length, p + MAX_BODY));
      p = stream.length;
    }
    out.push(msg);
    if (p <= o) break;
    o = p;
  }
  return out;
}
