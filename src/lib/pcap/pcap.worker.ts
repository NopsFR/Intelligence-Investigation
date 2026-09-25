import { analyzeCapture } from "./analyze";
import { readCapture, type CaptureFile } from "./capture";
import { dissect, maskSecretHeader, type LayerNode } from "./dissect";
import { FilterError, compileFilter } from "./filter";

// Holds one capture in memory and answers the packet lab's requests:
// load, display-filter, packet detail and follow-stream.

let bytes: Uint8Array | null = null;
let capture: CaptureFile | null = null;
let streams = new Map<number, number[]>();
let frameStream = new Map<number, number>();

type Req = { id: number; op: "load"; file: File } | { id: number; op: "filter"; expr: string } | { id: number; op: "packet"; n: number } | { id: number; op: "stream"; stream: number };

function maskStreamText(text: string): string {
  return text
    .replace(/^((?:proxy-)?authorization|cookie|set-cookie):\s*(.*)$/gim, (_m, k: string, v: string) => `${k}: ${maskSecretHeader(k, v)}`)
    .replace(/^(PASS)\s+.*$/gim, "$1 ********")
    .replace(/^(\S+\s+LOGIN\s+\S+)\s+.*$/gim, "$1 ********")
    .replace(/^(AUTH\s+(?:PLAIN|LOGIN))(\s+.*)?$/gim, "$1 ********");
}

self.onmessage = async (event: MessageEvent<Req>) => {
  const msg = event.data;
  try {
    if (msg.op === "load") {
      const b = new Uint8Array(await msg.file.arrayBuffer());
      const cap = readCapture(b);
      const s = new Map<number, number[]>();
      const report = await analyzeCapture(b, msg.file.name, cap, { streams: s });
      bytes = b;
      capture = cap;
      streams = s;
      frameStream = new Map();
      for (const [id, frames] of s) for (const n of frames) frameStream.set(n, id);
      self.postMessage({ id: msg.id, ok: true, report });
      return;
    }
    if (!bytes || !capture) throw new Error("No capture loaded");
    if (msg.op === "filter") {
      let predicate;
      try {
        predicate = compileFilter(msg.expr);
      } catch (err) {
        if (err instanceof FilterError) {
          self.postMessage({ id: msg.id, ok: true, error: err.message, position: err.position, matches: null });
          return;
        }
        throw err;
      }
      const matches: number[] = [];
      for (const f of capture.frames) {
        const d = dissect(bytes.subarray(f.offset, f.offset + f.captured), f.linkType);
        d.fields.set("frame.number", [f.index]);
        const st = frameStream.get(f.index);
        if (st !== undefined) {
          d.fields.set("tcp.stream", [st]);
          d.fields.set("udp.stream", [st]);
        }
        if (predicate(d.fields)) matches.push(f.index);
      }
      self.postMessage({ id: msg.id, ok: true, matches });
      return;
    }
    if (msg.op === "packet") {
      const f = capture.frames[msg.n - 1];
      if (!f) throw new Error(`No frame ${msg.n}`);
      const data = bytes.slice(f.offset, f.offset + f.captured);
      const d = dissect(data, f.linkType);
      const frameNode: LayerNode = { label: `Frame ${f.index}`, value: `${f.original} bytes on wire, ${f.captured} captured`, range: [0, f.captured], children: [{ label: "Arrival time", value: new Date(f.ts / 1000).toISOString() }, { label: "Interface", value: String(f.interfaceId) }, { label: "Link type", value: String(f.linkType) }] };
      self.postMessage({ id: msg.id, ok: true, layers: [frameNode, ...d.layers], bytes: data, malformed: d.malformed, stream: frameStream.get(f.index) });
      return;
    }
    if (msg.op === "stream") {
      const frames = streams.get(msg.stream) ?? [];
      const chunks: { dir: "client" | "server"; text: string; frame: number }[] = [];
      let first: { src: string; port?: number } | null = null;
      let total = 0;
      const seen = new Set<string>();
      for (const n of frames) {
        const f = capture.frames[n - 1];
        const d = dissect(bytes.subarray(f.offset, f.offset + f.captured), f.linkType);
        if (!d.payloadLength || d.payloadOffset === undefined) continue;
        if (d.tcp) {
          const key = `${d.src}|${d.srcPort}|${d.tcp.seq}|${d.payloadLength}`;
          if (seen.has(key)) continue; // retransmission
          seen.add(key);
        }
        if (!first) first = { src: d.src, port: d.srcPort };
        const dir = d.src === first.src && d.srcPort === first.port ? "client" : "server";
        const payload = bytes.subarray(f.offset + d.payloadOffset, f.offset + d.payloadOffset + d.payloadLength);
        let text = "";
        for (const c of payload) text += (c >= 0x20 && c < 0x7f) || c === 10 || c === 13 || c === 9 ? String.fromCharCode(c) : ".";
        const last = chunks[chunks.length - 1];
        if (last && last.dir === dir) last.text += text;
        else chunks.push({ dir, text, frame: n });
        total += payload.length;
        if (total > 1024 * 1024) break;
      }
      self.postMessage({ id: msg.id, ok: true, chunks: chunks.map((c) => ({ ...c, text: maskStreamText(c.text) })), truncated: total > 1024 * 1024 });
    }
  } catch (err) {
    self.postMessage({ id: msg.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
