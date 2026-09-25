"use client";

import { KeyRound, Lock, RefreshCw, Shield, Unlock } from "lucide-react";
import { useState } from "react";
import {
  aesDecrypt,
  aesEncrypt,
  aesGenerateKey,
  fromBase64,
  fromHex,
  hashText,
  hex,
  hmac,
  ivLength,
  rsaDecrypt,
  rsaEncrypt,
  rsaGenerateKeyPair,
  rsaSign,
  rsaVerify,
  toBase64,
  xorBruteForce,
  xorBytes,
  type AesMode,
} from "@/lib/labs/crypto";
import { Tabs } from "@/components/ui/overlays";
import { CopyButton, ErrorNote, Panel } from "@/components/ui/primitives";
import { Chip, Mono } from "../analysis/common";

export function CryptoLab() {
  const [tab, setTab] = useState("hash");
  return (
    <div className="flex flex-col gap-4">
      <Tabs
        label="Crypto tools"
        value={tab}
        onChange={setTab}
        items={[
          { id: "hash", label: "Hash / HMAC" },
          { id: "xor", label: "XOR" },
          { id: "aes", label: "AES" },
          { id: "rsa", label: "RSA" },
        ]}
      />
      {tab === "hash" && <HashPanel />}
      {tab === "xor" && <XorPanel />}
      {tab === "aes" && <AesPanel />}
      {tab === "rsa" && <RsaPanel />}
    </div>
  );
}

function HashPanel() {
  const [text, setText] = useState("");
  const [hmacKey, setHmacKey] = useState("");
  const [results, setResults] = useState<Record<string, string>>({});
  const [hmacResults, setHmacResults] = useState<Record<string, string>>({});

  const run = async (t: string) => {
    setText(t);
    const algs = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const;
    const entries = await Promise.all(algs.map(async (a) => [a, await hashText(a, t)] as const));
    setResults(Object.fromEntries(entries));
  };
  const runHmac = async (key: string) => {
    setHmacKey(key);
    if (!text) return;
    const algs = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const;
    const entries = await Promise.all(algs.map(async (a) => [a, await hmac(a, key, text)] as const));
    setHmacResults(Object.fromEntries(entries));
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Hash">
        <textarea className="input mono min-h-[100px] text-[12px]" placeholder="Text to hash" value={text} onChange={(e) => void run(e.target.value)} aria-label="Text to hash" />
        <dl className="mt-3 flex flex-col gap-2">
          {Object.entries(results).map(([alg, value]) => (
            <div key={alg}>
              <dt className="label mb-1">{alg}</dt>
              <dd className="flex items-center gap-1.5">
                <Mono className="min-w-0 flex-1 truncate text-fg-1">{value}</Mono>
                <CopyButton value={value} />
              </dd>
            </div>
          ))}
        </dl>
      </Panel>
      <Panel title="HMAC" meta="Uses the text from Hash on the left">
        <input className="input mono h-9" placeholder="HMAC key" value={hmacKey} onChange={(e) => void runHmac(e.target.value)} aria-label="HMAC key" />
        {!text ? (
          <p className="mt-3 text-sm text-fg-3">Enter text to hash first.</p>
        ) : (
          <dl className="mt-3 flex flex-col gap-2">
            {Object.entries(hmacResults).map(([alg, value]) => (
              <div key={alg}>
                <dt className="label mb-1">HMAC-{alg}</dt>
                <dd className="flex items-center gap-1.5">
                  <Mono className="min-w-0 flex-1 truncate text-fg-1">{value}</Mono>
                  <CopyButton value={value} />
                </dd>
              </div>
            ))}
          </dl>
        )}
      </Panel>
    </div>
  );
}

function XorPanel() {
  const [mode, setMode] = useState<"encode" | "brute">("encode");
  const [text, setText] = useState("");
  const [key, setKey] = useState("");
  const [format, setFormat] = useState<"text" | "hex" | "base64">("text");
  const [inputFormat, setInputFormat] = useState<"text" | "hex" | "base64">("hex");
  const [bruteInput, setBruteInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const output = (() => {
    try {
      if (!text || !key) return "";
      const data = new TextEncoder().encode(text);
      const keyBytes = new TextEncoder().encode(key);
      const out = xorBytes(data, keyBytes);
      setError(null);
      return format === "hex" ? hex(out) : format === "base64" ? toBase64(out) : new TextDecoder().decode(out).replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);
    } catch (e) {
      setError((e as Error).message);
      return "";
    }
  })();

  const bruteResults = (() => {
    try {
      if (!bruteInput.trim()) return [];
      const bytes = inputFormat === "hex" ? fromHex(bruteInput) : inputFormat === "base64" ? fromBase64(bruteInput) : new TextEncoder().encode(bruteInput);
      return xorBruteForce(bytes, 12);
    } catch {
      return [];
    }
  })();

  return (
    <div className="flex flex-col gap-4">
      <div className="inline-flex self-start rounded-[3px] border border-line-2 bg-ink-0 p-[2px]" role="radiogroup" aria-label="XOR mode">
        {(["encode", "brute"] as const).map((m) => (
          <button key={m} type="button" role="radio" aria-checked={mode === m} onClick={() => setMode(m)} className={`h-[26px] rounded-[2px] px-3 text-sm ${mode === m ? "bg-ink-3 text-fg-1" : "text-fg-3"}`}>
            {m === "encode" ? "Encode / decode with a key" : "Single-byte brute force"}
          </button>
        ))}
      </div>
      {mode === "encode" ? (
        <Panel title="XOR with a text key">
          <div className="grid gap-3 sm:grid-cols-2">
            <textarea className="input mono min-h-[100px] text-[12px]" placeholder="Text" value={text} onChange={(e) => setText(e.target.value)} aria-label="XOR input text" />
            <input className="input mono h-9" placeholder="Key" value={key} onChange={(e) => setKey(e.target.value)} aria-label="XOR key" />
          </div>
          <div className="mt-3 flex items-center gap-2">
            <span className="label">Output as</span>
            {(["text", "hex", "base64"] as const).map((f) => (
              <button key={f} type="button" onClick={() => setFormat(f)} className={`btn btn-sm ${format === f ? "btn-primary" : "btn-ghost"}`}>
                {f}
              </button>
            ))}
          </div>
          {error && <ErrorNote>{error}</ErrorNote>}
          <div className="mt-2">
            <Mono className="block rounded-[2px] bg-ink-0 p-3 break-all whitespace-pre-wrap text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{output || "—"}</Mono>
          </div>
          <p className="mt-2 text-xs text-fg-4">XOR is symmetric: run the same key over the output to recover the original.</p>
        </Panel>
      ) : (
        <Panel title="Single-byte XOR key search" meta="Ranks all 256 keys by how much the result looks like natural-language text">
          <div className="flex flex-wrap items-center gap-2">
            <textarea className="input mono min-h-[80px] flex-1 text-[12px]" placeholder="Ciphertext" value={bruteInput} onChange={(e) => setBruteInput(e.target.value)} aria-label="Ciphertext to brute force" />
            <div className="flex flex-col gap-1">
              {(["hex", "base64", "text"] as const).map((f) => (
                <button key={f} type="button" onClick={() => setInputFormat(f)} className={`btn btn-sm ${inputFormat === f ? "btn-primary" : "btn-ghost"}`}>
                  {f}
                </button>
              ))}
            </div>
          </div>
          {bruteResults.length > 0 && (
            <div className="mt-3 overflow-hidden rounded-[2px] border border-line-1">
              <table className="table">
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Score</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {bruteResults.map((r) => (
                    <tr key={r.key}>
                      <td className="mono text-fg-1">0x{r.key.toString(16).padStart(2, "0")}</td>
                      <td className="mono text-fg-3">{r.score.toFixed(2)}</td>
                      <td className="mono max-w-[420px] truncate text-fg-2">{r.text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

function AesPanel() {
  const [mode, setMode] = useState<AesMode>("AES-GCM");
  const [keyHex, setKeyHex] = useState("");
  const [ivHex, setIvHex] = useState("");
  const [plaintext, setPlaintext] = useState("Attack at dawn.");
  const [ciphertextB64, setCiphertextB64] = useState("");
  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    const key = await aesGenerateKey(256);
    const iv = crypto.getRandomValues(new Uint8Array(ivLength(mode)));
    setKeyHex(hex(key));
    setIvHex(hex(iv));
  };

  const encrypt = async () => {
    try {
      const key = fromHex(keyHex);
      const iv = fromHex(ivHex);
      const ct = await aesEncrypt(mode, key, iv, new TextEncoder().encode(plaintext));
      setCiphertextB64(toBase64(ct));
      setError(null);
      setDecrypted(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const decrypt = async () => {
    try {
      const key = fromHex(keyHex);
      const iv = fromHex(ivHex);
      const pt = await aesDecrypt(mode, key, iv, fromBase64(ciphertextB64));
      setDecrypted(new TextDecoder().decode(pt));
      setError(null);
    } catch (e) {
      setError(`Decryption failed: ${(e as Error).message}. With AES-GCM this means the key, IV, or ciphertext is wrong or was tampered with.`);
      setDecrypted(null);
    }
  };

  return (
    <Panel title="AES" meta="Encryption and decryption via the browser's WebCrypto API">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {(["AES-GCM", "AES-CBC", "AES-CTR"] as const).map((m) => (
          <button key={m} type="button" onClick={() => setMode(m)} className={`btn btn-sm ${mode === m ? "btn-primary" : "btn-ghost"}`}>
            {m}
          </button>
        ))}
        <button type="button" className="btn btn-ghost btn-sm ml-auto" onClick={() => void generate()}>
          <RefreshCw size={12} /> Generate key + IV
        </button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs text-fg-3">
          Key (hex, 16/24/32 bytes)
          <input className="input mono h-9" value={keyHex} onChange={(e) => setKeyHex(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-xs text-fg-3">
          {mode === "AES-CTR" ? "Counter (hex, 16 bytes)" : "IV (hex, 12 or 16 bytes)"}
          <input className="input mono h-9" value={ivHex} onChange={(e) => setIvHex(e.target.value)} />
        </label>
      </div>
      <label className="mt-3 flex flex-col gap-1 text-xs text-fg-3">
        Plaintext
        <textarea className="input mono min-h-[80px] text-[12px]" value={plaintext} onChange={(e) => setPlaintext(e.target.value)} />
      </label>
      <button type="button" className="btn btn-primary mt-2" onClick={() => void encrypt()} disabled={!keyHex || !ivHex}>
        <Lock size={13} /> Encrypt
      </button>
      {ciphertextB64 && (
        <div className="mt-3">
          <div className="label mb-1 flex items-center gap-2">
            Ciphertext (base64)
            <CopyButton value={ciphertextB64} />
          </div>
          <Mono className="block rounded-[2px] bg-ink-0 p-3 break-all text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{ciphertextB64}</Mono>
        </div>
      )}
      <label className="mt-3 flex flex-col gap-1 text-xs text-fg-3">
        Ciphertext to decrypt (base64)
        <textarea className="input mono min-h-[60px] text-[12px]" value={ciphertextB64} onChange={(e) => setCiphertextB64(e.target.value)} />
      </label>
      <button type="button" className="btn btn-primary mt-2" onClick={() => void decrypt()} disabled={!keyHex || !ivHex || !ciphertextB64}>
        <Unlock size={13} /> Decrypt
      </button>
      {error && (
        <div className="mt-3">
          <ErrorNote>{error}</ErrorNote>
        </div>
      )}
      {decrypted !== null && (
        <div className="mt-3">
          <div className="label mb-1">Decrypted</div>
          <Mono className="block rounded-[2px] bg-ink-0 p-3 break-all whitespace-pre-wrap text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{decrypted}</Mono>
        </div>
      )}
      <p className="mt-3 text-xs text-fg-4">Keys and IVs never leave your browser. AES-GCM is authenticated: a wrong key, IV or a tampered ciphertext fails to decrypt rather than silently producing garbage.</p>
    </Panel>
  );
}

function RsaPanel() {
  const [bits, setBits] = useState<2048 | 3072 | 4096>(2048);
  const [busy, setBusy] = useState(false);
  const [keys, setKeys] = useState<{ publicKeyPem: string; privateKeyPem: string; publicKey: CryptoKey; privateKey: CryptoKey } | null>(null);
  const [message, setMessage] = useState("A secret for the recipient's eyes only.");
  const [ciphertext, setCiphertext] = useState("");
  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [signature, setSignature] = useState("");
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const generate = async (usage: "encrypt" | "sign") => {
    setBusy(true);
    setError(null);
    try {
      setKeys(await rsaGenerateKeyPair(bits, usage));
      setCiphertext("");
      setDecrypted(null);
      setSignature("");
      setVerifyResult(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Key pair">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {([2048, 3072, 4096] as const).map((b) => (
            <button key={b} type="button" onClick={() => setBits(b)} className={`btn btn-sm ${bits === b ? "btn-primary" : "btn-ghost"}`}>
              {b}-bit
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <button type="button" className="btn" disabled={busy} onClick={() => void generate("encrypt")}>
            <KeyRound size={13} /> Generate (OAEP, encrypt)
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => void generate("sign")}>
            <Shield size={13} /> Generate (PSS, sign)
          </button>
        </div>
        {error && (
          <div className="mt-3">
            <ErrorNote>{error}</ErrorNote>
          </div>
        )}
        {keys && (
          <div className="mt-3 flex flex-col gap-3">
            <div>
              <div className="label mb-1 flex items-center gap-2">
                Public key <CopyButton value={keys.publicKeyPem} />
              </div>
              <pre className="mono max-h-32 overflow-auto rounded-[2px] bg-ink-0 p-2 text-[11px] whitespace-pre-wrap text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{keys.publicKeyPem}</pre>
            </div>
            <div>
              <div className="label mb-1 flex items-center gap-2">
                Private key <CopyButton value={keys.privateKeyPem} /> <Chip tone="warn">keep secret</Chip>
              </div>
              <pre className="mono max-h-32 overflow-auto rounded-[2px] bg-ink-0 p-2 text-[11px] whitespace-pre-wrap text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{keys.privateKeyPem}</pre>
            </div>
          </div>
        )}
      </Panel>

      <Panel title="Encrypt / decrypt (RSA-OAEP)" meta="Needs a key pair generated for 'encrypt' above">
        <textarea className="input mono min-h-[70px] text-[12px]" value={message} onChange={(e) => setMessage(e.target.value)} aria-label="Message to encrypt" />
        <div className="mt-2 flex gap-2">
          <button
            type="button"
            className="btn btn-primary"
            disabled={!keys}
            onClick={async () => {
              try {
                const ct = await rsaEncrypt(keys!.publicKey, new TextEncoder().encode(message));
                setCiphertext(toBase64(ct));
                setError(null);
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <Lock size={13} /> Encrypt
          </button>
          <button
            type="button"
            className="btn"
            disabled={!keys || !ciphertext}
            onClick={async () => {
              try {
                const pt = await rsaDecrypt(keys!.privateKey, fromBase64(ciphertext));
                setDecrypted(new TextDecoder().decode(pt));
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <Unlock size={13} /> Decrypt
          </button>
        </div>
        {ciphertext && <Mono className="mt-2 block max-h-24 overflow-auto rounded-[2px] bg-ink-0 p-2 break-all text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{ciphertext}</Mono>}
        {decrypted !== null && (
          <div className="mt-2">
            <div className="label mb-1">Decrypted</div>
            <Mono className="text-fg-1">{decrypted}</Mono>
          </div>
        )}

        <div className="mt-5 border-t border-line-1 pt-4">
          <div className="label mb-2">Sign / verify (RSA-PSS)</div>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!keys}
              onClick={async () => {
                try {
                  const sig = await rsaSign(keys!.privateKey, new TextEncoder().encode(message));
                  setSignature(toBase64(sig));
                  setVerifyResult(null);
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              Sign
            </button>
            <button
              type="button"
              className="btn"
              disabled={!keys || !signature}
              onClick={async () => {
                try {
                  setVerifyResult(await rsaVerify(keys!.publicKey, new TextEncoder().encode(message), fromBase64(signature)));
                } catch {
                  setVerifyResult(false);
                }
              }}
            >
              Verify
            </button>
          </div>
          {signature && <Mono className="mt-2 block max-h-24 overflow-auto rounded-[2px] bg-ink-0 p-2 break-all text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{signature}</Mono>}
          {verifyResult !== null && <p className={`mt-2 text-sm ${verifyResult ? "text-ok" : "text-err"}`}>{verifyResult ? "Signature valid for this message." : "Signature does NOT verify for this message."}</p>}
          <p className="mt-2 text-xs text-fg-4">Edit the message after signing, then verify, to see a tampered message fail.</p>
        </div>
      </Panel>
    </div>
  );
}
