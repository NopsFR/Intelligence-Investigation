// Password security analysis — entirely local. The password itself never
// leaves the browser here; the only network contact anywhere in this app for
// a password is the existing k-anonymity Pwned Passwords check, which sends
// only a 5-character SHA-1 prefix (see /api/intel/exposure/password).
//
// Strength here is an estimate, not a guarantee: real-world crackability
// depends on the attacker's wordlists, GPU budget, and the site's own hash
// function — this only reasons about the password's own structure.

export interface CharsetBreakdown {
  lower: boolean;
  upper: boolean;
  digit: boolean;
  symbol: boolean;
  other: boolean;
  poolSize: number;
}

export interface PatternFinding {
  id: string;
  label: string;
  detail: string;
}

export type StrengthTier = "very-weak" | "weak" | "fair" | "strong" | "very-strong";

export interface PasswordAnalysis {
  length: number;
  charset: CharsetBreakdown;
  entropyBits: number;
  tier: StrengthTier;
  patterns: PatternFinding[];
  suggestions: string[];
}

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

// A small, well-known set of the most common leaked passwords — enough to
// catch the obvious cases locally, not a substitute for the k-anonymity
// breach check below.
const COMMON_PASSWORDS = new Set([
  "password",
  "123456",
  "123456789",
  "12345678",
  "12345",
  "1234567",
  "qwerty",
  "abc123",
  "password1",
  "iloveyou",
  "111111",
  "123123",
  "admin",
  "letmein",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "login",
  "princess",
  "qwerty123",
  "solo",
  "starwars",
  "football",
  "baseball",
  "trustno1",
  "superman",
  "hello",
  "freedom",
  "whatever",
  "qazwsx",
  "passw0rd",
  "shadow",
  "sunshine",
  "michael",
  "jennifer",
  "changeme",
]);

function charsetOf(pw: string): CharsetBreakdown {
  const lower = /[a-z]/.test(pw);
  const upper = /[A-Z]/.test(pw);
  const digit = /[0-9]/.test(pw);
  const symbol = /[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(pw);
  const other = /[^\x00-\x7f]/.test(pw); // non-ASCII (accents, emoji, other scripts)
  let poolSize = 0;
  if (lower) poolSize += 26;
  if (upper) poolSize += 26;
  if (digit) poolSize += 10;
  if (symbol) poolSize += 33;
  if (other) poolSize += 100; // conservative floor for non-ASCII
  return { lower, upper, digit, symbol, other, poolSize: poolSize || 1 };
}

function longestRepeatedRun(pw: string): number {
  let best = 1;
  let run = 1;
  for (let i = 1; i < pw.length; i++) {
    run = pw[i] === pw[i - 1] ? run + 1 : 1;
    if (run > best) best = run;
  }
  return best;
}

function hasSequentialRun(pw: string, minLen = 4): boolean {
  const lower = pw.toLowerCase();
  for (let i = 0; i <= lower.length - minLen; i++) {
    let ascending = true;
    let descending = true;
    for (let j = 1; j < minLen; j++) {
      const a = lower.charCodeAt(i + j - 1);
      const b = lower.charCodeAt(i + j);
      if (b - a !== 1) ascending = false;
      if (a - b !== 1) descending = false;
    }
    if (ascending || descending) return true;
  }
  return false;
}

function hasKeyboardRun(pw: string, minLen = 4): boolean {
  const lower = pw.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - minLen; i++) {
      const fwd = row.slice(i, i + minLen);
      const rev = [...fwd].reverse().join("");
      if (lower.includes(fwd) || lower.includes(rev)) return true;
    }
  }
  return false;
}

function tierFromEntropy(bits: number, patternPenalty: number): StrengthTier {
  const effective = Math.max(0, bits - patternPenalty);
  if (effective < 28) return "very-weak";
  if (effective < 40) return "weak";
  if (effective < 60) return "fair";
  if (effective < 80) return "strong";
  return "very-strong";
}

export function analyzePassword(pw: string): PasswordAnalysis {
  const length = pw.length;
  const charset = charsetOf(pw);
  const entropyBits = length > 0 ? length * Math.log2(charset.poolSize) : 0;

  const patterns: PatternFinding[] = [];
  let penalty = 0;

  const lower = pw.toLowerCase();
  const stem = lower.replace(/[\d!@#$%^&*._-]+$/, "");
  if (COMMON_PASSWORDS.has(lower)) {
    patterns.push({ id: "common", label: "Matches a widely known common password", detail: "Found in a small local list of the most-leaked passwords ever — real attackers try these first, before any brute force." });
    penalty += 40;
  } else if (stem.length >= 4 && stem !== lower && COMMON_PASSWORDS.has(stem)) {
    patterns.push({ id: "common-stem", label: `Common word ("${stem}") with digits/symbols appended`, detail: "Appending numbers or a symbol to a dictionary word is the first mutation every cracking tool tries — it does not meaningfully change how guessable the base word is." });
    penalty += 30;
  }
  const run = longestRepeatedRun(pw);
  if (run >= 3) {
    patterns.push({ id: "repeat", label: `Repeated character run (${run} in a row)`, detail: "Long runs of the same character add far less randomness than their length suggests." });
    penalty += Math.min(20, run * 2);
  }
  if (hasSequentialRun(pw)) {
    patterns.push({ id: "sequential", label: "Sequential characters (e.g. abcd, 4321)", detail: "Sequences are in every cracking wordlist's mutation rules." });
    penalty += 15;
  }
  if (hasKeyboardRun(pw)) {
    patterns.push({ id: "keyboard", label: "Keyboard-adjacent pattern (e.g. qwerty, asdf)", detail: "Adjacent-key patterns look complex but are extremely common and well known to attackers." });
    penalty += 15;
  }
  if (length > 0 && length < 8) {
    patterns.push({ id: "short", label: "Shorter than 8 characters", detail: "Short passwords have few enough possibilities that modern hardware can exhaust them quickly, especially against a fast hash." });
    penalty += 10;
  }

  const suggestions: string[] = [];
  if (length < 12) suggestions.push("Use at least 12 characters — length contributes more to strength than complexity rules.");
  if (!charset.upper || !charset.lower) suggestions.push("Mix upper and lower case.");
  if (!charset.digit) suggestions.push("Include at least one digit.");
  if (!charset.symbol) suggestions.push("Include at least one symbol.");
  if (patterns.some((p) => p.id === "common" || p.id === "common-stem")) suggestions.push("Avoid dictionary words and known common passwords entirely — use a passphrase or generator instead.");
  if (patterns.some((p) => p.id === "sequential" || p.id === "keyboard")) suggestions.push("Avoid sequential or keyboard-adjacent runs.");
  if (!suggestions.length) suggestions.push("Consider a password manager so you never need to remember or reuse this password.");

  return { length, charset, entropyBits, tier: tierFromEntropy(entropyBits, penalty), patterns, suggestions };
}

// ---------------------------------------------------------------- Generators (Web Crypto, never Math.random)

function randomIndex(max: number): number {
  const arr = new Uint32Array(1);
  // Rejection sampling avoids modulo bias.
  const limit = Math.floor(0xffffffff / max) * max;
  let v: number;
  do {
    crypto.getRandomValues(arr);
    v = arr[0];
  } while (v >= limit);
  return v % max;
}

export interface PasswordGeneratorOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

const CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};

export function generatePassword(opts: PasswordGeneratorOptions): string {
  const pools: string[] = [];
  if (opts.lower) pools.push(CHARSETS.lower);
  if (opts.upper) pools.push(CHARSETS.upper);
  if (opts.digits) pools.push(CHARSETS.digits);
  if (opts.symbols) pools.push(CHARSETS.symbols);
  if (!pools.length) throw new Error("Select at least one character set");
  const alphabet = pools.join("");
  // Guarantee at least one character from each selected pool, then fill the rest.
  const chars: string[] = pools.map((p) => p[randomIndex(p.length)]);
  while (chars.length < opts.length) chars.push(alphabet[randomIndex(alphabet.length)]);
  // Fisher-Yates shuffle so the guaranteed characters aren't always at the front.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, opts.length).join("");
}

// A short, pronounceable word list for passphrase generation (not a full
// EFF diceware list — small and curated for a good local bundle size).
export const PASSPHRASE_WORDS = [
  "anchor","autumn","badge","bamboo","banner","basil","beacon","bishop","blanket","borrow",
  "bramble","bridge","bronze","canyon","cascade","cedar","channel","charcoal","cinder","clover",
  "cobalt","comet","copper","coral","cosmic","cotton","crater","crimson","crystal","current",
  "dagger","dawn","delta","desert","dolphin","dragon","drift","ember","emerald","falcon",
  "feather","fern","flame","flint","forest","fossil","fountain","frost","garden","gecko",
  "glacier","granite","gravel","harbor","harvest","hazel","heron","hollow","hornet","hyphen",
  "iguana","indigo","island","ivory","jasper","jungle","kernel","kettle","lagoon","lantern",
  "lattice","lava","lentil","lichen","lightning","lilac","linen","lumen","lunar","magnet",
  "mango","maple","marble","marsh","meadow","mercury","meteor","mint","mirror","mist",
  "moss","mustang","nebula","nectar","needle","nimbus","nomad","oasis","obsidian","onyx",
  "opal","orbit","orchid","otter","outpost","oxygen","paddle","panther","parcel","pebble",
  "pepper","phantom","pigeon","pilot","pine","planet","plaza","polar","prairie","prism",
  "puzzle","quartz","quiver","rabbit","raven","reef","ridge","river","rocket","rooster",
  "rustic","saddle","saffron","sage","salmon","sapphire","satin","savanna","scarlet","sequoia",
  "shadow","shale","shelter","shore","signal","silver","sketch","slate","sliver","smoke",
  "sonar","sparrow","spiral","spruce","stardust","steel","stone","storm","stream","summit",
  "sunset","swan","tempest","terrace","thicket","thistle","thunder","timber","tinder","topaz",
  "torch","trellis","tundra","tunnel","turtle","tusk","umber","valley","vapor","velvet",
  "vertex","violet","vortex","voyage","walnut","warden","wasp","willow","winter","wisp",
];

export function generatePassphrase(wordCount: number, separator = "-"): string {
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) words.push(PASSPHRASE_WORDS[randomIndex(PASSPHRASE_WORDS.length)]);
  return words.join(separator);
}

/** log2 of the space this passphrase is drawn from, for an honest strength claim. */
export function passphraseEntropyBits(wordCount: number): number {
  return wordCount * Math.log2(PASSPHRASE_WORDS.length);
}
