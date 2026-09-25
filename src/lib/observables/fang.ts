// Defanging conventions for sharing indicators safely. Dependency-free (client-safe).

/** Reverses common IOC defanging conventions (hxxp, [.], (dot), [at] ...). */
export function refang(input: string): string {
  return input
    .trim()
    .replace(/^h(xx|\*\*|XX)p(s?):\/\//i, "http$2://")
    .replace(/^(fxp|fxps):\/\//i, (m) => m.replace(/fx/i, "ft"))
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\{dot\}/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)|\{at\}/gi, "@")
    .replace(/\[\s*\/\s*\]/g, "/")
    .replace(/\\\./g, ".");
}

/** Makes an indicator safe to paste into reports and chat. */
export function defang(input: string): string {
  return input
    .replace(/^http(s?):\/\//i, "hxxp$1://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}
