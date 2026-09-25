export interface ParsedUrlInfo {
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  queryParams: Record<string, string>;
  fragment: string;
  isIp: boolean;
}

export function parseUrl(rawUrl: string): ParsedUrlInfo | null {
  try {
    const url = new URL(rawUrl);
    const queryParams: Record<string, string> = {};
    url.searchParams.forEach((v, k) => {
      queryParams[k] = v;
    });
    return {
      protocol: url.protocol.replace(":", ""),
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? "443" : "80"),
      pathname: url.pathname,
      queryParams,
      fragment: url.hash.replace("#", ""),
      isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) || url.hostname.includes(":"),
    };
  } catch {
    return null;
  }
}
