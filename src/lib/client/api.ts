export class ApiClientError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

/** Same-origin JSON fetch. Error bodies ({ error: { code, message } }) become ApiClientError. */
export async function api<T>(path: string, init: RequestInit & { body?: BodyInit | null; json?: unknown } = {}): Promise<T> {
  const { json, headers, ...rest } = init;
  let res: Response;
  try {
    res = await fetch(path, {
      ...rest,
      credentials: "same-origin",
      headers: { ...(json !== undefined ? { "content-type": "application/json" } : {}), accept: "application/json", ...(headers ?? {}) },
      body: json !== undefined ? JSON.stringify(json) : rest.body,
    });
  } catch {
    throw new ApiClientError("Network error — the server could not be reached.", 0, "network");
  }
  const text = await res.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!res.ok) {
    const err = (body as { error?: { code?: string; message?: string } } | undefined)?.error;
    throw new ApiClientError(err?.message ?? `Request failed (HTTP ${res.status})`, res.status, err?.code ?? "http-error");
  }
  return body as T;
}
