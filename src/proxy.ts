import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, verifySession } from "@/lib/server/session";

// Per-request CSP nonce for pages, and (when NOPS_PRIVATE=1) an operator
// session requirement for everything except the unlock flow and health probe.

const PUBLIC_WHEN_PRIVATE = [/^\/unlock$/, /^\/api\/session$/, /^\/api\/health$/];

function contentSecurityPolicy(nonce: string): string {
  const dev = process.env.NODE_ENV === "development";
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    // Inline style attributes are needed by React and the graph renderer; scripts stay nonce-locked.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "manifest-src 'self'",
    "worker-src 'self' blob:",
    ...(dev ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");
}

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isApi = pathname.startsWith("/api/");

  if (process.env.NOPS_PRIVATE === "1" && !PUBLIC_WHEN_PRIVATE.some((re) => re.test(pathname))) {
    if (!verifySession(request.cookies.get(SESSION_COOKIE)?.value)) {
      if (isApi) return NextResponse.json({ error: { code: "operator-required", message: "This deployment is private. Unlock it with the operator token." } }, { status: 401 });
      const url = request.nextUrl.clone();
      url.pathname = "/unlock";
      url.search = pathname === "/" ? "" : `?next=${encodeURIComponent(pathname)}`;
      return NextResponse.redirect(url);
    }
  }

  if (isApi) return NextResponse.next();

  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = contentSecurityPolicy(nonce);
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!_next/static|_next/image|icon.svg|favicon.ico|fonts/).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
