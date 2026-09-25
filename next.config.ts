import type { NextConfig } from "next";

// Page CSP is per-request (nonce) and set in src/proxy.ts. These headers apply to every response.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  agentRules: false,
  devIndicators: false,
  // The ATT&CK dataset is read from disk at runtime rather than bundled into every function.
  outputFileTracingIncludes: {
    "/api/**": ["./src/data/attack/enterprise.json"],
    "/attack/**": ["./src/data/attack/enterprise.json"],
    "/investigations/**": ["./src/data/attack/enterprise.json"],
  },
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      { source: "/api/:path*", headers: [{ key: "Cache-Control", value: "no-store" }] },
    ];
  },
};

export default nextConfig;
