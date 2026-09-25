import { expect, test, type Page } from "@playwright/test";

// These flows use observables whose analysis is fully local (private address
// space, offline URL/hostname parsing), so they are deterministic without
// network access to intelligence providers.

async function noConsoleErrors(page: Page) {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  return errors;
}

test("shell, navigation and keyboard chords", async ({ page }) => {
  const errors = await noConsoleErrors(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "API Observatory" }).click();
  await expect(page.getByRole("heading", { name: "API Observatory" })).toBeVisible();
  await page.locator("body").press("g");
  await page.locator("body").press("a");
  await expect(page.getByRole("heading", { name: "MITRE ATT&CK" })).toBeVisible();
  expect(errors).toEqual([]);
});

test("command bar detects the type and runs a quick scan to a live workspace", async ({ page }) => {
  const errors = await noConsoleErrors(page);
  await page.goto("/");
  const input = page.getByRole("textbox", { name: "Observable to investigate" });
  await page.keyboard.press("/");
  await expect(input).toBeFocused();
  await input.fill("192.168.50.111");
  await expect(page.getByText("IPv4", { exact: true }).first()).toBeVisible();
  await input.press("Enter");
  await page.waitForURL(/\/investigations\/[a-z0-9]+/);
  await expect(page.getByRole("heading", { name: "192.168.50.111" })).toBeVisible();
  await expect(page.getByText(/Complete|Partial/).first()).toBeVisible({ timeout: 20_000 });

  // Finding → evidence → source drawer → raw.
  await page.getByRole("tab", { name: /Findings/ }).click();
  const finding = page.getByRole("button", { name: /Private-use network/ });
  await finding.click();
  await expect(page.getByText("Why it matters")).toBeVisible();
  await page.getByRole("button", { name: "Source response" }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("Normalised result")).toBeVisible();
  await drawer.getByRole("button", { name: /Show raw response/ }).click();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  // External sources were never queried for private space.
  await page.getByRole("tab", { name: /Sources/ }).click();
  await expect(page.getByText(/private address space/).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test("unrecognised input is rejected clearly", async ({ page }) => {
  await page.goto("/");
  const input = page.getByRole("textbox", { name: "Observable to investigate" });
  await input.fill("definitely not an observable");
  await expect(page.getByText("Unknown")).toBeVisible();
  await expect(page.getByRole("button", { name: "Run quick scan" })).toBeDisabled();
});

test("command palette searches ATT&CK and navigates", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog", { name: "Command palette" });
  await expect(palette).toBeVisible();
  await page.keyboard.type("T1059");
  await expect(palette.getByRole("option", { name: /Command and Scripting Interpreter/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Command and Scripting Interpreter" })).toBeVisible();
});

test("URL investigation shows structural findings and a real evidence graph", async ({ page }) => {
  await page.goto("/");
  const input = page.getByRole("textbox", { name: "Observable to investigate" });
  await input.fill("http://paypal.com@198.51.100.7/login.exe");
  await input.press("Enter");
  await page.waitForURL(/\/investigations\/[a-z0-9]+/);
  await page.getByRole("tab", { name: /Findings/ }).click();
  await expect(page.getByText("URL contains embedded credentials or userinfo")).toBeVisible({ timeout: 20_000 });
  await page.getByRole("tab", { name: /Graph/ }).click();
  await expect(page.getByLabel("Evidence graph")).toBeVisible();
});

test("observatory rows expand to show capability and auth detail without secrets", async ({ page }) => {
  await page.goto("/observatory");
  await page.getByRole("button", { name: "Expand VirusTotal" }).click();
  await expect(page.getByText("VIRUSTOTAL_API_KEY")).toBeVisible();
  const html = await page.content();
  expect(html).not.toMatch(/postgres(ql)?:\/\//);
});

test("operator unlock, then IOC extraction adds refanged indicators", async ({ page }) => {
  test.skip(!process.env.E2E_OPERATOR_TOKEN, "needs E2E_OPERATOR_TOKEN matching the server's NOPS_ADMIN_TOKEN");
  await page.goto("/settings?section=security");
  await page.getByLabel(/Operator token/).fill("wrong-token");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByText("That operator token is not valid.")).toBeVisible();
  await page.getByLabel(/Operator token/).fill(process.env.E2E_OPERATOR_TOKEN!);
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByText(/Unlocked/)).toBeVisible();

  await page.goto("/ioc");
  await page.getByRole("button", { name: "Extract from text" }).first().click();
  await page.getByRole("dialog").getByRole("textbox").first().fill("Beacon to hxxp://203[.]0.113[.]9/gate.php and CVE-2024-3400");
  await page.getByRole("button", { name: "Extract", exact: true }).click();
  await expect(page.getByRole("dialog").getByText("http://203.0.113.9/gate.php")).toBeVisible();
  await page.getByRole("button", { name: /^Add \d+/ }).click();
  await expect(page.getByRole("table").getByText("CVE-2024-3400", { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/added|updated/).first()).toBeVisible();
});

test("settings: appearance preferences persist", async ({ page }) => {
  await page.goto("/settings?section=appearance");
  await page.getByRole("radio", { name: "Compact" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-density", "compact");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-density", "compact");
  await page.getByRole("button", { name: "Reset to defaults" }).click();
});

test("security headers and CSP nonce are present", async ({ request }) => {
  const res = await request.get("/");
  const csp = res.headers()["content-security-policy"];
  expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
  expect(csp).toContain("frame-ancestors 'none'");
  expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  expect(res.headers()["x-powered-by"]).toBeUndefined();
});

test("state-changing API calls reject cross-site requests", async ({ request }) => {
  const res = await request.post("/api/investigations", { data: { observable: "8.8.8.8" }, headers: { origin: "https://evil.test", "sec-fetch-site": "cross-site" } });
  expect(res.status()).toBe(403);
  const form = await request.post("/api/investigations", { form: { observable: "8.8.8.8" } });
  expect([403, 415]).toContain(form.status());
});

test("mobile navigation and workspace @mobile", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Investigations" }).click();
  await expect(page.getByRole("heading", { name: "Investigations" })).toBeVisible();
  await page.getByRole("button", { name: "Search and investigate" }).click();
  await page.keyboard.type("10.0.0.8");
  await expect(page.getByRole("option", { name: /Quick scan/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await page.waitForURL(/\/investigations\/[a-z0-9]+/);
  await expect(page.getByRole("heading", { name: "10.0.0.8" })).toBeVisible();
});
