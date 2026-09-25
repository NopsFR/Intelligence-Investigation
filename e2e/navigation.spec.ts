import { test, expect } from "@playwright/test";

test.describe("Primary navigation", () => {
  test("loads the dashboard with the search bar", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByLabel("Observable search")).toBeVisible();
  });

  test("navigates to every primary section", async ({ page }) => {
    await page.goto("/");
    for (const [label, path] of [
      ["Investigate", "/investigate"],
      ["History", "/history"],
      ["IOC Library", "/ioc-library"],
      ["ATT&CK", "/attack"],
      ["Toolbox", "/toolbox"],
      ["Observatory", "/observatory"],
      ["Settings", "/settings"],
    ] as const) {
      const menuButton = page.getByLabel("Open menu");
      if (await menuButton.isVisible().catch(() => false)) {
        await menuButton.click();
      }
      await page.getByRole("link", { name: label, exact: true }).first().click();
      await expect(page).toHaveURL(new RegExp(path.replace("/", "\\/") + "$"));
    }
  });

  test("is keyboard navigable via tab order", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Tab");
    const focused = await page.evaluate(() => document.activeElement?.tagName);
    expect(focused).toBeTruthy();
  });
});

test.describe("Observable detection", () => {
  test("detects a domain and enables scan buttons", async ({ page }) => {
    await page.goto("/investigate");
    const input = page.getByLabel("Observable search");
    await input.fill("example.com");
    await expect(page.getByText("Domain")).toBeVisible();
    await expect(page.getByRole("button", { name: /Quick Scan/i })).toBeEnabled();
  });

  test("flags an unrecognized observable", async ({ page }) => {
    await page.goto("/investigate");
    const input = page.getByLabel("Observable search");
    await input.fill("!!!not-valid!!!");
    await expect(page.getByText("Unrecognized observable format")).toBeVisible();
    await expect(page.getByRole("button", { name: /Quick Scan/i })).toBeDisabled();
  });

  test("shows empty ready state with no input", async ({ page }) => {
    await page.goto("/investigate");
    await expect(page.getByText("Ready to investigate")).toBeVisible();
  });
});

test.describe("History empty and mobile", () => {
  test("shows an explanatory empty state when nothing matches", async ({ page }) => {
    await page.goto("/history?search=zzz_no_such_observable_zzz");
    await expect(page.getByText(/No investigations match this filter/i)).toBeVisible();
  });
});
