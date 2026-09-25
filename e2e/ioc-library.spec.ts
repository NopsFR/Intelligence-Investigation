import { test, expect } from "@playwright/test";

test("adds and removes an IOC without contacting external providers", async ({ page }) => {
  await page.goto("/ioc-library");

  const value = `198.51.100.${Math.floor(Math.random() * 254) + 1}`;
  await page.getByPlaceholder("IP, domain, URL, hash, or CVE").fill(value);
  await page.getByPlaceholder("tags (comma separated)").fill("test,e2e");
  await page.getByRole("button", { name: /Add to library/i }).click();

  await expect(page.getByText(value)).toBeVisible();
  await expect(page.getByText("test").first()).toBeVisible();

  await page.getByRole("button", { name: "Remove" }).first().click();
  await expect(page.getByText(value)).not.toBeVisible();
});
