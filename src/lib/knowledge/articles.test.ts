import { describe, expect, it } from "vitest";
import { ARTICLES, CATEGORY_LABEL, getArticle, relatedArticles, searchArticles } from "./articles";

describe("knowledge base integrity", () => {
  it("has no duplicate slugs", () => {
    const slugs = ARTICLES.map((a) => a.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("every related slug points at a real article", () => {
    for (const a of ARTICLES) {
      for (const slug of a.related) {
        expect(getArticle(slug), `${a.slug} references missing related article "${slug}"`).toBeDefined();
      }
    }
  });

  it("every article has a known category", () => {
    for (const a of ARTICLES) {
      expect(CATEGORY_LABEL[a.category]).toBeDefined();
    }
  });

  it("every article has non-empty required sections", () => {
    for (const a of ARTICLES) {
      for (const field of ["summary", "what", "why", "how", "detection", "defence"] as const) {
        expect(a[field].length, `${a.slug}.${field}`).toBeGreaterThan(10);
      }
      expect(a.references.length, `${a.slug}.references`).toBeGreaterThan(0);
    }
  });

  it("relatedArticles resolves to real Article objects", () => {
    const a = getArticle("sql-injection")!;
    const related = relatedArticles(a);
    expect(related.length).toBe(a.related.length);
    expect(related.every((r) => typeof r.title === "string")).toBe(true);
  });

  it("searchArticles filters by query text and category", () => {
    expect(searchArticles("injection").length).toBeGreaterThan(0);
    expect(searchArticles("", "crypto").every((a) => a.category === "crypto")).toBe(true);
    expect(searchArticles("nonexistent-term-xyz").length).toBe(0);
  });
});
