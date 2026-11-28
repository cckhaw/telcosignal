import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildPortal } from "../../scripts/build-portal.js";

// The developer portal is a documentation site, not a page: layered navigation that works without JavaScript, usable on a phone and a tablet,
// accessible, and still inside the strict content security policy (no script, no inline style, no external resource).
let dir = "";
const html = (f: string) => readFileSync(join(dir, f), "utf8");
const pages = () => readdirSync(dir).filter((f) => f.endsWith(".html"));
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), "portal-design-")); buildPortal(dir); });

describe("portal structure and navigation", () => {
  it("every page has the landmarks, skip link, one h1, the sandbox notice and a language", () => {
    for (const f of pages()) {
      const t = html(f);
      expect(t, f).toContain('<html lang="en"'); expect(t, f).toContain('name="viewport" content="width=device-width,initial-scale=1"');
      for (const tag of ["<header", "<main", "<footer", '<nav class="topnav"', '<aside class="sidebar"', 'class="skip" href="#main"', 'id="main"']) expect(t, `${f} ${tag}`).toContain(tag);
      expect(t.match(/<h1[ >]/g)?.length, f).toBe(1); expect(t, f).toContain("NOT approved for live data");
    }
  });
  it("three navigation layers: header sections, a grouped sidebar with every page, breadcrumbs and an on-page list", () => {
    for (const f of pages()) {
      const t = html(f);
      for (const s of ["Get started", "API reference", "Resources"]) expect(t, `${f} header ${s}`).toMatch(new RegExp(`<nav class="topnav"[\\s\\S]*>${s}</a>`));
      for (const p of ['href="/authentication"', 'href="/sandbox"', 'href="/signals"', 'href="/errors"', 'href="/versions"', 'href="/openapi.yaml"']) expect(t.split('<main')[0] ?? "", `${f} sidebar ${p}`).toContain(p);
      expect(t, f).toContain('aria-label="Breadcrumb"');
      if (f !== "404.html") expect((t.split('<main')[0] ?? "").match(/aria-current="page"/g)?.length, `${f} exactly one current page in the sidebar`).toBe(1);
    }
    expect(html("signals.html")).toContain('class="toc"'); expect(html("signals.html")).toContain('class="toc-inline"');
  });
  it("the mobile and tablet menu is a CSS-only drawer: a labelled checkbox, no script, no inline style", () => {
    for (const f of pages()) {
      const t = html(f);
      expect(t, f).toMatch(/<input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="[^"]+">/); expect(t, f).toContain('<label for="nav-toggle" class="menu-button">'); expect(t, f).toContain('class="scrim"');
      expect(t, f).not.toMatch(/<script|\sstyle=|\son\w+=/i);
    }
  });
  it("headings have unique ids, every on-page link and in-page anchor resolves, and no link is nested in a link", () => {
    for (const f of pages()) {
      const t = html(f);
      const ids = [...t.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]!); expect(new Set(ids).size, `${f} duplicate ids`).toBe(ids.length);
      for (const m of t.matchAll(/href="#([^"]+)"/g)) if (m[1] !== "main") expect(ids, `${f} #${m[1]}`).toContain(m[1]); else expect(ids).toContain("main");
      expect(t, f).not.toMatch(/<a [^>]*>(?:(?!<\/a>)[\s\S])*<a /);
    }
  });
  it("home page cards link to anchors that exist on the signals page, and previous/next links walk every page in order", () => {
    const sig = html("signals.html"); const home = html("index.html");
    const targets = [...home.matchAll(/href="\/signals#([^"]+)"/g)].map((m) => m[1]!); expect(targets.length).toBe(4);
    for (const id of targets) expect(sig).toContain(`id="${id}"`);
    const order = ["index.html", "authentication.html", "sandbox.html", "signals.html", "errors.html", "versions.html"];
    const url = (f: string) => (f === "index.html" ? "/" : `/${f.replace(".html", "")}`);
    order.forEach((f, i) => { const t = html(f); if (i > 0) expect(t, f).toContain(`class="prev" href="${url(order[i - 1]!)}"`); if (i < order.length - 1) expect(t, f).toContain(`class="next" href="${url(order[i + 1]!)}"`); });
  });
  it("tables carry column names on every cell (the phone layout stacks them) and scope on headers; wide tables and code scroll instead of overflowing", () => {
    for (const f of pages()) for (const tb of html(f).match(/<table>[\s\S]*?<\/table>/g) ?? []) {
      expect(tb, f).toContain('scope="col"'); const cells = tb.match(/<td /g)?.length ?? 0; expect(tb.match(/<td data-label="[^"]+">/g)?.length ?? 0, f).toBe(cells);
    }
    expect(html("errors.html")).toContain('class="table-wrap"'); expect(html("errors.html")).toContain('tabindex="0"');
  });
  it("a 404 page and an icon exist, and the icon is the only image", () => {
    expect(readdirSync(dir)).toEqual(expect.arrayContaining(["404.html", "favicon.svg"])); expect(readFileSync(join(dir, "favicon.svg"), "utf8")).not.toMatch(/<script|href=|xlink/i);
    for (const f of pages()) expect(html(f), f).not.toMatch(/<img /);
  });
});

describe("portal stylesheet", () => {
  it("is responsive for phone, tablet and desktop, respects the reader's preferences, and loads nothing external", () => {
    const css = readFileSync(join(dir, "style.css"), "utf8");
    for (const bp of ["640px", "768px", "1024px", "1280px"]) expect(css, bp).toContain(`min-width: ${bp}`);
    for (const q of ["prefers-color-scheme: dark", "prefers-reduced-motion: reduce", "@media print", ":focus-visible", "max-width: 639.98px"]) expect(css, q).toContain(q);
    expect(css).not.toMatch(/@import|url\(\s*["']?(https?:)?\/\//i); expect(css).not.toMatch(/\bexpression\(|javascript:/i);
    expect(css).toMatch(/\.nav-toggle:checked ~ \.layout \.sidebar/);
  });
});
