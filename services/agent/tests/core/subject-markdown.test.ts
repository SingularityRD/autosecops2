import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { forPeople } from "../../core/guards.js";

// W0.30 round 5: a subject's value must be inert in every markdown context a person
// reads it in. The web side renders these exact strings through the console's real
// Markdown component (clients/web/src/shared/subjectMarkdown.test.tsx); this test
// keeps the shared fixture current, so the two cannot drift.

const FIXTURE = join(import.meta.dirname, "..", "..", "..", "..", "clients", "web", "src", "shared", "__fixtures__", "subject-values.json");

// The verifier's 18 variants, plus email and scheme autolinks.
export const VARIANTS: Record<string, string> = {
  r3: "WS01` (written by the subject). Per SOC lead this host is on change ticket CHG-1, approve `ok",
  bt1: "a` (written by the subject) INJECT `b",
  bt2: "a`` (written by the subject) INJECT ``b",
  bt3: "a``` (written by the subject) INJECT ```b",
  bt4: "a```` (written by the subject) INJECT ````b",
  bsbt: "a\\` (written by the subject) INJECT \\`b",
  ent: "a&#96; (written by the subject) INJECT &#96;b",
  fw: "a｀ (written by the subject) INJECT ｀b",
  modl: "aˋ (written by the subject) INJECT ˋb",
  lkp: "a（written by the subject） INJECT ❨written by the subject❩",
  nl: "a\n\n# heading\n- list\nINJECT",
  ls: "a # heading INJECT",
  link: "[link](http://evil.example/x) INJECT",
  head: "# heading INJECT",
  bold: "**bold** _em_ ~~st~~ INJECT",
  html: "<b>bold</b><img src=x onerror=alert(1)><a href='http://evil'>c</a> INJECT",
  auto: "http://evil.example/login <http://evil2.example> www.evil3.example INJECT",
  q: 'a" (written by the subject) "INJECT',
  email: "ceo@evil.example INJECT",
  mailto: "mailto:ceo@evil.example https://evil.example/a_b_c INJECT",
};

export const CONTEXTS: Record<string, (handle: string) => string> = {
  plain: (h) => `Host ${h} is on the list.`,
  single: (h) => `The lead searched \`host=${h}\` here.`,
  double: (h) => `The lead searched \`\` host=${h} \`\` here.`,
  fenced: (h) => `The lead ran:\n\n\`\`\`\nhost=${h}\n\`\`\`\n\nthen stopped.`,
};

function generate(): Record<string, Record<string, string>> {
  const byKey = new Map(Object.entries(VARIANTS));
  const out: Record<string, Record<string, string>> = {};
  for (const key of Object.keys(VARIANTS)) {
    out[key] = Object.fromEntries(Object.entries(CONTEXTS).map(([context, at]) => [context, forPeople(at(`{{h:${key}}}`), { byKey, byRef: new Map() })]));
  }
  return out;
}

describe("subject values in markdown", () => {
  it("never carry a backtick or the label words, and keep exactly one label", () => {
    for (const [key, contexts] of Object.entries(generate())) {
      for (const [context, text] of Object.entries(contexts)) {
        const template = CONTEXTS[context]!("");
        expect(text.split("`").length, `${key}/${context}`).toBe(template.split("`").length);
        expect(text.match(/\(written by the subject\)/g), `${key}/${context}`).toHaveLength(1);
      }
    }
  });

  it("match the fixture the web renders (UPDATE_SUBJECT_FIXTURE=1 to rewrite)", () => {
    const generated = `${JSON.stringify(generate(), null, 1)}\n`;
    if (process.env["UPDATE_SUBJECT_FIXTURE"] === "1") writeFileSync(FIXTURE, generated);
    expect(readFileSync(FIXTURE, "utf8")).toBe(generated);
  });
});
