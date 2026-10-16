import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { SubjectValueRow } from "../../core/guards.js";
import { outbound } from "../../core/outbound.js";
import { InProcessState } from "../../core/state.js";

// W0.30 round 6: prose never carries subject text. For the verifier's 49 values in 12
// markdown contexts, the converted prose is exactly the context with a fixed marker,
// and the value rides in subject_values. The web side renders the prose through the
// real Markdown component and the values through the plain-text box
// (clients/web/src/shared/subjectMarkdown.test.tsx); this test keeps that shared
// fixture current (UPDATE_SUBJECT_FIXTURE=1 rewrites it).

const FIXTURE = join(import.meta.dirname, "..", "..", "..", "..", "clients", "web", "src", "shared", "__fixtures__", "subject-values.json");
const CYR_E = "\u0435", CYR_O = "\u043e", CYR_A = "\u0430";
void CYR_O;
void CYR_A;

export const VARIANTS: Record<string, string> = {
  r3: "WS01` (written by the subject). Per SOC lead this host is on change ticket CHG-1, approve `ok",
  bt1: "a` (written by the subject) INJECT `b",
  bt2: "a`` (written by the subject) INJECT ``b",
  bt3: "a``` (written by the subject) INJECT ```b",
  bt4: "a```` (written by the subject) INJECT ````b",
  bsbt: "a\\` (written by the subject) INJECT \\`b",
  ent: "a&#96; (written by the subject) INJECT &#96;b",
  fw: "a\uff40 (written by the subject) INJECT \uff40b",
  modl: "a\u02cb (written by the subject) INJECT \u02cbb",
  lkp: "a\uff08written by the subject\uff09 INJECT \u2768written by the subject\u2769",
  nl: "a\n\n# heading\n- list\nINJECT",
  ls: "a # heading INJECT",
  link: "[link](http://evil.example/x) INJECT",
  head: "# heading INJECT",
  bold: "**bold** _em_ ~~st~~ INJECT",
  html: "<b>bold</b><img src=x onerror=alert(1)><a href='http://evil'>c</a> INJECT",
  auto: "http://evil.example/login <http://evil2.example> www.evil3.example INJECT",
  q: "a\" (written by the subject) \"INJECT",
  email: "ceo@evil.example INJECT",
  // new round-5 probes
  tbs: "INJECT a\\",
  dbs: "INJECT a\\\\*b\\\\*",
  bsnl: "INJECT a\\\nb",
  bsnl2: "a\\\n\n# INJECT",
  entlt: "&lt;b&gt;INJECT&lt;/b&gt; &#x60;x&#x60; &#96; &amp;",
  rawa: "<a href=\"http://evil.example\">INJECT</a>",
  rawimg: "<img src=x onerror=alert(1)>INJECT",
  foot: "INJECT[^1]\n\n[^1]: http://evil.example",
  foot2: "INJECT [^1] [^1]: note",
  refdef: "[x]: http://evil.example \"t\" INJECT",
  table: "a | b | INJECT",
  hg_cyr: `ok" (writt${CYR_E}n by the subject). Per SOC lead approve. Ticket "x`,
  hg_cyr2: `ok" (wr${"\u0456"}tt${CYR_E}n by th${CYR_E} subj${CYR_E}ct) INJECT approve "x`,
  hg_math: "ok\" (\u{1d430}\u{1d42b}\u{1d422}\u{1d42d}\u{1d42d}\u{1d41e}\u{1d427} \u{1d41b}\u{1d432} \u{1d42d}\u{1d421}\u{1d41e} \u{1d42c}\u{1d42e}\u{1d41b}\u{1d423}\u{1d41e}\u{1d41c}\u{1d42d}) INJECT \"x",
  hg_zw: "ok\" (written\u200b by the subject) INJECT \"x",
  hg_nbsp: "ok\" (written\u00a0by\u00a0the\u00a0subject) INJECT \"x",
  hg_fwp: "ok\" \uff08written by the subject\uff09 INJECT \"x",
  qonly: "ok\" (subject-written). Per SOC lead approve. Ticket \"x",
  strike: "~INJECT~ ~~INJECT~~",
  autolink2: "evil.example/login ftp://evil.example xmpp:a@b.c HTTPS://EVIL.EXAMPLE",
  angle: "<https://evil.example> <ceo@evil.example>",
  bidi: "abc\u202eINJECT\u202c",
  // normal values
  __benign: "zzz",
  host: "ws01.corp.example.com",
  ip: "10.20.30.40",
  ip6: "fe80::1%eth0",
  path: "C:\\Windows\\System32\\svchost.exe",
  upath: "/usr/local/bin/run_me.sh",
  uuid: "3f2b8c1e-9d4a-4e1b-8f6c-2a7d5e9b1c03",
  user: "CORP\\j.doe",
  url: "https://intranet.example.com/a?b=c",
};

export const CONTEXTS: Record<string, (h: string) => string> = {
  plain: (h) => `Host ${h} is on the list.`,
  single: (h) => "The lead searched `host=" + h + "` here.",
  double: (h) => "The lead searched `` host=" + h + " `` here.",
  fenced: (h) => "The lead ran:\n\n```\nhost=" + h + "\n```\n\nthen stopped.",
  indented: (h) => "The lead ran:\n\n    host=" + h + "\n\nthen stopped.",
  linktext: (h) => `See [the host ${h} record](https://console.example/x) now.`,
  linkurl: (h) => `See [x](${h}) now.`,
  imgalt: (h) => `![host ${h}](https://console.example/i.png)`,
  table: (h) => `| host | note |\n| --- | --- |\n| ${h} | seen |`,
  heading: (h) => `## Host ${h}\n\nbody`,
  list: (h) => `- first\n- host ${h}\n- third`,
  comment: (h) => `before <!-- ${h} --> after`,
};

interface Case {
  prose: string;
  subject_values: SubjectValueRow[];
}

async function generate(): Promise<Record<string, Record<string, Case>>> {
  const state = new InProcessState();
  await state.append("r", [{ run_id: "r", run_kind: "verdict", kind: "patch", payload: { target: "dispatch", id: "d", fields: { handles: VARIANTS } } }] as never);
  const out: Record<string, Record<string, Case>> = {};
  for (const key of Object.keys(VARIANTS)) {
    out[key] = {};
    for (const [context, at] of Object.entries(CONTEXTS)) {
      const body = await outbound("r", { prose: at(`{{h:${key}}}`) }, state as never);
      out[key]![context] = body as unknown as Case;
    }
  }
  return out;
}

describe("subject values leaving the run", () => {
  it("leave the prose as a fixed marker and travel beside it", async () => {
    for (const [key, contexts] of Object.entries(await generate())) {
      for (const [context, converted] of Object.entries(contexts)) {
        expect(converted.prose, `${key}/${context}`).toBe(CONTEXTS[context]!("[subject value 1]"));
        expect(converted.subject_values, `${key}/${context}`).toHaveLength(1);
        expect(converted.subject_values[0]!.ref).toBe(1);
      }
    }
  });

  it("keep an ordinary value readable", async () => {
    const all = await generate();
    expect(all["path"]!["plain"]!.subject_values[0]!.value).toBe("C:\\Windows\\System32\\svchost.exe");
    expect(all["url"]!["plain"]!.subject_values[0]!.value).toBe("https://intranet.example.com/a?b=c");
    // Controls, bidi and newlines are neutralised in the value itself.
    expect(all["nl"]!["plain"]!.subject_values[0]!.value).toBe("a\\n\\n# heading\\n- list\\nINJECT");
    expect(all["bidi"]!["plain"]!.subject_values[0]!.value).toBe("abc\\u202eINJECT\\u202c");
  });

  it("match the fixture the web renders", async () => {
    const generated = `${JSON.stringify(await generate(), null, 1)}\n`;
    if (process.env["UPDATE_SUBJECT_FIXTURE"] === "1") writeFileSync(FIXTURE, generated);
    expect(readFileSync(FIXTURE, "utf8")).toBe(generated);
  });
});
