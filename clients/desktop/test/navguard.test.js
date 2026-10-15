// npm test (after `npm run build`): the URL and permission policy of
// src/navguard.ts, run against the compiled dist/.
const test = require("node:test");
const assert = require("node:assert/strict");
const g = require("../dist/navguard.js");

test("only the local backend origin counts as the app", () => {
  assert.equal(g.isAppUrl("http://127.0.0.1:6987/"), true);
  assert.equal(g.isAppUrl("http://127.0.0.1:6987/cases/1?x=1#y"), true);
  // A prefix match would accept these; the origin check must not.
  assert.equal(g.isAppUrl("http://127.0.0.1:6987.evil.example/"), false);
  assert.equal(g.isAppUrl("http://127.0.0.1:69870/"), false);
  assert.equal(g.isAppUrl("http://127.0.0.1:6987@evil.example/"), false);
  assert.equal(g.isAppUrl("https://127.0.0.1:6987/"), false);
  assert.equal(g.isAppUrl("http://localhost:6987/"), false);
  assert.equal(g.isAppUrl("file:///etc/passwd"), false);
  assert.equal(g.isAppUrl("not a url"), false);
});

test("only https and mailto reach the OS", () => {
  assert.equal(g.isExternalAllowed("https://docs.example.com/x"), true);
  assert.equal(g.isExternalAllowed("mailto:soc@example.com"), true);
  for (const bad of [
    "http://example.com/",
    "file:///Applications/Calculator.app",
    "smb://host/share",
    "javascript:alert(1)",
    "x-apple.systempreferences:com.apple.preference.security",
    "ms-msdt:/id",
    "vscode://file/etc/passwd",
    "",
    "::",
  ]) {
    assert.equal(g.isExternalAllowed(bad), false, bad);
  }
});

test("permissions: short list, console only", () => {
  assert.equal(g.isPermissionAllowed("clipboard-sanitized-write", "http://127.0.0.1:6987/"), true);
  assert.equal(g.isPermissionAllowed("notifications", "http://127.0.0.1:6987/alerts"), true);
  assert.equal(g.isPermissionAllowed("media", "http://127.0.0.1:6987/"), false);
  assert.equal(g.isPermissionAllowed("geolocation", "http://127.0.0.1:6987/"), false);
  assert.equal(g.isPermissionAllowed("notifications", "https://evil.example/"), false);
  assert.equal(g.isPermissionAllowed("notifications", ""), false);
});

test("mailto keeps the address and plain fields, drops attach and the rest", () => {
  assert.equal(g.externalUrl("https://docs.example.com/a?b=1"), "https://docs.example.com/a?b=1");
  assert.equal(g.externalUrl("mailto:soc@example.com"), "mailto:soc@example.com");
  const out = g.externalUrl("mailto:soc@example.com?subject=Hi&attach=/etc/passwd&Attachment=x&body=b&x-foo=1");
  assert.equal(out, "mailto:soc@example.com?subject=Hi&body=b");
  assert.equal(g.externalUrl("file:///etc/passwd"), null);
  assert.equal(g.externalUrl("not a url"), null);
});

// A fake WebContents recording the handlers hardenWebContents installs.
function fakeContents() {
  const handlers = {};
  return {
    handlers,
    on(name, fn) {
      handlers[name] = fn;
    },
    setWindowOpenHandler(fn) {
      handlers.open = fn;
    },
  };
}
const fakeEvent = () => ({ prevented: false, preventDefault() { this.prevented = true; } });

test("hardenWebContents: navigation, redirects, new windows, webviews", () => {
  const c = fakeContents();
  const opened = [];
  g.hardenWebContents(c, (u) => opened.push(u));
  for (const name of ["will-navigate", "will-redirect"]) {
    const inApp = fakeEvent();
    c.handlers[name](inApp, "http://127.0.0.1:6987/cases");
    assert.equal(inApp.prevented, false, name);
    const away = fakeEvent();
    c.handlers[name](away, "https://evil.example/");
    assert.equal(away.prevented, true, name);
    const file = fakeEvent();
    c.handlers[name](file, "file:///etc/passwd");
    assert.equal(file.prevented, true, name);
  }
  const wv = fakeEvent();
  c.handlers["will-attach-webview"](wv);
  assert.equal(wv.prevented, true);
  const allow = c.handlers.open({ url: "http://127.0.0.1:6987/x" });
  assert.equal(allow.action, "allow");
  assert.deepEqual(allow.overrideBrowserWindowOptions.webPreferences, {
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webSecurity: true,
  });
  assert.deepEqual(c.handlers.open({ url: "http://127.0.0.1:6987.evil.example/" }), { action: "deny" });
  assert.deepEqual(c.handlers.open({ url: "smb://host/share" }), { action: "deny" });
  assert.deepEqual(c.handlers.open({ url: "mailto:a@b.c?attach=/x" }), { action: "deny" });
  // Only https/mailto reached the OS, the mailto without attach.
  // http: is not handed to the OS, so the look-alike origin opens nothing.
  assert.deepEqual(opened, ["https://evil.example/", "https://evil.example/", "mailto:a@b.c"]);
});

test("applyPermissionPolicy: the session handlers call the policy", () => {
  const ses = {};
  g.applyPermissionPolicy({
    setPermissionRequestHandler(fn) { ses.request = fn; },
    setPermissionCheckHandler(fn) { ses.check = fn; },
  });
  const ask = (perm, requestingUrl, pageUrl = "http://127.0.0.1:6987/") => {
    let granted;
    ses.request({ getURL: () => pageUrl }, perm, (v) => { granted = v; }, { requestingUrl });
    return granted;
  };
  assert.equal(ask("notifications", "http://127.0.0.1:6987/"), true);
  assert.equal(ask("clipboard-sanitized-write", "http://127.0.0.1:6987/"), true);
  assert.equal(ask("media", "http://127.0.0.1:6987/"), false);
  assert.equal(ask("geolocation", "http://127.0.0.1:6987/"), false);
  assert.equal(ask("notifications", "https://evil.example/"), false);
  // No requestingUrl: falls back to the page URL.
  assert.equal(ask("notifications", "", "https://evil.example/"), false);
  assert.equal(ask("notifications", "", "http://127.0.0.1:6987/"), true);
  assert.equal(ses.check(null, "media", "http://127.0.0.1:6987"), false);
  assert.equal(ses.check(null, "notifications", "http://127.0.0.1:6987"), true);
  assert.equal(ses.check(null, "notifications", "https://evil.example"), false);
});
