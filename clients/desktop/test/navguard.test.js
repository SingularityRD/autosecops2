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
