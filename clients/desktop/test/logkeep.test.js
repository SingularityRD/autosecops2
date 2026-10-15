// npm test (after `npm run build`): log names and retention of
// src/logkeep.ts and the support command of src/supportcmd.ts.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { openAppLog, snapshotContainerLogs } = require("../dist/logkeep.js");
const { supportCommand } = require("../dist/supportcmd.js");

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "autosecops-desktop-test-"));

// A fake child process that prints `text` and exits.
function fakeSpawn(text) {
  return () => {
    const proc = new EventEmitter();
    proc.stdout = new PassThrough();
    proc.stderr = new PassThrough();
    setImmediate(() => {
      proc.stdout.end(text);
      proc.stderr.end();
      setImmediate(() => proc.emit("close", 0));
    });
    return proc;
  };
}

test("the app log is autosecops-desktop.log and rotates", () => {
  const dir = tmp();
  openAppLog(dir)("first");
  openAppLog(dir)("second");
  assert.match(fs.readFileSync(path.join(dir, "autosecops-desktop.log"), "utf8"), /second\n$/);
  assert.match(fs.readFileSync(path.join(dir, "autosecops-desktop.log.1"), "utf8"), /first\n$/);
});

test("container snapshots are autosecops-<UTC>.log; old vigil-* ones age out", async () => {
  const logs = tmp();
  const dir = path.join(logs, "containers");
  fs.mkdirSync(dir);
  for (const f of [
    "vigil-20260101T000000Z.log",
    "vigil-20260201T000000Z.log",
    "autosecops-20260301T000000Z.log",
    "unrelated.log",
  ]) {
    fs.writeFileSync(path.join(dir, f), "x");
  }
  const file = await snapshotContainerLogs(
    fakeSpawn("container output\n"),
    [],
    logs,
    5000,
    3,
    new Date("2026-10-05T00:00:00Z"),
  );
  assert.equal(path.basename(file), "autosecops-20261005T000000Z.log");
  assert.deepEqual(fs.readdirSync(dir).sort(), [
    "autosecops-20260301T000000Z.log",
    "autosecops-20261005T000000Z.log",
    "unrelated.log",
    "vigil-20260201T000000Z.log",
  ]);
});

test("support command quotes the packaged path", () => {
  const cmd = supportCommand("/Applications/AutoSecOps.app/Contents/Resources/vigil-support");
  assert.equal(cmd, 'sh "/Applications/AutoSecOps.app/Contents/Resources/vigil-support/vigil-support.sh"');
});
