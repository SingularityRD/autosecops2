// afterPack hook: flip the Electron fuses, then (macOS, no Developer ID) apply
// an ad-hoc signature. Runs before electron-builder's own signing step, so a
// real Developer ID / Authenticode signature, when configured, covers the
// flipped binary.
//
// Fuses (https://www.electronjs.org/docs/latest/tutorial/fuses) are flipped
// here instead of through `electronFuses` in electron-builder.yml because
// electron-builder flips those AFTER afterPack, which would break the ad-hoc
// signature applied below.
//
// Ad-hoc signature: electron-builder skips signing when no identity is
// available, which leaves the bundle carrying only Electron's linker signature:
// it identifies as "Electron", doesn't cover our Info.plist or resources, and
// fails `codesign --verify`. macOS then can't identify the app, so TCC silently
// denies protected folders (Documents/Desktop/…) without ever showing a
// permission prompt. An ad-hoc signature isn't a Developer ID — a downloaded
// copy still needs notarization to pass Gatekeeper cleanly — but it makes the
// bundle internally valid and identifiable, which is what the permission
// prompts key off.
//
// Check a build: `codesign -dv --verbose=4 AutoSecOps.app` shows
// "Signature=adhoc" here, "Authority=Developer ID Application: …" when signed;
// `spctl --assess --type execute -vv AutoSecOps.app` accepts only a notarized
// Developer ID build.
const { execFileSync } = require("child_process");
const path = require("path");

// A real identity is configured when electron-builder's signing variables are
// set (CSC_LINK / CSC_NAME, see the desktop jobs of .github/workflows/release.yml).
const hasDeveloperId = () =>
  Boolean(process.env.CSC_LINK || process.env.CSC_NAME) &&
  process.env.CSC_IDENTITY_AUTO_DISCOVERY !== "false";

async function flipFuses(context) {
  const { FuseVersion, FuseV1Options } = await import("@electron/fuses");
  await context.packager.addElectronFuses(context, {
    version: FuseVersion.V1,
    // The app never runs itself as plain Node, takes no NODE_OPTIONS and opens
    // no inspector port: none of these may be switched on from outside.
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    // Code is loaded from app.asar only, never from a loose app/ folder.
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
  });
}

exports.default = async function afterPack(context) {
  await flipFuses(context);

  if (context.electronPlatformName !== "darwin" || hasDeveloperId()) return;

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(context.appOutDir, `${appName}.app`);
  const appId = context.packager.appInfo.id;

  execFileSync(
    "codesign",
    ["--force", "--deep", "--sign", "-", "--identifier", appId, appPath],
    { stdio: "inherit" },
  );
  execFileSync("codesign", ["--verify", "--strict", appPath], { stdio: "inherit" });
  console.log(`  • ad-hoc signed ${appName}.app as ${appId}`);
};
