// What the windows may load, and what may be handed to the OS. Deliberately
// free of `electron` imports so it can be exercised from a plain node script
// (test/navguard.test.js).
//
// The main window shows the web console served by the local backend. Anything
// else it tries to open (a link, a redirect, window.open) is either the
// console itself or goes to the system browser, never into an app window, and
// only for schemes that cannot launch a local program.

export const BACKEND_URL = "http://127.0.0.1:6987";
const BACKEND_ORIGIN = new URL(BACKEND_URL).origin;

// Schemes the OS may open for a URL that came from web content. file:, smb:,
// custom app protocols and the like can start programs or mount shares, so a
// compromised or confused page must not be able to reach them.
const EXTERNAL_SCHEMES = new Set(["https:", "mailto:"]);

// Permissions the console uses (copy buttons, browser notifications for new
// alerts). Everything else (camera, microphone, geolocation, MIDI, HID, ...)
// is refused.
const GRANTED_PERMISSIONS = new Set(["clipboard-sanitized-write", "notifications", "fullscreen"]);

function parse(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** True when `url` belongs to the local backend (same scheme, host and port). */
export function isAppUrl(url: string): boolean {
  const u = parse(url);
  return u !== null && u.origin === BACKEND_ORIGIN;
}

/** True when a URL that came from web content may be passed to shell.openExternal. */
export function isExternalAllowed(url: string): boolean {
  const u = parse(url);
  return u !== null && EXTERNAL_SCHEMES.has(u.protocol);
}

/** Permission requests are granted only to the console, and only from the short list. */
export function isPermissionAllowed(permission: string, requestingUrl: string): boolean {
  return isAppUrl(requestingUrl) && GRANTED_PERMISSIONS.has(permission);
}
