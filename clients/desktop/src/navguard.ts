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

// mailto: fields a mail client may take from a link. Everything else is
// dropped, notably attach= / attachment=, which some clients honour by
// attaching a local file to the draft.
const MAILTO_FIELDS = new Set(["to", "cc", "bcc", "subject", "body"]);

/**
 * The URL to hand to the OS, or null when it must not be opened. https URLs
 * pass unchanged; a mailto: keeps its address and the MAILTO_FIELDS only.
 */
export function externalUrl(url: string): string | null {
  const u = parse(url);
  if (u === null || !EXTERNAL_SCHEMES.has(u.protocol)) return null;
  if (u.protocol !== "mailto:") return u.href;
  const kept = new URLSearchParams();
  for (const [k, v] of new URLSearchParams(u.search)) {
    if (MAILTO_FIELDS.has(k.toLowerCase())) kept.append(k.toLowerCase(), v);
  }
  const query = kept.toString();
  return `mailto:${u.pathname}${query ? `?${query}` : ""}`;
}

/** Permission requests are granted only to the console, and only from the short list. */
export function isPermissionAllowed(permission: string, requestingUrl: string): boolean {
  return isAppUrl(requestingUrl) && GRANTED_PERMISSIONS.has(permission);
}

/* ---------------- wiring (structural types, so tests can pass fakes) ---------------- */

const CHILD_WINDOW_PREFS = { contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true };

type PreventableEvent = { preventDefault(): void };
type OpenHandlerResult =
  | { action: "deny" }
  | { action: "allow"; overrideBrowserWindowOptions: { webPreferences: typeof CHILD_WINDOW_PREFS } };

/** The parts of Electron's WebContents that hardenWebContents uses. */
export interface GuardableContents {
  on(event: "will-navigate" | "will-redirect", listener: (event: PreventableEvent, url: string) => void): unknown;
  on(event: "will-attach-webview", listener: (event: PreventableEvent) => void): unknown;
  setWindowOpenHandler(handler: (details: { url: string }) => OpenHandlerResult): void;
}

/**
 * Every window: no navigation away from the console (the splash never
 * navigates at all), new windows only for the console itself and sandboxed,
 * other links to `openExternal` (after externalUrl), never a <webview>.
 */
export function hardenWebContents(
  contents: GuardableContents,
  openExternal: (url: string) => void,
  log: (line: string) => void = () => {},
): void {
  const toOs = (url: string) => {
    const safe = externalUrl(url);
    if (safe !== null) openExternal(safe);
    else log(`blocked opening ${url.slice(0, 200)}`);
  };
  const guard = (event: PreventableEvent, url: string) => {
    if (isAppUrl(url)) return;
    event.preventDefault();
    toOs(url);
  };
  contents.on("will-navigate", guard);
  contents.on("will-redirect", guard);
  contents.on("will-attach-webview", (event) => event.preventDefault());
  contents.setWindowOpenHandler(({ url }) => {
    if (isAppUrl(url)) {
      return { action: "allow", overrideBrowserWindowOptions: { webPreferences: { ...CHILD_WINDOW_PREFS } } };
    }
    toOs(url);
    return { action: "deny" };
  });
}

/** The parts of Electron's Session that applyPermissionPolicy uses. */
export interface PermissionSession {
  setPermissionRequestHandler(
    handler: (
      wc: { getURL(): string },
      permission: string,
      callback: (granted: boolean) => void,
      details: { requestingUrl?: string },
    ) => void,
  ): void;
  setPermissionCheckHandler(handler: (wc: unknown, permission: string, requestingOrigin: string) => boolean): void;
}

/** Camera, microphone, geolocation and the rest are refused; see GRANTED_PERMISSIONS. */
export function applyPermissionPolicy(ses: PermissionSession): void {
  ses.setPermissionRequestHandler((wc, permission, callback, details) => {
    callback(isPermissionAllowed(permission, details.requestingUrl || wc.getURL()));
  });
  ses.setPermissionCheckHandler((_wc, permission, requestingOrigin) =>
    isPermissionAllowed(permission, requestingOrigin),
  );
}
