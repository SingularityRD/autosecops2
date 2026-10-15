// Password reset copy shared by the forgot-password view and its tests.

// No mail on this server (air-gapped installs): nothing was sent, so never
// claim a link is on its way. Shown whatever the server's wording.
export const RESET_ASK_ADMIN =
  "Email isn't set up on this AutoSecOps server, so no reset link was sent. " +
  'Contact your AutoSecOps administrator: they can issue you a one-time reset link.'

// A single-sign-on-only account has no AutoSecOps password. The reply can't
// say whether the email is one (that would reveal the account), so say it here.
export const RESET_SSO_NOTE =
  'Signed in with single sign-on? Your password lives at your identity provider; ' +
  'reset it there. This form only resets AutoSecOps passwords.'
