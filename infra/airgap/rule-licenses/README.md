# Detection rule corpora: licences and attribution

`rules/<clone>.tar.gz` are unmodified snapshots of community rule
repositories, taken on the build machine (`build-bundle.sh --rules-dir`). They
are not AutoSecOps code and are not under its Apache-2.0 licence: each one
keeps its own licence. Next to each snapshot, `rules/<clone>.LICENSE` is that
repository's own licence file, copied from the clone. That file prevails over
this summary.

| Clone | Upstream | Licence |
|---|---|---|
| `sigma` | https://github.com/SigmaHQ/sigma | Detection Rule License (DRL) 1.1, full text in `DRL-1.1.md` (the repository's own `LICENSE` only links to it) |
| `security_content` | https://github.com/splunk/security_content | Apache-2.0 |
| `detection-rules` | https://github.com/elastic/detection-rules | Elastic License 2.0 |
| `Hunting-Queries-Detection-Rules` | https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules | BSD-3-Clause |

Conditions to keep in mind:

- **DRL 1.1 (Sigma).** Whoever shares the rules keeps each rule's `author`
  field, a link to the rule set and this licence. Alerts produced by a Sigma
  rule match keep the rule's author attribution.
- **Elastic License 2.0.** The rules may not be provided to third parties as a
  hosted or managed service, and licence notices may not be removed.
- **Apache-2.0 / BSD-3-Clause.** Keep the copyright and licence notices.
