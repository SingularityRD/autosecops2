import { getAllIntegrations } from '../../config/integrations'
import type { IntegrationMetadata } from '../../config/integrationSchema'

export const SERVER_TO_INTEGRATION = new Map(Object.entries({
  'aws-security': 'aws-security-hub',
  'elastic': 'elastic-siem',
  'splunk-selfhosted': 'splunk',
}))

export function getIntegrationForServer(serverName: string): IntegrationMetadata | undefined {
  // Both servers share descriptor id `splunk`. The official card is configured
  // by SPLUNK_MCP_URL; the name fallback would hand it the REST form.
  if (serverName === 'splunk') return undefined
  const id = SERVER_TO_INTEGRATION.get(serverName) ?? serverName
  return getAllIntegrations().find((i) => i.id === id)
}

/** How far AutoSecOps stands behind each catalogued MCP server. One map, so a
 *  server has exactly one status; a server not listed here is supported.
 *  - `wip`: not offered. Left out of Add integration; if it was already enabled
 *    it stays in the Connected table with a WIP chip.
 *  - `experimental`: offered, but never run against a live instance (no vendor
 *    instance to test on), so only the client side is covered. Every screen that
 *    enables one shows the Experimental chip, and the setup forms say why. A
 *    server leaves this status when it gains a live test, not on request. */
export type ConnectorSupport = 'supported' | 'experimental' | 'wip'

const SERVER_SUPPORT: Record<string, Exclude<ConnectorSupport, 'supported'>> = {
  'carbon-black': 'wip', 'hybrid-analysis': 'wip', 'anyrun': 'wip',
  'alienvault-otx': 'wip', 'palo-alto': 'wip',
  'slack': 'wip', 'misp': 'wip', 'ip-geolocation': 'wip', 'url-analysis': 'wip',
  'microsoft-defender': 'wip', 'azure-ad': 'wip', 'microsoft-teams': 'wip',

  'crowdstrike': 'experimental', 'sentinelone': 'experimental',
  'azure-sentinel': 'experimental', 'splunk': 'experimental',
  'gcp-secops': 'experimental', 'gcp-threat-intel': 'experimental',
  'joe-sandbox': 'experimental', 'vstrike': 'experimental',
  // no read-only call to probe (Atomic Red Team runs the operator's own runner);
  // CAPE needs a KVM host with analysis VMs
  'atomic-red-team': 'experimental', 'cape-sandbox': 'experimental',
}

export function connectorSupport(server: string): ConnectorSupport {
  return SERVER_SUPPORT[server] ?? 'supported'
}

const serversWith = (status: ConnectorSupport) =>
  new Set(Object.keys(SERVER_SUPPORT).filter((s) => SERVER_SUPPORT[s] === status))

export const WIP_SERVERS = serversWith('wip')
export const EXPERIMENTAL_SERVERS = serversWith('experimental')

/** True when a server behind this catalog integration is experimental. */
export function isExperimentalIntegration(integrationId: string): boolean {
  for (const server of EXPERIMENTAL_SERVERS) {
    if (getIntegrationForServer(server)?.id === integrationId) return true
  }
  return false
}

export const EXPERIMENTAL_NOTE =
  'Experimental: AutoSecOps has not run this connector against a live instance yet, so it may not work. ' +
  'If you use it, tell AutoSecOps support whether it worked and attach a support bundle.'

/** Card-title overrides for `prettyServerName`. Fix casing/branding here rather
 *  than renaming the server id, which is load-bearing (mcp-config.json, backend
 *  registration, persisted enabled-state store). */
export const SERVER_DISPLAY_NAMES = new Map(Object.entries({
  'gcp-scc': 'GCP Security Command Center',
  'splunk-selfhosted': 'Splunk (Self-Hosted)',
}))

interface McpCategory {
  label: string
  servers: string[]
}

/** Display categories, in order. A server matches the first category whose
    `servers` list contains it; anything unmatched lands in "Other". */
export const MCP_CATEGORIES: McpCategory[] = [
  { label: 'Internal / Platform', servers: ['security-detections'] },
  { label: 'Reference Servers', servers: ['github'] },
  { label: 'EDR / XDR', servers: ['crowdstrike', 'sentinelone', 'carbon-black', 'microsoft-defender'] },
  { label: 'SIEM / Data Lake', servers: ['splunk', 'splunk-selfhosted', 'elastic', 'opensearch', 'azure-sentinel', 'gcp-secops', 'cribl-stream'] },
  { label: 'Threat Intelligence', servers: ['virustotal', 'gcp-threat-intel', 'shodan', 'alienvault-otx', 'misp', 'firecrawl', 'cloudforce_one'] },
  { label: 'Cloud Security', servers: ['aws-security', 'gcp-scc', 'palo-alto'] },
  { label: 'Identity & Access', servers: ['okta', 'azure-ad'] },
  { label: 'Network Security', servers: ['vstrike', 'cloudflare'] },
  { label: 'Incident Management', servers: ['jira', 'pagerduty', 'slack', 'microsoft-teams'] },
  { label: 'Sandbox / Analysis', servers: ['joe-sandbox', 'hybrid-analysis', 'anyrun', 'url-analysis', 'ip-geolocation', 'cape-sandbox'] },
  { label: 'Adversary Emulation', servers: ['atomic-red-team'] },
]

export const SERVER_DESCRIPTIONS = new Map(Object.entries({
  firecrawl: 'Web search and page retrieval for an investigation. Retrieved pages are scrubbed and delimited before a model sees them — a page is data, not direction.',
  'security-detections': 'Searches across 30,000+ detection rules (Sigma, Splunk, Elastic, KQL). Powers detection gap analysis and rule recommendations.',
  github: 'Access GitHub repos, issues, PRs, and code search. Useful for looking up detection rule history, IaC configs, or creating remediation issues.',
  crowdstrike: 'Query CrowdStrike Falcon for endpoint detections, host info, and IOC management. Requires Falcon API credentials.',
  sentinelone: 'Query SentinelOne for alerts, asset inventory, and vulnerabilities via the read-only Purple AI MCP.',
  'carbon-black': 'Query VMware Carbon Black for endpoint events, process trees, and binary analysis.',
  'microsoft-defender': 'Query Microsoft Defender for Endpoint alerts, device info, and advanced hunting. May overlap with Sentinel.',
  splunk: 'The official Splunk MCP server, deployed separately from Splunk Enterprise. Configured by SPLUNK_MCP_URL in the environment, not from Settings.',
  'splunk-selfhosted': 'Run SPL searches against a self-hosted Splunk over its REST API (port 8089) for log analysis, correlation searches, and alert triage. Server URL and credentials are configured in Settings.',
  elastic: 'Query Elasticsearch and Elastic Security for logs, IOC hits, and detection alerts. Requires an Elasticsearch URL and API key or username/password.',
  opensearch: 'Query OpenSearch for logs and IOC hits, and ingest Security Analytics findings. Requires an OpenSearch URL and username/password.',
  'azure-sentinel': 'Query Microsoft Sentinel via KQL for security logs, incidents, and custom detection rules.',
  'gcp-secops': 'Query Google SecOps (Chronicle) for UDM security events, detection rules, and threat investigation.',
  'cribl-stream': 'Manage Cribl Stream data pipelines — inspect routes, check data flow, and troubleshoot ingestion.',
  virustotal: 'Look up file hashes, URLs, domains, and IPs against VirusTotal for malware and reputation data.',
  'gcp-threat-intel': 'Google Threat Intelligence (Mandiant + VirusTotal) for threat actor profiles, campaigns, and IOC enrichment.',
  shodan: 'Search Shodan for internet-exposed devices, open ports, and service banners on IPs and domains.',
  'alienvault-otx': 'Query AlienVault OTX for community-sourced threat intelligence pulses, IOCs, and threat reports.',
  misp: 'Connect to a MISP instance for threat sharing, IOC lookups, and collaborative threat intelligence.',
  'aws-security': 'AWS Security assessment covering GuardDuty, Security Hub, Inspector, and IAM Access Analyzer findings.',
  'gcp-scc': 'Google Cloud Security Command Center for cloud asset inventory, vulnerability findings, and threat detection.',
  'palo-alto': 'Query Palo Alto Networks firewalls for threat logs, traffic analysis, and IP/domain blocking.',
  okta: 'Query Okta for user authentication events, suspicious sign-ins, and identity-based threat investigation.',
  'azure-ad': 'Query Microsoft Entra ID (Azure AD) for sign-in logs, risky users, and directory lookups.',
  jira: 'Create and manage Jira issues for incident tracking, remediation tasks, and SOC workflow integration.',
  pagerduty: 'Trigger and manage PagerDuty incidents for on-call alerting and escalation during security events.',
  slack: 'Send alerts and investigation summaries to Slack channels. Enables team collaboration during incidents.',
  'microsoft-teams': 'Post alerts and case updates to Microsoft Teams channels for SOC team communication.',
  'joe-sandbox': 'Submit files and URLs to Joe Sandbox for deep malware analysis with behavioral reports.',
  'hybrid-analysis': 'Submit samples to CrowdStrike Hybrid Analysis for free automated malware analysis and IOC extraction.',
  anyrun: 'Interactive malware sandbox for real-time analysis with process monitoring and network capture.',
  'url-analysis': 'Analyze suspicious URLs for phishing indicators, redirects, and malicious content.',
  'ip-geolocation': 'Look up geographic location, ISP, and organization info for IP addresses during investigations.',
  'atomic-red-team': 'Invoke one Atomic Red Team technique against a named range. Disabled until toggled; saving config does not run the runner.',
}))

export function prettyServerName(name: string): string {
  return name
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

export const INTEGRATIONS_DESC = 'The tools AutoSecOps reads from and acts through. Secrets are encrypted and never shown again.'

export type IntegrationsTab = 'connected' | 'add' | 'custom' | 'surface'

/** `?tab=`: `servers` is the old name of Connected; anything unknown lands there. */
export function tabFromQuery(value: string | null): IntegrationsTab {
  if (value === 'servers') return 'connected'
  if (value === 'connected' || value === 'add' || value === 'custom' || value === 'surface') return value
  return 'connected'
}
