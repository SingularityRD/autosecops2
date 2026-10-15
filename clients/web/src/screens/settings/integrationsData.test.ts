import { describe, it, expect } from 'vitest'
import {
  connectorSupport,
  EXPERIMENTAL_NOTE,
  EXPERIMENTAL_SERVERS,
  getIntegrationForServer,
  isExperimentalIntegration,
  MCP_CATEGORIES,
  SERVER_TO_INTEGRATION,
  WIP_SERVERS,
} from './integrationsData'

// Both Splunk servers share the descriptor id `splunk`. The self-hosted one is
// the card the Splunk REST form configures (#1113); the official one is
// configured by SPLUNK_MCP_URL and must not open that form, or an operator who
// thinks they pointed Vigil at the official MCP server has written a port-8089
// REST config instead.
describe('getIntegrationForServer', () => {
  it('opens the Splunk REST form from the self-hosted card', () => {
    const integration = getIntegrationForServer('splunk-selfhosted')
    expect(integration?.id).toBe('splunk')
    expect(integration?.fields?.length).toBeGreaterThan(0)
  })

  it('gives the official splunk card no form, even though a catalog id matches its name', () => {
    expect(getIntegrationForServer('splunk')).toBeUndefined()
  })

  it('resolves every aliased server to the integration it maps to', () => {
    for (const [server, id] of SERVER_TO_INTEGRATION) {
      expect(getIntegrationForServer(server)?.id, server).toBe(id)
    }
  })

  it('shows the self-hosted server as a Settings card', () => {
    const siem = MCP_CATEGORIES.find((c) => c.servers.includes('splunk-selfhosted'))
    expect(siem?.servers).toContain('splunk')
    expect(siem?.servers).toContain('splunk-selfhosted')
  })
})

describe('EXPERIMENTAL_SERVERS', () => {
  // a misspelt server name would silently drop the label from its card
  it('names only servers the console shows, none of them already hidden as WIP', () => {
    const shown = new Set(MCP_CATEGORIES.flatMap((c) => c.servers))
    for (const server of EXPERIMENTAL_SERVERS) {
      expect(shown.has(server), server).toBe(true)
      expect(WIP_SERVERS.has(server), server).toBe(false)
    }
  })

  it('gives each server one status: WIP and Experimental never overlap', () => {
    for (const server of EXPERIMENTAL_SERVERS) expect(connectorSupport(server)).toBe('experimental')
    for (const server of WIP_SERVERS) expect(connectorSupport(server)).toBe('wip')
    expect(connectorSupport('okta')).toBe('supported')
  })

  it('maps experimental servers to their catalog integration, but not the self-hosted Splunk form', () => {
    expect(isExperimentalIntegration('crowdstrike')).toBe(true)
    expect(isExperimentalIntegration('azure-sentinel')).toBe(true)
    expect(isExperimentalIntegration('splunk')).toBe(false)
    expect(isExperimentalIntegration('okta')).toBe(false)
  })

  it('points users at AutoSecOps support, not the upstream issue tracker', () => {
    expect(EXPERIMENTAL_NOTE).toMatch(/AutoSecOps support/)
    expect(EXPERIMENTAL_NOTE).not.toMatch(/vigil|open an issue|github/i)
  })
})

