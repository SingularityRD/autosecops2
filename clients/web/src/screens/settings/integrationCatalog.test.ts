import { describe, it, expect } from 'vitest'
import { getAllIntegrations } from '../../config/integrations'
import { buildCatalog } from './integrationCatalog'

describe('buildCatalog', () => {
  // SA-01: the executors the product advertises could not be connected from Add integration
  it('offers the response executors with a setup form and the Experimental label (W0.37)', () => {
    const entries = buildCatalog(getAllIntegrations(), [], new Set())
    for (const id of ['microsoft-defender', 'azure-ad', 'palo-alto']) {
      const entry = entries.find((e) => e.server === id)
      expect(entry, id).toBeDefined()
      expect(entry?.experimental, id).toBe(true)
      expect(entry?.integration?.id, id).toBe(id)
    }
  })

  it('still leaves work-in-progress servers out', () => {
    const entries = buildCatalog(getAllIntegrations(), [], new Set())
    expect(entries.find((e) => e.server === 'carbon-black')).toBeUndefined()
  })
})
