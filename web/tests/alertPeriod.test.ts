import assert from 'node:assert/strict'
import test from 'node:test'
import { alertPeriod } from '../app/composables/alertPeriod.ts'

test('alert periods use local midnight and inclusive custom end dates', () => {
  const now = new Date(2026, 10, 25, 12, 30)
  assert.deepEqual(alertPeriod('today', '', '', now), {
    from: new Date(2026, 10, 25).toISOString(), to: now.toISOString(),
  })
  assert.deepEqual(alertPeriod('custom', '2026-11-24', '2026-11-25', now), {
    from: new Date(2026, 10, 24).toISOString(), to: new Date(2026, 10, 26).toISOString(),
  })
  for (const days of [1, 7, 30]) {
    const result = alertPeriod(String(days), '', '', now)!
    assert.equal(new Date(result.to).getTime() - new Date(result.from).getTime(), days * 86400000)
  }
  assert.equal(alertPeriod('custom', '', ''), null)
  assert.equal(alertPeriod('custom', '2026-11-26', '2026-11-24'), null)
  assert.equal(alertPeriod('custom', 'invalid', '2026-11-24'), null)
})
