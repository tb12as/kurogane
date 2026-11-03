// run: pnpm test (node strips the types natively)
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { bytes, dur, parseDur, when } from '../app/composables/format.ts'

test('parseDur', () => {
  assert.equal(parseDur('90s'), 90_000)
  assert.equal(parseDur('1h30m'), 5_400_000)
  assert.equal(parseDur('2d'), 172_800_000)
  assert.equal(parseDur('1x'), null)
  assert.equal(parseDur(''), null)
  assert.equal(parseDur('5m junk'), null)
})

test('dur formats go nanoseconds', () => {
  assert.equal(dur(300e9), '5m')
  assert.equal(dur(7200e9), '2h')
  assert.equal(dur(45e9), '45s')
  assert.equal(dur('5m'), '5m')
})

test('when treats go zero time as never', () => {
  assert.equal(when('0001-01-01T00:00:00Z'), null)
  assert.ok(when('2026-11-03T00:00:00Z'))
})

test('bytes', () => {
  assert.equal(bytes(1536), '1.5 KB')
  assert.equal(bytes(2048, '/s'), '2.0 KB/s')
})
