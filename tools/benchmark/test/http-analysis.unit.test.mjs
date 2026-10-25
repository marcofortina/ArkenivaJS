import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pairedComparison, runOrder, quantile } from '../http-analysis.mjs';

test('Confidence analysis preserves repeat pairing and exposes inadequate evidence', () => {
  const baseline = [1, 10, 100, 1000, 10000];
  const result = pairedComparison(
    baseline,
    baseline.map((value) => value * 1.1),
  );
  assert.ok(Math.abs(result.meanChangePercent - 10) < 1e-10);
  for (const bound of result.confidence95Percent) assert.ok(Math.abs(bound - 10) < 1e-10);
  assert.equal(result.releaseGate, false);
  assert.equal(pairedComparison([1], [2]).sufficientlyRepeated, false);
  assert.equal(quantile([1, 3], 0.5), 2);
  assert.throws(() => pairedComparison([0], [1]));
  assert.throws(() => pairedComparison([1], [1, 2]));
});
test('Run randomization includes all four modes in each independent repeat', () => {
  const order = runOrder(5, 137);
  assert.deepEqual(order, runOrder(5, 137));
  assert.notDeepEqual(order, runOrder(5, 138));
  for (let repeat = 1; repeat <= 5; repeat++)
    assert.deepEqual(
      order
        .filter((row) => row.repeat === repeat)
        .map((row) => row.mode)
        .sort(),
      ['BASELINE', 'DETAILED', 'FRAMEWORK', 'STANDARD'],
    );
});
