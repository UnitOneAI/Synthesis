import test from 'node:test';
import assert from 'node:assert/strict';
import { interfacePriorities, batchStage, reviewStageCoverage } from '../src/review-order.mjs';
import { runReviewPool } from '../src/review-pool.mjs';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

test('external scheduling distinguishes declared exposure, unknown exposure, internal context and test code', () => {
  const model = {
    evidence: [{ id: 'prod', path: 'src/api.cs' }, { id: 'test', path: 'tests/api.cs' }],
    interfaces: [
      { id: 'declared', kind: 'http-inbound', component: 'api', evidence: ['prod'] },
      { id: 'unknown', kind: 'http-inbound', component: 'other', evidence: ['prod'] },
      { id: 'control', kind: 'control', component: 'api', evidence: ['prod'] },
      { id: 'worker', kind: 'database', component: 'worker', evidence: ['prod'] },
      { id: 'test', kind: 'http-inbound', component: 'test', evidence: ['test'] },
    ],
    architecture: { records: { entities: [{ id: 'caller', type: 'external' }], flows: [{ id: 'flow', source: 'caller', target: 'api', interfaceIds: ['declared'] }] } },
  };
  const priorities = interfacePriorities(model);
  assert.deepEqual([...priorities.values()].map(v => v.stage), [0, 1, 2, 3, 4]);
  const batch = { phase: 'repository', packet: { records: [{ id: 'declared' }] } };
  assert.equal(batchStage(batch, priorities), 0);
  assert.equal(batchStage({ ...batch, phase: 'graph-neighborhood' }, priorities), 2);
  model.architecture.decisions = [{ subjectId: 'caller', state: 'rejected' }];
  assert.equal(interfacePriorities(model).get('declared').stage, 1);
  model.architecture.decisions = [];
  assert.equal(interfacePriorities(model, { entities: [{ id: 'caller', reviewState: 'stale' }], flows: model.architecture.records.flows }).get('declared').stage, 1);
  const stages = reviewStageCoverage([{ id: 'a', reviewStage: 1 }, { id: 'b', reviewStage: 1 }, { id: 'c', reviewStage: 3 }], [{ id: 'a', status: 'completed' }, { id: 'b', status: 'failed' }]);
  assert.deepEqual([stages[1].completed, stages[1].failed, stages[1].pending, stages[3].pending], [1, 1, 0, 1]);
});

test('four workers drain external stage before internal dispatch and preserve all planned work', async () => {
  const events = [];
  const items = [{ id: 0, stage: 1 }, { id: 1, stage: 1 }, { id: 2, stage: 2 }, { id: 3, stage: 3 }, { id: 4, stage: 4 }];
  const result = await runReviewPool(items, { concurrency: 4, stage: item => item.stage, run: async item => {
    events.push(`start:${item.id}`);
    await delay(item.id === 0 ? 20 : 2);
    events.push(`end:${item.id}`);
  } });
  assert.equal(result.completed, items.length);
  assert.equal(result.queued, 0);
  assert.ok(events.indexOf('start:2') > events.indexOf('end:0'));
  assert.ok(events.indexOf('start:2') > events.indexOf('end:1'));
  assert.ok(events.indexOf('start:3') > events.indexOf('end:2'));
});

test('failed priority stage holds later scope while active successes settle; continuation can finish', async () => {
  const completed = new Set(), started = [];
  const items = [0, 1, 2, 3];
  const options = { concurrency: 4, stage: item => item < 2 ? 1 : 3, shouldAdvanceStage: (_before, _after, state) => state.failed === 0 };
  const first = await runReviewPool(items, { ...options, run: async item => {
    started.push(item);
    await delay(3);
    if (item === 0) return { failed: true };
    completed.add(item);
  } });
  assert.deepEqual(started, [0, 1]);
  assert.equal(first.stopReason, 'priority-stage-incomplete');
  assert.equal(first.queued, 2);
  const second = await runReviewPool(items.filter(i => !completed.has(i)), { ...options, run: async item => { completed.add(item); } });
  assert.equal(second.completed, 3);
  assert.equal(completed.size, 4);
});

test('cancellation drains stage waiters without dispatching internal work', async () => {
  const controller = new AbortController();
  const calls = [];
  const result = await runReviewPool([0, 1, 2], { concurrency: 4, stage: i => i, signal: controller.signal, run: async i => { calls.push(i); await delay(5); controller.abort(); } });
  assert.deepEqual(calls, [0]);
  assert.equal(result.stopReason, 'cancelled');
  assert.equal(result.queued, 2);
});
