'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store, recoverLoadedState } = require('../src/store');

const NOW = '2026-10-06T00:00:00.000Z';

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
}

function freshState() {
  return { version: 1, domains: {} };
}

function makeDomain(state, keys, threshold) {
  const { state: s2, result } = rotation.createDomain(
    state,
    { name: '测试域', publicKeys: keys.map((k) => k.publicKey), threshold },
    NOW,
  );
  return { state: s2, domain: result };
}

test('密钥集校验：排序、去重、数量与门限边界', () => {
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64); // 大写应归一化
  const c = 'c'.repeat(64);
  const { keys, threshold } = rotation.validateKeySet([c, a, b], 2);
  assert.deepEqual(keys, ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]);
  assert.equal(threshold, 2);

  assert.throws(() => rotation.validateKeySet([a, a], 1), /重复/);
  assert.throws(() => rotation.validateKeySet([a], 1), (e) => e.code === 'invalid_key_set');
  assert.throws(() => rotation.validateKeySet([a, b, c, 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)], 1), /2–5/);
  assert.throws(() => rotation.validateKeySet([a, 'zz'.repeat(32)], 1), /十六进制/);
  assert.throws(() => rotation.validateKeySet([a, b], 0), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 3), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 1.5), (e) => e.code === 'invalid_threshold');
});

test('检查点摘要与授权消息：规范化、确定性、与输入顺序无关', () => {
  const base = {
    domainId: 'dom-1',
    rotationId: 'rot-1',
    parentDigest: '0'.repeat(64),
    generation: 1,
    threshold: 2,
    keys: rotation.sortKeys(['b'.repeat(64), 'a'.repeat(64)]),
  };
  const same = { ...base, keys: rotation.sortKeys(['a'.repeat(64), 'b'.repeat(64)]) };
  assert.equal(rotation.checkpointDigest(base), rotation.checkpointDigest(same));
  assert.match(rotation.checkpointDigest(base), /^[0-9a-f]{64}$/);

  const message = rotation.authorizationMessage(base);
  assert.ok(message.includes('parent=' + '0'.repeat(64)));
  assert.ok(message.includes('keys=' + 'a'.repeat(64) + ',' + 'b'.repeat(64)));
  // 任一字段变化都会改变待签消息（篡改载荷必然验签失败）。
  assert.notEqual(rotation.authorizationMessage({ ...base, threshold: 3 }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, rotationId: 'rot-2' }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, parentDigest: '1'.repeat(64) }), message);
});

test('创建设备域：创世检查点立即激活并成为链头', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  assert.equal(domain.generation, 0);
  assert.equal(domain.headDigest, Object.keys(domain.checkpoints)[0]);
  const genesis = domain.checkpoints[domain.headDigest];
  assert.equal(genesis.status, 'activated');
  assert.equal(genesis.parentDigest, '0'.repeat(64));
  assert.deepEqual(genesis.keys, rotation.sortKeys(keys.map((k) => k.publicKey)));
  assert.ok(state.domains[domain.id]);
});

test('创建轮换：错误父摘要被拒且不改变状态；同标识幂等；冲突载荷被拒', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  const next = [genKey(), genKey()];

  assert.throws(
    () => rotation.createRotation(state, domain.id, { rotationId: 'r1', parentDigest: 'f'.repeat(64), publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );

  const input = { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 };
  const first = rotation.createRotation(state, domain.id, input, NOW);
  assert.equal(first.result.created, true);
  assert.equal(first.result.rotation.generation, 1);
  assert.equal(first.result.rotation.parentDigest, domain.headDigest);

  const again = rotation.createRotation(first.state, domain.id, input, NOW + 'x');
  assert.equal(again.result.created, false);
  assert.equal(again.state, first.state, '幂等创建不应改变状态');

  assert.throws(
    () => rotation.createRotation(first.state, domain.id, { ...input, threshold: 1 }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );
});

test('签名提交：非成员、篡改载荷、重复签名均被拒且不改变状态', () => {
  const members = [genKey(), genKey()];
  const outsider = genKey();
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const created = rotation.createRotation(
    state,
    domain.id,
    { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const rot = created.result.rotation;
  const message = rotation.authorizationMessage(rot);

  // 非父密钥成员
  const notMember = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: outsider.publicKey, signature: sign(outsider.privateKey, message) }],
    NOW,
  );
  assert.equal(notMember.result.results[0].code, 'not_parent_member');
  assert.equal(notMember.state, created.state);

  // 篡改载荷：签的是别的消息
  const tampered = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message + '\nextra=1') }],
    NOW,
  );
  assert.equal(tampered.result.results[0].code, 'invalid_signature');
  assert.equal(tampered.state, created.state);

  // 合法签名被接受
  const one = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(one.result.results[0].status, 'accepted');
  assert.equal(one.result.activated, false);
  assert.equal(one.result.signers, 1);

  // 重传同一签名 → 重复拒因，状态不变
  const dup = rotation.submitSignatures(
    one.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(dup.result.results[0].code, 'duplicate_signature');
  assert.equal(dup.state, one.state);

  // 同批内重复也只计一次
  const sameBatch = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
    ],
    NOW,
  );
  assert.equal(sameBatch.result.results[0].status, 'accepted');
  assert.equal(sameBatch.result.results[1].code, 'duplicate_signature');
  assert.equal(sameBatch.result.signers, 1);
});

test('达到父门限即激活：链头前进、证据完整、竞争候选被取代、迟到签名被拒', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const nextA = [genKey(), genKey()];
  const nextB = [genKey(), genKey(), genKey()];

  const s1 = rotation.createRotation(state, domain.id, { rotationId: 'win', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const s2 = rotation.createRotation(s1, domain.id, { rotationId: 'lose', parentDigest: domain.headDigest, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 }, NOW).state;

  const rotWin = s2.domains[domain.id].rotations.win;
  const msgWin = rotation.authorizationMessage(rotWin);
  const rotLose = s2.domains[domain.id].rotations.lose;
  const msgLose = rotation.authorizationMessage(rotLose);

  // 两个候选各收一票（竞争提交进行中）
  const s3 = rotation.submitSignatures(s2, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW).state;
  const s4 = rotation.submitSignatures(s3, domain.id, 'lose', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgLose) }], NOW).state;

  // win 达到门限 → 激活；lose 在同一迁移中被取代
  const done = rotation.submitSignatures(s4, domain.id, 'win', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgWin) }], NOW);
  assert.equal(done.result.activated, true);
  const after = done.state.domains[domain.id];
  assert.equal(after.headDigest, rotWin.digest);
  assert.equal(after.generation, 1);
  assert.deepEqual(after.keys, rotWin.keys);
  const headCp = after.checkpoints[after.headDigest];
  assert.equal(headCp.evidence.length, 2);
  assert.deepEqual(headCp.evidence.map((e) => e.publicKey).sort(), members.map((m) => m.publicKey).sort());
  assert.equal(after.rotations.lose.status, 'superseded');
  assert.match(after.rotations.lose.rejectedReason, /取代/);

  // 迟到的签名（激活后补签）被拒，链头不变
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW),
    (e) => e.code === 'rotation_already_activated',
  );
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'lose', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgLose) }], NOW),
    (e) => e.code === 'rotation_superseded',
  );
  assert.equal(done.state.domains[domain.id].headDigest, rotWin.digest);

  // 激活后用旧父摘要创建竞争候选 → 错误父摘要
  assert.throws(
    () => rotation.createRotation(done.state, domain.id, { rotationId: 'late', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );
});

test('持久化：提交后重载状态一致；并发补签只收敛为一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-store-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '并发域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW));
  const rot = store.state.domains[domain.id].rotations.r1;
  const message = rotation.authorizationMessage(rot);

  // 并发提交两批签名 + 两批重传（乱序到达的补签与重传）
  const batch = (m) => [{ publicKey: m.publicKey, signature: sign(m.privateKey, message) }];
  const outcomes = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
  ]);
  const fulfilled = outcomes.filter((o) => o.status === 'fulfilled').map((o) => o.value);
  const rejected = outcomes.filter((o) => o.status === 'rejected').map((o) => o.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '恰好一次提交触发激活');
  for (const late of rejected) assert.equal(late.code, 'rotation_already_activated', '激活后的重传应被拒');
  for (const f of fulfilled) {
    if (!f.activated) assert.ok(f.results.every((r) => r.status === 'rejected' || f.signers <= 2));
  }
  const finalDomain = store.state.domains[domain.id];
  assert.equal(finalDomain.headDigest, rot.digest);
  assert.equal(finalDomain.rotations.r1.signatures.length, 2, '重传被去重，仅两名签名者');
  assert.equal(finalDomain.checkpoints[rot.digest].evidence.length, 2);

  // 重载（模拟重启）后链头、检查点、证据完全一致
  const reloaded = new Store(file);
  reloaded.load();
  assert.deepEqual(reloaded.state, store.state);
  assert.ok(!fs.existsSync(`${file}.tmp`), '原子提交不残留临时文件');
});

test('持久化：竞争候选并发达标，磁盘上只有一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-race-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '竞争域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  for (const rid of ['race-1', 'race-2']) {
    const keys = [genKey(), genKey()];
    await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: rid, parentDigest: domain.headDigest, publicKeys: keys.map((k) => k.publicKey), threshold: 2 }, NOW));
  }
  const dom = () => store.state.domains[domain.id];
  const msg = (rid) => rotation.authorizationMessage(dom().rotations[rid]);
  const fullBatch = (rid) => members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, msg(rid)) }));

  const results = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-1', fullBatch('race-1'), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-2', fullBatch('race-2'), NOW)),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const rejected = results.filter((r) => r.status === 'rejected').map((r) => r.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '只有一个候选激活');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].code, 'rotation_superseded');

  const finalDomain = dom();
  const activated = Object.values(finalDomain.rotations).filter((r) => r.status === 'activated');
  assert.equal(activated.length, 1);
  assert.equal(finalDomain.headDigest, activated[0].digest);
  assert.equal(Object.values(finalDomain.checkpoints).filter((c) => c.generation === 1).length, 1, '同代次只有一个活动检查点');
});

/** 通过纯领域函数完成一整轮轮换（按父门限逐批签名），返回新状态。 */
function rotateOnce(state, domainId, parentKeys, nextKeys, newThreshold, rotationId) {
  const before = state.domains[domainId];
  let s = rotation.createRotation(
    state,
    domainId,
    { rotationId, parentDigest: before.headDigest, publicKeys: nextKeys.map((k) => k.publicKey), threshold: newThreshold },
    NOW,
  ).state;
  const rot = s.domains[domainId].rotations[rotationId];
  const message = rotation.authorizationMessage(rot);
  for (const member of parentKeys.slice(0, before.threshold)) {
    s = rotation.submitSignatures(
      s,
      domainId,
      rotationId,
      [{ publicKey: member.publicKey, signature: sign(member.privateKey, message) }],
      NOW,
    ).state;
  }
  if (s.domains[domainId].headDigest !== rot.digest) {
    throw new Error(`测试轮换 ${rotationId} 未激活：父门限签名不足`);
  }
  return s;
}

test('多代轮换：每代摘要/父摘要连续，重启后中间代检查点与证据完整保留', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-chain-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const g0 = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '多代域', publicKeys: g0.map((m) => m.publicKey), threshold: 2 }, NOW));
  const g1 = [genKey(), genKey()];
  const g2 = [genKey(), genKey(), genKey()];
  const g3 = [genKey(), genKey()];

  await store.commit((s) => ({ state: rotateOnce(s, domain.id, g0, g1, 2, 'rot-gen1') }));
  await store.commit((s) => ({ state: rotateOnce(s, domain.id, g1, g2, 3, 'rot-gen2') }));
  await store.commit((s) => ({ state: rotateOnce(s, domain.id, g2.slice(0, 3), g3, 2, 'rot-gen3') }));

  const before = store.state.domains[domain.id];
  const chain = Object.values(before.checkpoints).sort((a, b) => a.generation - b.generation);
  assert.equal(chain.length, 4, '内存中应有创世 + 三代已激活检查点');
  assert.equal(before.generation, 3);
  for (let i = 1; i < chain.length; i += 1) {
    assert.equal(chain[i].generation, i);
    assert.equal(chain[i].parentDigest, chain[i - 1].digest, `第 ${i} 代父摘要必须指向上一代摘要`);
    assert.equal(rotation.checkpointDigest(chain[i]), chain[i].digest);
  }
  assert.equal(before.headDigest, chain[3].digest);

  // 重启加载：完整授权链逐代保留，证据一份不丢。
  const reloaded = new Store(file);
  reloaded.load();
  const after = reloaded.state.domains[domain.id];
  assert.equal(Object.keys(after.checkpoints).length, 4, '重启后中间代检查点不得被压缩丢弃');
  const reloadedChain = Object.values(after.checkpoints).sort((a, b) => a.generation - b.generation);
  reloadedChain.forEach((cp, i) => {
    assert.equal(cp.digest, chain[i].digest, `第 ${i} 代摘要重启后不一致`);
    assert.equal(cp.parentDigest, chain[i].parentDigest);
    assert.deepEqual(cp.keys, chain[i].keys);
    assert.equal(cp.threshold, chain[i].threshold);
    assert.equal(cp.evidence.length, chain[i].evidence.length);
  });
  assert.deepEqual(reloaded.state, store.state);

  // 第二次重启必须幂等（恢复逻辑不得反复改写完好状态）。
  const reloadedAgain = new Store(file);
  reloadedAgain.load();
  assert.deepEqual(reloadedAgain.state, store.state);

  // 旧缺陷版本（仅保留创世与链头）造成的受损状态，在读取时安全恢复：
  // 中间两代检查点连同其证据被压缩丢弃，但已激活轮换记录仍在。
  const damaged = JSON.parse(JSON.stringify(store.state));
  const dom = damaged.domains[domain.id];
  const headDigest = dom.headDigest;
  const only0 = Object.values(dom.checkpoints).find((c) => c.generation === 0);
  dom.checkpoints = { [only0.digest]: only0, [headDigest]: dom.checkpoints[headDigest] };
  const { state: healed, changed } = recoverLoadedState(damaged);
  assert.equal(changed, true, '受损状态应触发恢复');
  const healedDomain = healed.domains[domain.id];
  assert.equal(Object.keys(healedDomain.checkpoints).length, 4, '两代中间检查点应全部重建');
  assert.equal(healedDomain.headDigest, headDigest, '恢复不得改变活动链头');
  const healedChain = Object.values(healedDomain.checkpoints).sort((a, b) => a.generation - b.generation);
  healedChain.forEach((cp, i) => {
    assert.equal(cp.digest, chain[i].digest, `恢复出的第 ${i} 代摘要必须与真实链一致`);
    assert.equal(cp.evidence.length, chain[i].evidence.length);
  });

  // 磁盘上已被旧版本写坏的 state.json（只含创世与链头）也必须在 load() 时修复并落盘。
  const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
  const diskDomain = onDisk.domains[domain.id];
  diskDomain.checkpoints = { [only0.digest]: only0, [headDigest]: diskDomain.checkpoints[headDigest] };
  fs.writeFileSync(file, JSON.stringify(onDisk, null, 2) + '\n');
  const healedStore = new Store(file);
  healedStore.load();
  assert.equal(Object.keys(healedStore.state.domains[domain.id].checkpoints).length, 4);
  const persisted = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(Object.keys(persisted.domains[domain.id].checkpoints).length, 4, '恢复结果必须原子落盘');
  assert.equal(persisted.domains[domain.id].headDigest, headDigest);
});

test('多代轮换：3-of-3 门限下每个非创世检查点恰有三份证据且重启可验', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-3of3-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const g0 = [genKey(), genKey(), genKey()];
  const g1 = [genKey(), genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '三门限域', publicKeys: g0.map((m) => m.publicKey), threshold: 3 }, NOW));
  await store.commit((s) => ({ state: rotateOnce(s, domain.id, g0, g1, 3, 'rot-a') }));
  await store.commit((s) => ({ state: rotateOnce(s, domain.id, g1, g0, 3, 'rot-b') }));

  const chain = Object.values(store.state.domains[domain.id].checkpoints).sort((a, b) => a.generation - b.generation);
  assert.equal(chain.length, 3);
  for (const cp of chain.slice(1)) {
    assert.equal(cp.evidence.length, 3, '非创世检查点应恰有父门限份证据');
    assert.equal(new Set(cp.evidence.map((e) => e.publicKey)).size, 3);
  }

  const reloaded = new Store(path.join(dir, 'state.json'));
  reloaded.load();
  assert.deepEqual(reloaded.state, store.state);
});

test('恢复安全：待签/已拒候选不得伪造历史；篡改证据与断链拒绝加载', () => {
  const members = [genKey(), genKey()];
  const next = [genKey(), genKey()];
  const { state: s0, domain } = makeDomain(freshState(), members, 2);
  const s1 = rotation.createRotation(
    s0, domain.id,
    { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  ).state;
  const rot = s1.domains[domain.id].rotations.r1;
  const message = rotation.authorizationMessage(rot);
  const one = rotation.submitSignatures(
    s1, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  ).state;

  // 待签候选（只有 1/2 份签名）不得被恢复成检查点。
  const { changed: pendingNoChange } = recoverLoadedState(JSON.parse(JSON.stringify(one)));
  assert.equal(pendingNoChange, false);
  assert.equal(Object.keys(one.domains[domain.id].checkpoints).length, 1);

  // 已拒（取代）候选同样不得写入历史。
  const rejected = JSON.parse(JSON.stringify(one));
  rejected.domains[domain.id].rotations.r1.status = 'superseded';
  assert.doesNotThrow(() => recoverLoadedState(rejected));
  assert.equal(Object.keys(rejected.domains[domain.id].checkpoints).length, 1);

  // 真正激活的状态作为对照。
  const done = rotation.submitSignatures(
    one, domain.id, 'r1',
    [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, message) }],
    NOW,
  ).state;
  assert.equal(Object.keys(done.domains[domain.id].checkpoints).length, 2);

  // 篡改证据签名 → 直接拒绝加载。
  const tampered = JSON.parse(JSON.stringify(done));
  const head = tampered.domains[domain.id].headDigest;
  tampered.domains[domain.id].checkpoints[head].evidence[0].signature = flipHexLocal(
    tampered.domains[domain.id].checkpoints[head].evidence[0].signature,
  );
  assert.throws(() => recoverLoadedState(tampered), /验签|复核/);

  // 模拟中间代被压缩丢弃，且已激活轮换记录的证据也损坏 → 拒绝伪造恢复。
  const damaged = JSON.parse(JSON.stringify(done));
  const d = damaged.domains[domain.id];
  const genesis = Object.values(d.checkpoints).find((c) => c.generation === 0);
  d.checkpoints = { [genesis.digest]: genesis };
  d.headDigest = genesis.digest;
  d.rotations.r1.signatures[1].signature = flipHexLocal(d.rotations.r1.signatures[1].signature);
  assert.throws(() => recoverLoadedState(damaged), /验签/);

  // 链头不指向链末端也必须拒绝启动。
  const brokenHead = JSON.parse(JSON.stringify(done));
  brokenHead.domains[domain.id].headDigest = genesis.digest;
  assert.throws(() => recoverLoadedState(brokenHead), /链头/);
});

function flipHexLocal(hex) {
  const last = hex.slice(-1);
  return hex.slice(0, -1) + (last === '0' ? '1' : '0');
}
