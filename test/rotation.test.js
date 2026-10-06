'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store } = require('../src/store');

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

test('持久化：多代连续轮换后重启，全部已激活检查点与证据按序保留', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-chain-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  // 连续三代轮换：genesis(0) → r1(1) → r2(2) → r3(3)，每轮 2-of-2 分批签名。
  let members = [genKey(), genKey()];
  const created = await store.commit((s) =>
    rotation.createDomain(s, { name: '多代链', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW),
  );
  const domainId = created.id;

  for (const rotationId of ['r1', 'r2', 'r3']) {
    const before = store.state.domains[domainId];
    const parentDigest = before.headDigest;
    const nextMembers = [genKey(), genKey()];
    await store.commit((s) =>
      rotation.createRotation(
        s,
        domainId,
        { rotationId, parentDigest, publicKeys: nextMembers.map((m) => m.publicKey), threshold: 2 },
        NOW,
      ),
    );
    const candidate = store.state.domains[domainId].rotations[rotationId];
    const message = rotation.authorizationMessage(candidate);
    // 两名父成员分两批提交。
    await store.commit((s) =>
      rotation.submitSignatures(s, domainId, rotationId, [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }], NOW),
    );
    const activated = await store.commit((s) =>
      rotation.submitSignatures(s, domainId, rotationId, [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, message) }], NOW),
    );
    assert.equal(activated.activated, true, `轮换 ${rotationId} 应激活`);
    assert.equal(activated.headDigest, candidate.digest);
    members = nextMembers;
  }

  const beforeRestart = store.state.domains[domainId];
  assert.equal(beforeRestart.generation, 3);
  assert.equal(Object.keys(beforeRestart.checkpoints).length, 4, '重启前应有 4 个已激活检查点');

  const reloaded = new Store(file);
  reloaded.load();
  const after = reloaded.state.domains[domainId];
  const chain = Object.values(after.checkpoints).sort((a, b) => a.generation - b.generation);
  assert.equal(chain.length, 4, '重启后必须仍有 4 个检查点（中间代不得丢失）');
  assert.deepEqual(
    chain.map((c) => c.generation),
    [0, 1, 2, 3],
    '代次必须连续有序',
  );
  for (let i = 1; i < chain.length; i += 1) {
    assert.equal(chain[i].parentDigest, chain[i - 1].digest, `代次 ${chain[i].generation} 父摘要必须衔接到上一代`);
    assert.equal(rotation.checkpointDigest(chain[i]), chain[i].digest, `代次 ${chain[i].generation} 摘要必须自洽`);
    assert.deepEqual(chain[i].keys, [...new Set(chain[i].keys)].sort(), '密钥集必须排序去重');
    assert.equal(chain[i].evidence.length, 2, `代次 ${chain[i].generation} 必须恰有两份证据`);
    const signers = chain[i].evidence.map((e) => e.publicKey);
    assert.equal(new Set(signers).size, 2, '证据签名者必须去重');
    const parent = chain[i - 1];
    for (const evidence of chain[i].evidence) {
      assert.ok(parent.keys.includes(evidence.publicKey), '证据签名者必须是父密钥成员');
      const rot = after.rotations[chain[i].rotationId];
      assert.ok(
        rotation.verifyAuthorization(rotation.authorizationMessage(rot), evidence.signature, evidence.publicKey),
        '每份证据必须对规范消息验签通过',
      );
    }
  }
  assert.equal(after.headDigest, beforeRestart.headDigest, '重启不得改变活动链头');
  assert.equal(after.generation, 3);
});

test('恢复：已被错误压缩的中间检查点凭已激活轮换记录安全重建；待签/已拒候选不入链', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-recover-'));
  const file = path.join(dir, 'state.json');

  // 直接按领域模型构造一份“两代已激活 + 待签/已拒候选”的状态，
  // 再模拟旧版 Store 的错误压缩：checkpoints 只留创世与链头。
  const state = { version: 1, domains: {} };
  const members = [genKey(), genKey()];
  const made = rotation.createDomain(state, { name: '受损域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW);
  const domainId = made.result.id;
  let s = made.state;

  const nextA = [genKey(), genKey()];
  s = rotation.createRotation(s, domainId, { rotationId: 'r1', parentDigest: made.result.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const rot1 = s.domains[domainId].rotations.r1;
  const msg1 = rotation.authorizationMessage(rot1);
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg1) }], NOW).state;
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg1) }], NOW).state;

  const head1 = s.domains[domainId].headDigest;
  const nextB = [genKey(), genKey()];
  s = rotation.createRotation(s, domainId, { rotationId: 'r2', parentDigest: head1, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const rot2 = s.domains[domainId].rotations.r2;
  const msg2 = rotation.authorizationMessage(rot2);
  s = rotation.submitSignatures(s, domainId, 'r2', [{ publicKey: nextA[0].publicKey, signature: sign(nextA[0].privateKey, msg2) }], NOW).state;
  s = rotation.submitSignatures(s, domainId, 'r2', [{ publicKey: nextA[1].publicKey, signature: sign(nextA[1].privateKey, msg2) }], NOW).state;

  const intact = s.domains[domainId];
  // 待签与已拒候选（任何时刻都不得被重建为检查点）。
  s = rotation.createRotation(s, domainId, { rotationId: 'pending-after', parentDigest: intact.headDigest, publicKeys: [genKey().publicKey, genKey().publicKey], threshold: 2 }, NOW).state;

  const damaged = {
    ...s,
    domains: {
      ...s.domains,
      [domainId]: {
        ...s.domains[domainId],
        checkpoints: {
          [intact.checkpoints[made.result.headDigest].digest]: intact.checkpoints[made.result.headDigest],
          [intact.headDigest]: intact.checkpoints[intact.headDigest],
        },
      },
    },
  };
  fs.writeFileSync(file, JSON.stringify(damaged, null, 2));

  const store = new Store(file);
  store.load();
  const healed = store.state.domains[domainId];
  const chain = Object.values(healed.checkpoints).sort((a, b) => a.generation - b.generation);
  assert.equal(chain.length, 3, '应恢复全部三个已激活检查点');
  assert.deepEqual(chain.map((c) => c.generation), [0, 1, 2]);
  assert.equal(chain[1].digest, rot1.digest, '中间代检查点必须被重建');
  assert.equal(chain[1].parentDigest, chain[0].digest);
  assert.equal(chain[2].parentDigest, chain[1].digest);
  assert.equal(chain[1].evidence.length, 2);
  assert.equal(healed.headDigest, intact.headDigest, '恢复不得改变活动链头');
  assert.equal(healed.rotations['pending-after'].status, 'pending');
  assert.equal(healed.checkpoints[healed.rotations['pending-after'].digest], undefined, '待签候选不得伪造成检查点');

  // 修复后的文件再次加载应保持稳定（幂等，无二次“恢复”）。
  const again = new Store(file);
  again.load();
  assert.equal(Object.keys(again.state.domains[domainId].checkpoints).length, 3);
});

test('恢复：证据被篡改或不足门限时拒绝伪造历史', () => {
  const state = { version: 1, domains: {} };
  const members = [genKey(), genKey()];
  const made = rotation.createDomain(state, { name: '篡改域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW);
  const domainId = made.result.id;
  let s = made.state;
  const nextKeys = [genKey(), genKey()];
  s = rotation.createRotation(s, domainId, { rotationId: 'r1', parentDigest: made.result.headDigest, publicKeys: nextKeys.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const rot1 = s.domains[domainId].rotations.r1;
  const msg = rotation.authorizationMessage(rot1);
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg) }], NOW).state;
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg) }], NOW).state;

  const activated = s.domains[domainId];
  // 模拟链头检查点丢失：只剩创世；headDigest 仍指向已激活轮换摘要，
  // 恢复时必须仅凭 rotations.r1（activated）重建，证据校验随之生效。
  const stripped = {
    ...activated,
    checkpoints: {
      [made.result.headDigest]: activated.checkpoints[made.result.headDigest],
    },
  };

  // 只有一份证据（不足父门限 2）→ 不得重建。
  const insufficient = JSON.parse(JSON.stringify(stripped));
  insufficient.rotations.r1.signatures = activated.rotations.r1.signatures.slice(0, 1);
  assert.throws(
    () => rotation.restoreDomain(insufficient),
    (e) => e.code === 'chain_recovery_failed',
    '证据不足门限时必须拒绝恢复',
  );

  // 证据签名被篡改 → 验签失败，不得重建。
  const tampered = JSON.parse(JSON.stringify(stripped));
  const badSig = tampered.rotations.r1.signatures[0].signature;
  tampered.rotations.r1.signatures[0].signature =
    badSig.slice(-1) === '0' ? badSig.slice(0, -1) + '1' : badSig.slice(0, -1) + '0';
  assert.throws(
    () => rotation.restoreDomain(tampered),
    (e) => e.code === 'chain_recovery_failed',
    '证据篡改时必须拒绝恢复',
  );

  // 已拒（superseded）候选即使签名齐备也不得据此补造检查点：
  // 从检查点映射中移除链头，并把轮换标为已拒 —— 链头悬空时必须报错，
  // 而不是把已拒候选伪造回历史链。
  const rejectedOnly = JSON.parse(JSON.stringify(stripped));
  delete rejectedOnly.checkpoints[activated.headDigest];
  rejectedOnly.rotations.r1.status = 'superseded';
  rejectedOnly.rotations.r1.rejectedReason = '已被取代';
  assert.throws(
    () => rotation.restoreDomain(rejectedOnly),
    (e) => e.code === 'chain_recovery_failed' && /链头/.test(e.message),
    '已拒候选缺失时链头悬空，必须报错而不是用候选伪造',
  );
});

test('恢复：链头派生投影（代次/门限/密钥集）不一致时按链头归一化且不移动链头', () => {
  const state = { version: 1, domains: {} };
  const members = [genKey(), genKey()];
  const made = rotation.createDomain(state, { name: '投影域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW);
  const domainId = made.result.id;
  let s = made.state;
  const nextKeys = [genKey(), genKey()];
  s = rotation.createRotation(s, domainId, { rotationId: 'r1', parentDigest: made.result.headDigest, publicKeys: nextKeys.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const rot1 = s.domains[domainId].rotations.r1;
  const msg = rotation.authorizationMessage(rot1);
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msg) }], NOW).state;
  s = rotation.submitSignatures(s, domainId, 'r1', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msg) }], NOW).state;

  const activated = s.domains[domainId];
  const corrupted = {
    ...activated,
    generation: 0, // 故意与链头代次不符
    threshold: 1,
    keys: members.map((m) => m.publicKey).sort(),
  };
  const { domain, recovered, normalized } = rotation.restoreDomain(corrupted);
  assert.equal(recovered, 0, '检查点完整时无需重建');
  assert.equal(normalized, true, '投影不一致应标记归一化');
  assert.equal(domain.headDigest, activated.headDigest, '归一化不得移动活动链头');
  assert.equal(domain.generation, 1);
  assert.equal(domain.threshold, 2);
  assert.deepEqual(domain.keys, rot1.keys);
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
