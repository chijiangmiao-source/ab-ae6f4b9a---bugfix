'use strict';

/**
 * 验收入口（compose 中的 verify 服务）：
 *   1. 运行轮换规则单元测试（node --test）；
 *   2. 运行构建检查（scripts/build-check.js）；
 *   3. 对运行中的服务做 HTTP 冒烟：
 *      - 创建二钥、门限为二的设备域；
 *      - 错误父摘要 / 篡改载荷 / 重复重传 / 非成员签名均被拒且链头不变；
 *      - 分两轮完成连续轮换（第二轮以刚激活的链头为固定父摘要），
 *        每轮两名父成员分批签名，逐代核对摘要/父摘要连续性与证据；
 *      - 补齐两名有效签名后，接口可读回已激活链头与两份签名证据；
 *      - 页面渲染出相同结果；
 *      - 激活后的竞争候选与迟到补签被拒；
 *      - 并发竞争候选只收敛为一个活动检查点；
 *      - 应用真实重启后：全部已激活检查点（含中间代）、固定父摘要、
 *        排序密钥集、门限与签名证据逐代完整、顺序一致，健康端点反映最新链头；
 *      - 健康端点反映设备域状态。
 *   全部通过退出码 0，否则退出码 1。
 */

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const APP_URL = (process.env.APP_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

let failures = 0;

function pass(name) {
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.error(`  ✗ ${name}`);
  if (detail) console.error(`    ${String(detail).split('\n').join('\n    ')}`);
}

async function step(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err && err.message ? err.message : err);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}（期望 ${expected}，实际 ${actual}）`);
}

/**
 * 核对域详情中的完整已激活检查点链：
 *  - 检查点数量与每一代摘要、固定父摘要连续性；
 *  - 排序后的密钥集与门限；
 *  - 每个非创世检查点恰有两份证据，签名者互不相同且为父成员，
 *    并对规范授权消息逐一做 Ed25519 验签（证据必须“正确”，不仅是数量对）。
 */
function assertActivatedChain(detail, expected) {
  const cps = detail.checkpoints;
  assertEqual(cps.length, expected.length, `检查点数量应为 ${expected.length}`);
  expected.forEach((want, index) => {
    const cp = cps[index];
    assertEqual(cp.generation, want.generation, `检查点 #${index} 代次不符`);
    if (want.digest) assertEqual(cp.digest, want.digest, `第 ${want.generation} 代摘要不符`);
    assertEqual(cp.parentDigest, want.parentDigest, `第 ${want.generation} 代父摘要不符`);
    assertEqual(cp.threshold, want.threshold, `第 ${want.generation} 代门限不符`);
    assert(
      JSON.stringify(cp.keys) === JSON.stringify(want.keys),
      `第 ${want.generation} 代排序后密钥集不符`,
    );
    assertEqual(cp.status, 'activated', `第 ${want.generation} 代应为已激活状态`);
    if (index > 0) assertEqual(cp.parentDigest, cps[index - 1].digest, '父摘要必须指向上一代摘要');
    if (want.generation === 0) {
      assertEqual(cp.evidence.length, 0, '创世检查点不应有签名证据');
      return;
    }
    assertEqual(cp.evidence.length, 2, `第 ${want.generation} 代应恰有两份签名证据`);
    const signers = cp.evidence.map((e) => e.publicKey);
    assertEqual(new Set(signers).size, 2, `第 ${want.generation} 代证据签名者重复`);
    const parentKeys = expected[index - 1].keys;
    for (const publicKey of signers) {
      assert(parentKeys.includes(publicKey), `第 ${want.generation} 代证据含非父成员签名`);
    }
    const message = [
      'maintenance-rotation-authorization/v1',
      `domain=${detail.id}`,
      `rotation=${cp.rotationId}`,
      `parent=${cp.parentDigest}`,
      `generation=${cp.generation}`,
      `threshold=${cp.threshold}`,
      `keys=${cp.keys.join(',')}`,
    ].join('\n');
    for (const evidence of cp.evidence) {
      const ok = crypto.verify(
        null,
        Buffer.from(message, 'utf8'),
        crypto.createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            Buffer.from(evidence.publicKey, 'hex'),
          ]),
          format: 'der',
          type: 'spki',
        }),
        Buffer.from(evidence.signature, 'hex'),
      );
      assert(ok, `第 ${want.generation} 代存在未通过验签的证据（签名者 ${evidence.publicKey}）`);
    }
  });
  assertEqual(detail.headDigest, cps[cps.length - 1].digest, '域链头必须是最后一代检查点');
  assertEqual(detail.generation, expected.length - 1, '域最新代次必须与链末一致');
}

function runProcess(args, options = {}) {
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', timeout: 120000, ...options });
  return { status: res.status, output: `${res.stdout || ''}${res.stderr || ''}` };
}

async function api(method, urlPath, body) {
  const res = await fetch(`${APP_URL}${urlPath}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON 响应（如 HTML 页面） */
  }
  return { status: res.status, json, text };
}

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(key, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), key.privateKey).toString('hex');
}

function flipHex(hex) {
  const last = hex.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + flipped;
}

async function waitForHealth(timeoutMs, predicate) {
  const deadline = Date.now() + timeoutMs;
  let lastError = '未收到响应';
  while (Date.now() < deadline) {
    try {
      const res = await api('GET', '/healthz');
      if (res.status === 200 && res.json && res.json.status === 'ok') {
        if (!predicate || predicate(res.json)) return res.json;
        lastError = '健康响应不满足等待条件';
      } else {
        lastError = `HTTP ${res.status}`;
      }
    } catch (err) {
      lastError = err.message;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`等待服务健康超时：${lastError}`);
}

async function main() {
  console.log(`验收目标：${APP_URL}\n`);

  console.log('— 阶段 1：轮换规则单元测试 —');
  await step('node --test 轮换规则测试全部通过', async () => {
    const res = runProcess(['--test', 'test/']);
    assertEqual(res.status, 0, `单元测试失败：\n${res.output.trim().split('\n').slice(-30).join('\n')}`);
  });

  console.log('— 阶段 2：构建检查 —');
  await step('全部源码语法检查与模块加载检查通过', async () => {
    const res = runProcess([path.join('scripts', 'build-check.js')]);
    assertEqual(res.status, 0, `构建检查失败：\n${res.output}`);
  });

  console.log('— 阶段 3：HTTP 冒烟 —');
  let bootId = null;

  await step('服务健康且健康响应可用于反映设备域状态', async () => {
    const health = await waitForHealth(60000);
    assert(health.bootId && health.startedAt, '健康响应缺少 bootId/startedAt');
    assert(Array.isArray(health.domains), '健康响应缺少设备域列表');
    bootId = health.bootId;
  });

  // —— 验收主域：二钥、门限为二 ——
  const memberA = genKey();
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const outsider = genKey();
  let domainId;
  let genesisHead;
  let rotationDigest;
  let sigA;
  let sigB;

  await step('创建二钥且门限为二的设备域（公钥乱序提交，服务端排序）', async () => {
    const res = await api('POST', '/api/domains', {
      name: '验收域-2of2',
      publicKeys: [memberB.publicKey, memberA.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建设备域失败：${res.text}`);
    domainId = res.json.id;
    const expectedKeys = [memberA.publicKey, memberB.publicKey].sort();
    assert(JSON.stringify(res.json.keys) === JSON.stringify(expectedKeys), '密钥集未按规范排序');
    assertEqual(res.json.generation, 0, '创世代次应为 0');
    genesisHead = res.json.headDigest;
    assert(/^[0-9a-f]{64}$/.test(genesisHead), '链头摘要格式非法');
  });

  await step('健康响应反映新设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const entry = health.domains.find((d) => d.id === domainId);
    assert(entry, '健康响应中找不到新设备域');
    assertEqual(entry.headDigest, genesisHead, '健康响应中的链头与接口不一致');
  });

  await step('错误父摘要的轮换候选被拒且链头不变', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'bad-parent',
      parentDigest: 'ab'.repeat(32),
      publicKeys: [nextC.publicKey, nextD.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 422, `应返回 422：${res.text}`);
    assertEqual(res.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '链头被错误请求改变');
  });

  await step('创建轮换候选：固定父摘要、下一代次、排序后新公钥集、新门限', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-001',
      parentDigest: genesisHead,
      publicKeys: [nextD.publicKey, nextC.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建轮换失败：${res.text}`);
    rotationDigest = res.json.digest;
    assertEqual(res.json.parentDigest, genesisHead, '父摘要未固定为当前链头');
    assertEqual(res.json.generation, 1, '下一代次应为 1');
    assertEqual(res.json.threshold, 2, '新门限应为 2');
    assert(JSON.stringify(res.json.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新公钥集未排序');
    assertEqual(res.json.status, 'pending', '候选应处于待签状态');
  });

  await step('篡改载荷与非成员签名被拒且链头不变', async () => {
    const msgRes = await api('GET', `/api/domains/${domainId}/rotations/rot-2026-001/message`);
    assertEqual(msgRes.status, 200, '应能读取规范待签消息');
    const message = msgRes.json.message;
    assert(message.includes(`parent=${genesisHead}`), '待签消息未绑定父摘要');
    sigA = sign(memberA, message);
    sigB = sign(memberB, message);

    const tampered = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: flipHex(sigA) }],
    });
    assertEqual(tampered.json.results[0].code, 'invalid_signature', '篡改签名应给出 invalid_signature');

    const wrongMessage = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sign(memberA, message + '\nforged=1') }],
    });
    assertEqual(wrongMessage.json.results[0].code, 'invalid_signature', '签错消息应给出 invalid_signature');

    const notMember = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: outsider.publicKey, signature: sign(outsider, message) }],
    });
    assertEqual(notMember.json.results[0].code, 'not_parent_member', '非父成员应给出 not_parent_member');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '被拒签名改变了链头');
    assertEqual(head.evidence.length, 0, '被拒签名不应产生证据');
  });

  await step('第一批签名（1/2）：候选保持待签，链头不提前生效', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.status, 200, `提交签名失败：${res.text}`);
    assertEqual(res.json.results[0].status, 'accepted', '有效签名应被接受');
    assertEqual(res.json.activated, false, '未达门限不应激活');
    assertEqual(res.json.signers, 1, '应记录 1 名签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '未达门限链头不应前进');
  });

  await step('重传同一签名：给出重复拒因且不改变状态', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.json.results[0].code, 'duplicate_signature', '重传应给出 duplicate_signature');
    assertEqual(res.json.signers, 1, '重传不应增加签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '重传不应改变链头');
  });

  await step('补齐第二名有效签名：同一提交中激活，接口读回链头与两份证据', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberB.publicKey, signature: sigB }],
    });
    assertEqual(res.json.results[0].status, 'accepted', '第二名签名应被接受');
    assertEqual(res.json.activated, true, '达到父门限应激活');
    assertEqual(res.json.headDigest, rotationDigest, '链头应前进到候选摘要');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '链头摘要与候选摘要不一致');
    assertEqual(head.generation, 1, '链头代次应为 1');
    assertEqual(head.threshold, 2, '新门限应生效');
    assert(JSON.stringify(head.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新密钥集应生效');
    assertEqual(head.evidence.length, 2, '应恰好有两份签名证据');
    const evidenceKeys = head.evidence.map((e) => e.publicKey).sort();
    assert(JSON.stringify(evidenceKeys) === JSON.stringify([memberA.publicKey, memberB.publicKey].sort()), '证据签名者不符');
    const evidenceSigs = Object.fromEntries(head.evidence.map((e) => [e.publicKey, e.signature]));
    assertEqual(evidenceSigs[memberA.publicKey], sigA, '成员 A 的签名证据不符');
    assertEqual(evidenceSigs[memberB.publicKey], sigB, '成员 B 的签名证据不符');
  });

  await step('激活后的迟到补签与竞争候选均被拒且链头不变', async () => {
    const late = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(late.status, 409, `迟到补签应返回 409：${late.text}`);
    assertEqual(late.json.error.code, 'rotation_already_activated', '迟到补签应给出拒因');

    const staleParent = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'stale-competitor',
      parentDigest: genesisHead,
      publicKeys: [outsider.publicKey, genKey().publicKey],
      threshold: 2,
    });
    assertEqual(staleParent.status, 422, '旧父摘要的竞争候选应被拒');
    assertEqual(staleParent.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '竞争请求改变了链头');
  });

  // —— 第二轮轮换：以刚激活的第一代链头为固定父摘要 ——
  const nextE = genKey();
  const nextF = genKey();
  let rotation2Digest;
  let sigC;
  let sigD;

  await step('第二轮：候选必须以刚激活的链头为父摘要，旧父摘要被拒', async () => {
    const stale = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-002-stale',
      parentDigest: genesisHead,
      publicKeys: [nextE.publicKey, nextF.publicKey],
      threshold: 2,
    });
    assertEqual(stale.status, 422, `旧父摘要应被拒：${stale.text}`);
    assertEqual(stale.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');

    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-002',
      parentDigest: rotationDigest,
      publicKeys: [nextF.publicKey, nextE.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建第二轮轮换失败：${res.text}`);
    assertEqual(res.json.parentDigest, rotationDigest, '第二轮父摘要必须固定为第一代链头');
    assertEqual(res.json.generation, 2, '第二轮代次应为 2');
    assertEqual(res.json.status, 'pending', '候选应处于待签状态');
    rotation2Digest = res.json.digest;
  });

  await step('第二轮：两名新一代父成员（C/D）分批签名，第一批后不提前激活', async () => {
    const msgRes = await api('GET', `/api/domains/${domainId}/rotations/rot-2026-002/message`);
    const message = msgRes.json.message;
    assert(message.includes(`parent=${rotationDigest}`), '第二轮待签消息必须绑定第一代链头');
    sigC = sign(nextC, message);
    sigD = sign(nextD, message);

    // 上一代成员（A/B）已不是父成员，签名必须被拒。
    const oldMember = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-002/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sign(memberA, message) }],
    });
    assertEqual(oldMember.json.results[0].code, 'not_parent_member', '非本轮父成员应被拒');

    const first = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-002/signatures`, {
      signatures: [{ publicKey: nextC.publicKey, signature: sigC }],
    });
    assertEqual(first.json.results[0].status, 'accepted', '成员 C 的签名应被接受');
    assertEqual(first.json.activated, false, '仅 1/2 份签名时不应激活');
    assertEqual(first.json.headDigest, rotationDigest, '链头仍应停留在第一代');
  });

  await step('第二轮：补齐第二份签名后激活第二代，链头前进且历史含全部已激活检查点', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-002/signatures`, {
      signatures: [{ publicKey: nextD.publicKey, signature: sigD }],
    });
    assertEqual(res.json.activated, true, '达到父门限（2/2）应激活');
    assertEqual(res.json.headDigest, rotation2Digest, '链头应前进到第二代摘要');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotation2Digest, '链头应为第二代摘要');
    assertEqual(head.generation, 2, '最新代次应为 2');
    assertEqual(head.parentDigest, rotationDigest, '第二代父摘要应为第一代摘要');
    assert(JSON.stringify(head.keys) === JSON.stringify([nextE.publicKey, nextF.publicKey].sort()), '第二代密钥集不符');
    assertEqual(head.evidence.length, 2, '第二代应恰有两份证据');
    assert(
      JSON.stringify(head.evidence.map((e) => e.publicKey).sort()) ===
        JSON.stringify([nextC.publicKey, nextD.publicKey].sort()),
      '第二代证据签名者应为 C 与 D',
    );

    const detail = (await api('GET', `/api/domains/${domainId}`)).json;
    assertActivatedChain(detail, [
      { generation: 0, parentDigest: '0'.repeat(64), threshold: 2, keys: [memberA.publicKey, memberB.publicKey].sort() },
      { generation: 1, digest: rotationDigest, parentDigest: genesisHead, threshold: 2, keys: [nextC.publicKey, nextD.publicKey].sort() },
      { generation: 2, digest: rotation2Digest, parentDigest: rotationDigest, threshold: 2, keys: [nextE.publicKey, nextF.publicKey].sort() },
    ]);
  });

  // —— 第二设备域：并发竞争只收敛为一个活动检查点 ——
  let domain2Id;
  let domain2Head;
  await step('并发竞争候选：恰好一个激活，其余被取代', async () => {
    const members = [genKey(), genKey()];
    const created = await api('POST', '/api/domains', {
      name: '并发竞争域',
      publicKeys: members.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(created.status, 201, `创建第二设备域失败：${created.text}`);
    domain2Id = created.json.id;
    const parent = created.json.headDigest;

    for (const rid of ['race-1', 'race-2']) {
      const keys = [genKey(), genKey()];
      const res = await api('POST', `/api/domains/${domain2Id}/rotations`, {
        rotationId: rid,
        parentDigest: parent,
        publicKeys: keys.map((k) => k.publicKey),
        threshold: 2,
      });
      assertEqual(res.status, 201, `创建竞争候选失败：${res.text}`);
    }
    const detail = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const batch = (rid) => {
      const rot = detail.rotations.find((r) => r.rotationId === rid);
      return members.map((m) => ({ publicKey: m.publicKey, signature: sign(m, rot.message) }));
    };
    const [r1, r2] = await Promise.all([
      api('POST', `/api/domains/${domain2Id}/rotations/race-1/signatures`, { signatures: batch('race-1') }),
      api('POST', `/api/domains/${domain2Id}/rotations/race-2/signatures`, { signatures: batch('race-2') }),
    ]);
    const outcomes = [r1, r2];
    const activated = outcomes.filter((o) => o.status === 200 && o.json.activated === true);
    const superseded = outcomes.filter((o) => o.status === 409 && o.json.error && o.json.error.code === 'rotation_superseded');
    assertEqual(activated.length, 1, '并发下应恰好一个候选激活');
    assertEqual(superseded.length, 1, '落选候选应给出取代拒因');

    const after = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const activeRotations = after.rotations.filter((r) => r.status === 'activated');
    assertEqual(activeRotations.length, 1, '应只有一个已激活轮换');
    assertEqual(after.headDigest, activeRotations[0].digest, '链头应等于唯一激活候选');
    const gen1 = after.checkpoints.filter((c) => c.generation === 1);
    assertEqual(gen1.length, 1, '同一代次应只有一个活动检查点');
    const loser = after.rotations.find((r) => r.status === 'superseded');
    assert(loser && loser.rejectedReason, '落选候选应记录拒因');
    domain2Head = after.headDigest;
  });

  // —— 重启一致性 ——
  let domain1Before;
  let domain2Before;
  await step('应用真实重启后：全部已激活检查点、固定父摘要、密钥集、门限与证据逐代完整', async () => {
    domain1Before = (await api('GET', `/api/domains/${domainId}`)).json;
    domain2Before = (await api('GET', `/api/domains/${domain2Id}`)).json;

    const restart = await api('POST', '/api/admin/restart');
    assertEqual(restart.status, 202, `重启端点应返回 202：${restart.text}`);

    const health = await waitForHealth(60000, (h) => h.bootId !== bootId);
    assert(health.bootId !== bootId, '重启后 bootId 应变化（确为新进程）');

    const domain1After = (await api('GET', `/api/domains/${domainId}`)).json;
    const domain2After = (await api('GET', `/api/domains/${domain2Id}`)).json;
    assert(
      JSON.stringify(domain1After) === JSON.stringify(domain1Before),
      '验收域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    assert(
      JSON.stringify(domain2After) === JSON.stringify(domain2Before),
      '并发域重启前后状态不一致（链头/检查点/证据丢失）',
    );

    // 中间代（第 1 代）必须仍在历史链中，且三代链逐字段连续、证据逐份验签通过。
    assertActivatedChain(domain1After, [
      { generation: 0, parentDigest: '0'.repeat(64), threshold: 2, keys: [memberA.publicKey, memberB.publicKey].sort() },
      { generation: 1, digest: rotationDigest, parentDigest: genesisHead, threshold: 2, keys: [nextC.publicKey, nextD.publicKey].sort() },
      { generation: 2, digest: rotation2Digest, parentDigest: rotationDigest, threshold: 2, keys: [nextE.publicKey, nextF.publicKey].sort() },
    ]);
    const generations = domain1After.checkpoints.map((c) => c.generation);
    assert(
      JSON.stringify(generations) === JSON.stringify([0, 1, 2]),
      `检查点必须按代次 0,1,2 顺序返回，实际 ${JSON.stringify(generations)}`,
    );

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotation2Digest, '重启后链头摘要变化');
    assertEqual(head.generation, 2, '重启后最新代次变化');
    assertEqual(head.evidence.length, 2, '重启后第二代签名证据份数变化');
    const intermediate = domain1After.checkpoints.find((c) => c.generation === 1);
    assert(intermediate, '重启后中间代（第 1 代）检查点消失');
    assertEqual(intermediate.parentDigest, genesisHead, '中间代固定父摘要错误');
    assertEqual(intermediate.evidence.length, 2, '中间代两份签名证据必须保留');
    assert(
      JSON.stringify(intermediate.evidence.map((e) => e.publicKey).sort()) ===
        JSON.stringify([memberA.publicKey, memberB.publicKey].sort()),
      '中间代证据签名者必须可复核',
    );

    // 再重启一次：恢复/读取必须幂等，历史不被二次压缩。
    const restart2 = await api('POST', '/api/admin/restart');
    assertEqual(restart2.status, 202, `第二次重启端点应返回 202：${restart2.text}`);
    await waitForHealth(60000, (h) => h.bootId !== health.bootId);
    const domain1After2 = (await api('GET', `/api/domains/${domainId}`)).json;
    assert(
      JSON.stringify(domain1After2) === JSON.stringify(domain1Before),
      '第二次重启后状态发生漂移（历史恢复必须幂等）',
    );
  });

  await step('健康响应在重启后仍反映最新链头', async () => {
    const health = (await api('GET', '/healthz')).json;
    const d1 = health.domains.find((d) => d.id === domainId);
    const d2 = health.domains.find((d) => d.id === domain2Id);
    assert(d1 && d1.headDigest === rotation2Digest, '健康响应中验收域链头应为第二代摘要');
    assertEqual(d1.generation, 2, '健康响应中验收域代次应为 2');
    assert(d2 && d2.headDigest === domain2Head, '健康响应中并发域链头不符');
  });

  await step('页面显示与接口相同的完整历史（含中间代检查点与其证据）', async () => {
    const page = await api('GET', '/');
    assertEqual(page.status, 200, '页面应可访问');
    assert(page.text.includes(rotation2Digest), '页面未显示第二代链头摘要');
    assert(page.text.includes(rotationDigest), '页面未显示中间代（第 1 代）检查点摘要');
    assert(page.text.includes(genesisHead), '页面未显示创世检查点摘要');
    assert(page.text.includes(memberA.publicKey), '页面未显示成员 A 的签名证据');
    assert(page.text.includes(memberB.publicKey), '页面未显示成员 B 的签名证据');
    assert(page.text.includes(nextC.publicKey) && page.text.includes(nextD.publicKey), '页面未显示第二代证据签名者 C/D');
    assert(page.text.includes(sigA), '页面未显示成员 A 的签名值');
    assert(page.text.includes(sigC), '页面未显示成员 C 的签名值');
    assert(page.text.includes('rot-2026-001') && page.text.includes('rot-2026-002'), '页面未显示两轮轮换标识');
    assert(page.text.includes('已激活'), '页面缺少已激活检查点分组');
    assert(page.text.includes('已拒'), '页面缺少已拒检查点分组');
    assert(page.text.includes('待签'), '页面缺少待签检查点分组');
    assert(page.text.includes('race-1') && page.text.includes('race-2'), '页面未显示竞争候选记录');
  });

  console.log('');
  if (failures > 0) {
    console.error(`验收失败：${failures} 项未通过`);
    process.exit(1);
  }
  console.log('验收全部通过。');
  process.exit(0);
}

main().catch((err) => {
  console.error(`验收执行异常：${err.stack || err}`);
  process.exit(1);
});
