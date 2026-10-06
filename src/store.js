'use strict';

/**
 * 持久化存储：单写者串行队列 + 原子文件提交。
 *
 * 每次 commit(mutator)：
 *  1. 在串行队列中执行 mutator（纯函数：state → {state, result}）；
 *  2. 若返回了新状态，则一次性写入临时文件、fsync、rename 替换、
 *     fsync 目录 —— 这是一次“持久化提交”，要么完整生效要么不生效；
 *  3. 只有落盘成功后才更新内存状态。
 *
 * 因此“收集到足够签名 → 激活候选 → 取代竞争候选 → 链头前进”
 * 永远落在同一次持久化提交里；并发的补签/重传在队列中串行收敛，
 * 不会产生第二个活动检查点。
 *
 * 重启恢复：磁盘上的每一代已激活检查点都必须完整保留，授权链才能
 * 逐代复核。历史上曾有缺陷版本在加载时只保留创世与链头检查点，
 * 丢弃中间代；load() 会检测这种受损状态，仅凭状态为“已激活”的
 * 轮换记录（含当时接受的全部签名）重建缺失检查点，并重新验证明细
 * 摘要、父链连续性、排序密钥集、门限与签名证据。待签/已拒候选
 * 永远不会被写成历史；任何无法通过复核的状态直接拒绝加载。
 */

const fs = require('node:fs');
const path = require('node:path');

const rotation = require('./rotation');

const STATE_VERSION = 1;

function initialState() {
  return { version: STATE_VERSION, domains: {} };
}

/**
 * 依据“已激活”轮换记录重建缺失的检查点。
 *
 * 只接受 status === 'activated' 的候选：待签或已拒（取代）候选
 * 绝不允许变成历史检查点。重建按代次顺序进行，父检查点必须在链上；
 * 重建出的检查点逐字段复核（摘要、密钥集、门限、证据），任一不通过
 * 都抛出异常而不是写入不可信历史。活动链头不参与、也不会被改变。
 *
 * @returns {{domain: object, recovered: number}}
 */
function restoreActivatedCheckpoints(domain) {
  const missing = Object.values(domain.rotations)
    .filter((rot) => rot.status === 'activated' && !domain.checkpoints[rot.digest])
    .sort((a, b) => a.generation - b.generation);

  if (missing.length === 0) return { domain, recovered: 0 };

  const checkpoints = { ...domain.checkpoints };
  for (const rot of missing) {
    const parent = checkpoints[rot.parentDigest];
    if (!parent) {
      throw new Error(
        `设备域 ${domain.id} 的已激活轮换 ${rot.rotationId} 缺少父检查点 ${rot.parentDigest}，无法安全重建`,
      );
    }

    const checkpoint = {
      digest: rot.digest,
      domainId: domain.id,
      rotationId: rot.rotationId,
      parentDigest: rot.parentDigest,
      generation: rot.generation,
      threshold: rot.threshold,
      keys: rot.keys,
      status: 'activated',
      activatedAt: rot.activatedAt,
      evidence: rot.signatures.map((s) => ({
        publicKey: s.publicKey,
        signature: s.signature,
        receivedAt: s.receivedAt,
      })),
    };

    // 明细摘要必须与候选摘要一致（载荷被篡改则无法重建）。
    const recomputed = rotation.checkpointDigest(checkpoint);
    if (recomputed !== checkpoint.digest) {
      throw new Error(
        `设备域 ${domain.id} 的轮换 ${rot.rotationId} 载荷摘要复核失败（期望 ${checkpoint.digest}，实得 ${recomputed}），拒绝伪造历史`,
      );
    }
    verifyCheckpointEvidence(checkpoint, parent);
    checkpoints[checkpoint.digest] = checkpoint;
  }

  return { domain: { ...domain, checkpoints }, recovered: missing.length };
}

/** 复核单个非创世检查点的签名证据：份数、去重、父成员资格、Ed25519 验签。 */
function verifyCheckpointEvidence(checkpoint, parent) {
  const evidence = checkpoint.evidence;
  if (!Array.isArray(evidence)) {
    throw new Error(`检查点 ${checkpoint.digest} 缺少签名证据，授权链不可复核`);
  }
  // 单批可能一次性带来多于门限份的有效签名，证据份数 >= 父门限即合法；
  // 但去重后不可能超过父密钥成员总数。
  if (evidence.length < parent.threshold) {
    throw new Error(
      `检查点 ${checkpoint.digest} 证据份数 ${evidence.length} 少于父门限 ${parent.threshold}`,
    );
  }
  if (evidence.length > parent.keys.length) {
    throw new Error(
      `检查点 ${checkpoint.digest} 证据份数 ${evidence.length} 超过父密钥成员数 ${parent.keys.length}`,
    );
  }
  const seen = new Set();
  for (const entry of evidence) {
    if (!entry || !entry.publicKey || !entry.signature) {
      throw new Error(`检查点 ${checkpoint.digest} 的签名证据结构不完整`);
    }
    if (seen.has(entry.publicKey)) {
      throw new Error(`检查点 ${checkpoint.digest} 存在重复签名者 ${entry.publicKey}`);
    }
    seen.add(entry.publicKey);
    if (!parent.keys.includes(entry.publicKey)) {
      throw new Error(`检查点 ${checkpoint.digest} 的签名者 ${entry.publicKey} 不是父检查点密钥成员`);
    }
    // 授权消息完全由检查点自身字段确定，无需依赖候选记录。
    const message = rotation.authorizationMessage(checkpoint);
    if (!rotation.verifyAuthorization(message, entry.signature, entry.publicKey)) {
      throw new Error(`检查点 ${checkpoint.digest} 的签名证据未通过 Ed25519 验签（疑似篡改）`);
    }
  }
}

/**
 * 校验整条已激活检查点链：
 *  - 唯一起点：第 0 代创世检查点（固定零父摘要、无证据）；
 *  - 代次连续（0..n 不缺、不重），每代父摘要指向上一代摘要；
 *  - 每个检查点的明细摘要可重算复现；
 *  - 每个非创世检查点恰有父门限份、来自父成员且验签通过的证据；
 *  - 活动链头必须是最后一代检查点。
 */
function verifyDomainChain(domain) {
  const checkpoints = Object.values(domain.checkpoints)
    .filter((cp) => cp.status === 'activated')
    .sort((a, b) => a.generation - b.generation);

  if (checkpoints.length === 0) {
    throw new Error(`设备域 ${domain.id} 没有任何已激活检查点`);
  }
  const [genesis, ...rest] = checkpoints;
  if (
    genesis.generation !== 0 ||
    genesis.rotationId !== rotation.GENESIS_ROTATION_ID ||
    genesis.parentDigest !== rotation.GENESIS_PARENT_DIGEST
  ) {
    throw new Error(`设备域 ${domain.id} 的创世检查点不合法`);
  }
  if (rotation.checkpointDigest(genesis) !== genesis.digest) {
    throw new Error(`设备域 ${domain.id} 的创世检查点摘要复核失败`);
  }
  if (!Array.isArray(genesis.evidence) || genesis.evidence.length !== 0) {
    throw new Error(`设备域 ${domain.id} 的创世检查点不应携带签名证据`);
  }

  let prev = genesis;
  for (const cp of rest) {
    if (cp.generation !== prev.generation + 1) {
      throw new Error(`设备域 ${domain.id} 授权链代次不连续：第 ${prev.generation} 代后出现第 ${cp.generation} 代`);
    }
    if (cp.parentDigest !== prev.digest) {
      throw new Error(
        `设备域 ${domain.id} 第 ${cp.generation} 代父摘要不连续（期望 ${prev.digest}，实得 ${cp.parentDigest}）`,
      );
    }
    if (rotation.checkpointDigest(cp) !== cp.digest) {
      throw new Error(`设备域 ${domain.id} 第 ${cp.generation} 代检查点摘要复核失败`);
    }
    if (!Array.isArray(cp.keys) || JSON.stringify(cp.keys) !== JSON.stringify([...new Set(cp.keys)].sort())) {
      throw new Error(`设备域 ${domain.id} 第 ${cp.generation} 代密钥集未排序去重`);
    }
    if (!Number.isInteger(cp.threshold) || cp.threshold < 1 || cp.threshold > cp.keys.length) {
      throw new Error(`设备域 ${domain.id} 第 ${cp.generation} 代门限不合法`);
    }
    verifyCheckpointEvidence(cp, prev);
    prev = cp;
  }

  if (domain.headDigest !== prev.digest) {
    throw new Error(
      `设备域 ${domain.id} 的活动链头 ${domain.headDigest} 不是授权链末端（${prev.digest}），拒绝在存疑状态下启动`,
    );
  }
  return checkpoints;
}

/**
 * 加载时恢复：重建缺失的已激活检查点并复核全链。
 * 活动链头不会被改变；仅当确实发生恢复时才需要重新落盘。
 *
 * @returns {{state: object, changed: boolean}}
 */
function recoverLoadedState(parsed) {
  let changed = false;
  const domains = Object.fromEntries(
    Object.entries(parsed.domains).map(([domainId, domain]) => {
      if (!domain || typeof domain !== 'object' || !domain.checkpoints || !domain.rotations) {
        throw new Error(`设备域 ${domainId} 状态结构损坏`);
      }
      const { domain: restored, recovered } = restoreActivatedCheckpoints(domain);
      let next = restored;
      if (recovered > 0) changed = true;

      const chain = verifyDomainChain(next);
      const head = chain[chain.length - 1];
      // 链头之外的域级字段是链头的派生缓存；仅对齐到链头，不改变链头本身。
      if (
        next.generation !== head.generation ||
        next.threshold !== head.threshold ||
        JSON.stringify(next.keys) !== JSON.stringify(head.keys)
      ) {
        next = { ...next, generation: head.generation, threshold: head.threshold, keys: head.keys };
        changed = true;
      }
      return [domainId, next];
    }),
  );
  return { state: { ...parsed, domains }, changed };
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = null;
    this._queue = Promise.resolve();
  }

  /** 启动时加载；状态文件不存在则初始化空状态并落盘。 */
  load() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    if (fs.existsSync(this.file)) {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STATE_VERSION || typeof parsed.domains !== 'object' || parsed.domains === null) {
        throw new Error(`状态文件损坏或版本不受支持：${this.file}`);
      }
      // 恢复受损历史（旧版本曾在加载时丢弃中间代检查点）并复核全链；
      // 只有实际补回数据时才重写文件，避免无意义的写放大。
      const { state, changed } = recoverLoadedState(parsed);
      if (changed) this._persist(state);
      this.state = state;
    } else {
      this.state = initialState();
      this._persist(this.state);
    }
    return this.state;
  }

  /**
   * 串行执行一次状态迁移。mutator 抛错时不产生任何持久化变更；
   * mutator 返回原状态引用时跳过落盘（纯拒绝路径不改变链头）。
   */
  commit(mutator) {
    const run = this._queue.then(() => {
      const outcome = mutator(this.state);
      if (!outcome || typeof outcome !== 'object' || !('state' in outcome)) {
        throw new Error('mutator 必须返回 { state, result }');
      }
      const { state, result } = outcome;
      if (state !== this.state) {
        this._persist(state);
        this.state = state;
      }
      return result;
    });
    // 队列本身不因单次失败而中断。
    this._queue = run.catch(() => {});
    return run;
  }

  /** 原子提交：写临时文件 → fsync → rename → fsync 目录。 */
  _persist(state) {
    const tmp = `${this.file}.tmp`;
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, JSON.stringify(state, null, 2));
      fs.writeSync(fd, '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
    const dirFd = fs.openSync(path.dirname(this.file), 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
}

module.exports = {
  Store,
  initialState,
  recoverLoadedState,
  restoreActivatedCheckpoints,
  verifyDomainChain,
  STATE_VERSION,
};
