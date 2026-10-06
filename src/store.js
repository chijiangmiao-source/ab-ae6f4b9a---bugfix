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
 */

const fs = require('node:fs');
const path = require('node:path');

const rotation = require('./rotation');

const STATE_VERSION = 1;

function initialState() {
  return { version: STATE_VERSION, domains: {} };
}

/**
 * 恢复磁盘状态：保留每代已激活检查点的完整历史，绝不压缩。
 *
 * 对每个设备域调用纯领域逻辑 rotation.restoreDomain：仅凭“已激活”的
 * 轮换记录重建缺失检查点（逐份证据验签、重算摘要、校验父链连续性与
 * 父门限），待签/已拒候选不会被伪造进历史，活动链头也不会被移动。
 *
 * 返回 { state, recoveredCount }；recoveredCount > 0 表示有受影响的
 * 设备域被安全修复，调用方应将修复后的状态重新原子落盘。
 */
function restoreLoadedState(state) {
  let recoveredCount = 0;
  let normalizedCount = 0;
  const domains = {};
  for (const [domainId, domain] of Object.entries(state.domains)) {
    const restored = rotation.restoreDomain(domain);
    domains[domainId] = restored.domain;
    recoveredCount += restored.recovered;
    if (restored.normalized) normalizedCount += 1;
  }
  return { state: { ...state, domains }, recoveredCount, normalizedCount };
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = null;
    this._queue = Promise.resolve();
  }

  /**
   * 启动时加载；状态文件不存在则初始化空状态并落盘。
   * 加载时复核并安全恢复完整检查点链：若历史上曾被压缩丢失中间代，
   * 则仅凭已激活轮换记录（证据全部验签通过）重建，并把修复结果
   * 重新原子落盘，使受影响的持久化设备域回到可复核状态。
   */
  load() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    if (fs.existsSync(this.file)) {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STATE_VERSION || typeof parsed.domains !== 'object' || parsed.domains === null) {
        throw new Error(`状态文件损坏或版本不受支持：${this.file}`);
      }
      const { state, recoveredCount, normalizedCount } = restoreLoadedState(parsed);
      this.state = state;
      if (recoveredCount > 0 || normalizedCount > 0) {
        console.warn(
          `[store] 授权链恢复完成：重建 ${recoveredCount} 个缺失检查点，归一化 ${normalizedCount} 个设备域的链头投影；已重新原子落盘`,
        );
        this._persist(this.state);
      }
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

module.exports = { Store, initialState, restoreLoadedState, STATE_VERSION };
