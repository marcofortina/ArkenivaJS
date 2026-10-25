import type { OperationOptions, RedisProvider } from '@arkenivajs/core';

/** Unit-only framework-port double; live compatibility uses the separately installed native Redis adapter. */
export function redisPortDouble() {
  const state: {
    value: string | null;
    accepted: boolean;
    removed: number;
    gate?: Promise<void>;
    failure?: unknown;
    calls: {
      method: string;
      key: string;
      value?: string;
      options?: OperationOptions & { ttlMs?: number };
    }[];
  } = { value: null, accepted: true, removed: 1, calls: [] };
  const wait = async () => {
    await state.gate;
    if (state.failure) throw state.failure;
  };
  const redis: RedisProvider = {
    async get(key, options) {
      state.calls.push({ method: 'get', key, ...(options ? { options } : {}) });
      await wait();
      return state.value;
    },
    async set(key, value, options) {
      state.calls.push({ method: 'set', key, value, ...(options ? { options } : {}) });
      await wait();
      return state.accepted;
    },
    async del(keys, options) {
      state.calls.push({ method: 'delete', key: keys[0]!, ...(options ? { options } : {}) });
      await wait();
      return state.removed;
    },
    async increment() {
      throw new Error('The cache must not increment native keys');
    },
    async publish() {
      throw new Error('The cache must not publish native messages');
    },
    native() {
      throw new Error('The cache must not bypass the Redis port');
    },
  };
  return { state, redis };
}
