// Packet payloads stay in SQLite; only ordering keys remain in memory.
export function diskPackets(
  store,
  generation,
  keys = [],
  initialize = true,
  excerpts = new Map(),
) {
  const table = store.readOnly ? "temp.plan_packets" : "work";
  if (initialize && store.readOnly)
    store.db.exec(
      "CREATE TEMP TABLE IF NOT EXISTS plan_packets(generation TEXT,kind TEXT,id TEXT,data TEXT,PRIMARY KEY(generation,kind,id));",
    );
  const read = (key) => {
    const value = JSON.parse(
      store.db
        .prepare(
          `SELECT data FROM ${table} WHERE generation=? AND kind='packet' AND id=?`,
        )
        .get(generation, key).data,
    );
    for (const record of value.packet.records)
      for (const evidence of record.evidence)
        if (excerpts.has(evidence.id))
          evidence.excerpt = excerpts.get(evidence.id);
    return value;
  };
  const write = (value) => {
    const safe = structuredClone(value);
    for (const record of safe.packet.records)
      for (const evidence of record.evidence) delete evidence.excerpt;
    store.db
      .prepare(`INSERT OR REPLACE INTO ${table} VALUES(?,'packet',?,?)`)
      .run(generation, value.id, JSON.stringify(safe));
    return value.id;
  };
  const target = {
    get length() {
      return keys.length;
    },
    *[Symbol.iterator]() {
      for (const key of keys) yield read(key);
    },
    push(...values) {
      keys.push(...values.map(write));
      return keys.length;
    },
    splice(start, count = keys.length - start, ...values) {
      return diskPackets(
        store,
        generation,
        keys.splice(start, count, ...values.map(write)),
        false,
        excerpts,
      );
    },
    map(fn) {
      return keys.map((key, index) => fn(read(key), index));
    },
    filter(fn) {
      return diskPackets(
        store,
        generation,
        keys.filter((key, index) => fn(read(key), index)),
        false,
        excerpts,
      );
    },
    some(fn) {
      return keys.some((key, index) => fn(read(key), index));
    },
    find(fn) {
      for (let i = 0; i < keys.length; i++) {
        const value = read(keys[i]);
        if (fn(value, i)) return value;
      }
    },
    reduce(fn, initial) {
      let value = initial;
      for (let i = 0; i < keys.length; i++) value = fn(value, read(keys[i]), i);
      return value;
    },
    flatMap(fn) {
      return keys.flatMap((key, index) => fn(read(key), index));
    },
  };
  return new Proxy(target, {
    get(obj, key) {
      if (typeof key === "string" && /^\d+$/.test(key))
        return keys[Number(key)] === undefined
          ? undefined
          : read(keys[Number(key)]);
      return Reflect.get(obj, key);
    },
  });
}
