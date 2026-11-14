import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { randomUUID } from "node:crypto";
import { sha, within } from "./sources.mjs";
const MAX = 180 * 1024 * 1024;
export async function workspaceStore(root, folder) {
  const dir = path.resolve(
    folder ||
      path.join(
        os.homedir(),
        ".synthesis",
        "workspaces",
        sha(root).slice(0, 20),
      ),
  );
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const real = await fs.realpath(dir);
  if (within(root, real))
    throw Error("Workspace must be outside the analyzed source root");
  const file = path.join(real, "snapshot.json"),
    lockFile = path.join(real, "writer.lock");
  let lock;
  try {
    lock = await fs.open(lockFile, "wx", 0o600);
    await lock.writeFile(String(process.pid));
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const pid = Number(await fs.readFile(lockFile, "utf8"));
    if (Number.isInteger(pid) && pid > 0) {
      try {
        process.kill(pid, 0);
        throw Error("Workspace is already open by another process");
      } catch (e) {
        if (e.code !== "ESRCH") throw e;
      }
    } else throw Error("Workspace lock is invalid; inspect it before removing");
    await fs.unlink(lockFile);
    lock = await fs.open(lockFile, "wx", 0o600);
    await lock.writeFile(String(process.pid));
  }
  let pending = Promise.resolve();
  async function load() {
    try {
      const stat = await fs.stat(file);
      if (stat.size > MAX) throw Error("Workspace snapshot exceeds size limit");
      const envelope = JSON.parse(await fs.readFile(file, "utf8"));
      if (
        envelope.version !== 1 ||
        envelope.rootHash !== sha(root) ||
        envelope.digest !== sha(JSON.stringify(envelope.data))
      )
        throw Error("Workspace snapshot validation failed");
      const { model, manifest } = envelope.data;
      if (
        !manifest ||
        !Array.isArray(manifest.repositories) ||
        !model ||
        model.staticOnly !== true ||
        !Array.isArray(model.interfaces) ||
        !Array.isArray(model.evidence) ||
        !Array.isArray(model.sources)
      )
        throw Error("Invalid workspace model");
      return envelope.data;
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
  }
  function save(data) {
    const json = JSON.stringify({
      version: 1,
      rootHash: sha(root),
      digest: sha(JSON.stringify(data)),
      data,
    });
    if (Buffer.byteLength(json) > MAX)
      return Promise.reject(Error("Workspace exceeds checkpoint limit"));
    const write = async () => {
      const temp = path.join(real, randomUUID() + ".tmp");
      try {
        await fs.writeFile(temp, json, { mode: 0o600, flag: "wx" });
        await fs.rename(temp, file);
      } finally {
        await fs.rm(temp, { force: true });
      }
    };
    pending = pending.catch(() => {}).then(write);
    return pending;
  }
  async function close() {
    await pending.catch(() => {});
    await lock.close();
    await fs.unlink(lockFile).catch(() => {});
  }
  return { dir: real, load, save, close };
}
