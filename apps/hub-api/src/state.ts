import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { emptyState, type HubState } from "../../../packages/protocol/src/index.js";

export class JsonStore {
  readonly path: string;

  constructor(dataDir: string) {
    this.path = join(dataDir, "hub-state.json");
  }

  async read(): Promise<HubState> {
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed = JSON.parse(raw) as HubState;
      if (parsed.schema_version !== 1) {
        throw new Error(`unsupported state schema ${String(parsed.schema_version)}`);
      }
      return { ...emptyState(), ...parsed };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return emptyState();
      }
      throw error;
    }
  }

  async write(state: HubState): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const tempPath = `${this.path}.tmp`;
    await writeFile(tempPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(tempPath, this.path);
  }

  async mutate<T>(fn: (state: HubState) => T | Promise<T>): Promise<T> {
    const state = await this.read();
    const result = await fn(state);
    await this.write(state);
    return result;
  }
}
