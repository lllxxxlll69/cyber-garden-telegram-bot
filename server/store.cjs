const fs = require('node:fs/promises');
const path = require('node:path');

// Repository contract: read(fn) returns a detached snapshot; transaction(fn)
// commits ALL changes atomically or none. Callbacks must be synchronous.
// A database adapter can implement these methods using database transactions.
class JsonRepository {
  constructor(directory) { this.directory = path.resolve(directory); this.tail = Promise.resolve(); }
  async open() {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    this.file = path.join(this.directory, 'store.json');
    this.lock = await fs.open(path.join(this.directory, 'server.lock'), 'wx', 0o600)
      .catch(() => { throw Error('Каталог данных уже занят. После аварии удалите server.lock, убедившись, что сервер остановлен.'); });
    try {
      await this.lock.writeFile(String(process.pid));
      try { this.state = JSON.parse(await fs.readFile(this.file, 'utf8')); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        this.state = { version: 1, users: [], sessions: [], codes: [], reports: [], deliveries: [], attempts: {}, offset: 0 };
      }
      if (this.state.version !== 1) throw Error('Неподдерживаемая версия хранилища');
      for (const key of ['projects', 'workflows', 'runs', 'templates']) this.state[key] ||= [];
      return this;
    } catch (error) { await this.close(); throw error; }
  }
  async read(fn) { await this.tail; return fn(structuredClone(this.state)); }
  transaction(fn) {
    const task = this.tail.then(async () => {
      const next = structuredClone(this.state);
      const result = fn(next);
      if (result && typeof result.then === 'function') throw Error('Repository callbacks must be synchronous');
      const temporary = this.file + '.tmp';
      const handle = await fs.open(temporary, 'w', 0o600);
      try { await handle.writeFile(JSON.stringify(next)); await handle.sync(); }
      finally { await handle.close(); }
      await fs.rename(temporary, this.file);
      this.state = next;
      return structuredClone(result);
    });
    this.tail = task.catch(() => {});
    return task;
  }
  async close() {
    await this.tail;
    if (this.lock) { await this.lock.close(); this.lock = null; await fs.unlink(path.join(this.directory, 'server.lock')); }
  }
}
module.exports = { JsonRepository };
