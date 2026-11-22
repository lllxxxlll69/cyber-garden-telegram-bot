const { randomBytes, randomUUID, createHash, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const derive = promisify(scrypt);
const hash = value => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
class AppError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new AppError(status, message); };
const active = (session, now) => !session.revoked && session.expires > now;
const publicSession = ({ id, kind, created, expires, chatId }) => ({ id, kind, created, expires, ...(chatId ? { chatId } : {}) });

class ReportService {
  constructor(repository, { sessionHours = 168, now = Date.now } = {}) {
    this.repo = repository; this.ttl = sessionHours * 3600000; this.now = now;
  }
  async credentials(login, password) {
    if (typeof login !== 'string' || !/^[a-zA-Z0-9_.-]{3,40}$/.test(login)) fail(400, 'Логин: 3-40 латинских букв, цифр, _, . или -');
    if (typeof password !== 'string' || password.length < 12 || password.length > 128) fail(400, 'Пароль: от 12 до 128 символов');
    return login.toLowerCase();
  }
  async login(login, password, register = false, kind = 'web') {
    login = await this.credentials(login, password);
    const now = this.now();
    await this.repo.transaction(s => {
      // Persisted throttle is per account, including accounts that do not yet exist.
      for (const [key, item] of Object.entries(s.attempts)) if (item.until <= now) delete s.attempts[key];
      const attempts = s.attempts['login:' + login] ||= { count: 0, until: now + 15 * 60000 };
      if (++attempts.count > 10) fail(429, 'Слишком много попыток. Повторите через 15 минут.');
    });
    let user = await this.repo.read(s => s.users.find(u => u.login === login));
    if (register) {
      const salt = randomBytes(16).toString('hex');
      const passwordHash = (await derive(password, salt, 64)).toString('hex');
      user = { id: randomUUID(), login, salt, passwordHash, created: now };
    } else {
      const actual = await derive(password, user?.salt || '00000000000000000000000000000000', 64);
      const expected = Buffer.from(user?.passwordHash || '00'.repeat(64), 'hex');
      if (!timingSafeEqual(actual, expected) || !user) fail(401, 'Неверный логин или пароль');
    }
    const raw = token();
    return this.repo.transaction(s => {
      if (register) {
        if (s.users.some(u => u.login === login)) fail(409, 'Логин уже занят');
        s.users.push(user);
      }
      delete s.attempts['login:' + login];
      s.sessions = s.sessions.filter(x => active(x, now));
      const session = { id: randomUUID(), userId: user.id, tokenHash: hash(raw), kind: kind === 'mobile' ? 'mobile' : 'web', created: now, expires: now + this.ttl };
      s.sessions.push(session);
      return { token: raw, session: publicSession(session), user: { id: user.id, login } };
    });
  }
  async authenticate(raw) {
    if (!raw || typeof raw !== 'string') fail(401, 'Войдите в аккаунт');
    const session = await this.repo.read(s => s.sessions.find(x => ['web', 'api', 'mobile'].includes(x.kind) && x.tokenHash === hash(raw) && active(x, this.now())));
    if (!session) fail(401, 'Сессия истекла. Войдите снова');
    return session;
  }
  async sessions(session) {
    return this.repo.read(s => s.sessions.filter(x => x.userId === session.userId && active(x, this.now())).map(publicSession));
  }
  async integrationSession(session) {
    const raw = token(), now = this.now();
    return this.repo.transaction(s => {
      const next = { id: randomUUID(), userId: session.userId, kind: 'api', tokenHash: hash(raw), created: now, expires: now + this.ttl };
      s.sessions.push(next);
      return { token: raw, session: publicSession(next) };
    });
  }
  async revoke(session, id) {
    return this.repo.transaction(s => {
      const target = s.sessions.find(x => x.id === id && x.userId === session.userId);
      if (!target) fail(404, 'Сессия не найдена');
      target.revoked = true;
    });
  }
  async createCode(session) {
    const code = randomBytes(12).toString('hex');
    const now = this.now();
    await this.repo.transaction(s => {
      s.codes = s.codes.filter(c => c.expires > now && c.userId !== session.userId);
      s.codes.push({ hash: hash(code), userId: session.userId, sessionId: session.id, expires: now + 5 * 60000 });
    });
    return { code, expires: now + 5 * 60000 };
  }
  async link(code, chatId) {
    if (typeof code !== 'string' || !/^[a-f0-9]{24}$/.test(code)) fail(401, 'Код недействителен или истёк');
    const now = this.now();
    return this.repo.transaction(s => {
      const index = s.codes.findIndex(c => c.hash === hash(code) && c.expires > now);
      const entry = s.codes[index];
      if (!entry || !s.sessions.some(x => x.id === entry.sessionId && active(x, now))) fail(401, 'Код недействителен или истёк');
      s.codes.splice(index, 1);
      for (const x of s.sessions) if (x.kind === 'telegram' && x.chatId === String(chatId)) x.revoked = true;
      const session = { id: randomUUID(), userId: entry.userId, kind: 'telegram', chatId: String(chatId), created: now, expires: now + this.ttl };
      s.sessions.push(session);
      return publicSession(session);
    });
  }
  async telegramSession(chatId) {
    const session = await this.repo.read(s => s.sessions.find(x => x.kind === 'telegram' && x.chatId === String(chatId) && active(x, this.now())));
    if (!session) fail(401, 'Войдите: получите код на локальном сервере и отправьте /login КОД');
    return session;
  }
  validateReport(input) {
    if (!input || !Array.isArray(input.findings) || input.findings.length > 500) fail(400, 'Отчёт должен содержать findings (не более 500 записей)');
    const text = (value, limit) => {
      if (value === undefined) return '';
      if (typeof value !== 'string' || value.length > limit) fail(400, 'Некорректный текст отчёта');
      return value.replace(/[\x00-\x08\x0b-\x1f]/g, '');
    };
    const findings = input.findings.map(f => {
      if (!f || !['info', 'low', 'medium', 'high', 'critical'].includes(f.severity)) fail(400, 'Неизвестная критичность');
      if (f.line !== undefined && (!Number.isInteger(f.line) || f.line < 0)) fail(400, 'Некорректный номер строки');
      return { title: text(f.title, 500), severity: f.severity, file: text(f.file, 1000), line: f.line || 0, rule: text(f.rule, 200), fix: text(f.fix, 3000), advice: text(f.advice, 3000), reference: text(f.reference, 500) };
    });
    return { title: text(input.title, 200) || 'Отчёт проверки безопасности', findings };
  }
  async saveReport(session, input, { deliver = true, includeJson = false } = {}) {
    const data = this.validateReport(input), now = this.now();
    return this.repo.transaction(s => {
      const report = { ...data, id: randomUUID(), userId: session.userId, created: now };
      s.reports.push(report);
      for (const x of s.sessions.filter(x => deliver && x.userId === session.userId && x.kind === 'telegram' && active(x, now))) {
        const job = { reportId: report.id, sessionId: x.id, state: 'pending', attempts: 0, next: now };
        s.deliveries.push({ ...job, id: randomUUID(), format: 'pdf' });
        if (includeJson) s.deliveries.push({ ...job, id: randomUUID(), format: 'json' });
      }
      return report;
    });
  }
  async reports(session) {
    return this.repo.read(s => s.reports.filter(r => r.userId === session.userId).reverse().slice(0, 50).map(({ findings, ...r }) => ({ ...r, count: findings.length })));
  }
  async report(session, id) {
    const report = await this.repo.read(s => s.reports.find(r => r.userId === session.userId && r.id === id));
    if (!report) fail(404, 'Отчёт не найден');
    return report;
  }
}
module.exports = { ReportService, AppError, active };
