const { AppError, active } = require('./service.cjs');
const { renderPdf } = require('./pdf.cjs');

class TelegramBot {
  constructor(token, service, { fetchImpl = fetch, render = renderPdf } = {}) {
    this.token = token; this.service = service; this.fetch = fetchImpl; this.render = render;
    this.stopping = false; this.controller = new AbortController(); this.delivering = false;
  }
  async call(method, body) {
    const multipart = body instanceof FormData;
    let response;
    try {
      response = await this.fetch(`https://api.telegram.org/bot${this.token}/${method}`, {
        method: 'POST', headers: multipart ? {} : { 'Content-Type': 'application/json' },
        body: multipart ? body : JSON.stringify(body),
        signal: AbortSignal.any([this.controller.signal, AbortSignal.timeout(40000)])
      });
    } catch { throw new Error('Telegram: сеть недоступна'); }
    const data = await response.json().catch(() => ({}));
    // Do not include request URLs, response descriptions, or tokens in logs.
    if (!response.ok || !data.ok) throw new Error(`Telegram API: ${response.status}`);
    return data.result;
  }
  text(chatId, text) { return this.call('sendMessage', { chat_id: chatId, text }); }
  async document(chatId, report) {
    const pdf = await this.render(report);
    const form = new FormData();
    form.set('chat_id', String(chatId));
    form.set('caption', `Cyber Garden: ${report.findings.length} находок`);
    form.set('document', new Blob([pdf], { type: 'application/pdf' }), `report-${report.id}.pdf`);
    return this.call('sendDocument', form);
  }
  async handle(update) {
    const message = update.message;
    if (!message || message.chat?.type !== 'private' || message.from?.is_bot || message.from?.id !== message.chat.id) return;
    const chatId = String(message.chat.id);
    const [command, argument] = (message.text || '').trim().split(/\s+/);
    const cmd = command?.split('@')[0];
    try {
      if (cmd === '/start' || cmd === '/help') {
        await this.text(chatId, 'Cyber Garden\n/login КОД - вход по одноразовому коду с локального сервера\n/reports - последние отчёты\n/report ID - скачать PDF (без ID - последний)\n/sessions - активные сессии\n/logout - завершить вход\nПароль в чат отправлять не нужно.');
        return;
      }
      if (cmd === '/login') {
        await this.service.link(argument, chatId);
        await this.text(chatId, 'Вход выполнен. Новые отчёты будут приходить в PDF. /report - последний отчёт.');
        return;
      }
      const session = await this.service.telegramSession(chatId);
      if (cmd === '/logout') {
        await this.service.revoke(session, session.id);
        await this.text(chatId, 'Сессия завершена. Отправка отчётов отключена.');
      } else if (cmd === '/sessions') {
        const sessions = await this.service.sessions(session);
        await this.text(chatId, sessions.slice(-20).map(s => `${s.kind}: ${s.id}\nдо ${new Date(s.expires).toISOString()}`).join('\n\n'));
      } else if (cmd === '/reports') {
        const reports = (await this.service.reports(session)).slice(0, 10);
        await this.text(chatId, reports.length ? reports.map(r => `${r.id}\n${r.title} (${r.count})`).join('\n\n') : 'Отчётов пока нет.');
      } else if (cmd === '/report') {
        const id = argument || (await this.service.reports(session))[0]?.id;
        const report = await this.service.report(session, id);
        await this.document(chatId, report);
      } else await this.text(chatId, 'Список команд: /help');
    } catch (error) {
      if (error instanceof AppError) await this.text(chatId, error.message);
      else throw error;
    }
  }
  async deliver() {
    if (this.delivering || this.stopping) return;
    this.delivering = true;
    try {
      const jobs = await this.service.repo.read(s => s.deliveries.filter(j => j.state === 'pending' && j.next <= this.service.now()).slice(0, 10));
      for (const job of jobs) {
        if (this.stopping) break;
        const target = await this.service.repo.read(s => {
          const session = s.sessions.find(x => x.id === job.sessionId && active(x, this.service.now()));
          const report = s.reports.find(r => r.id === job.reportId && r.userId === session?.userId);
          return session && report ? { session, report } : null;
        });
        let state = 'cancelled';
        if (target) {
          try { await this.document(target.session.chatId, target.report); state = 'sent'; }
          catch { state = job.attempts >= 7 ? 'failed' : 'pending'; }
        }
        await this.service.repo.transaction(s => {
          const current = s.deliveries.find(x => x.id === job.id);
          current.state = state; current.attempts++;
          current.next = this.service.now() + Math.min(3600000, 15000 * 2 ** current.attempts);
        });
      }
    } finally { this.delivering = false; }
  }
  async run() {
    await this.call('getMe', {});
    this.timer = setInterval(() => { this.deliver().catch(() => console.error('Ошибка очереди доставки')); }, 15000);
    await this.deliver();
    while (!this.stopping) {
      try {
        const offset = await this.service.repo.read(s => s.offset);
        const updates = await this.call('getUpdates', { offset, timeout: 25, allowed_updates: ['message'] });
        for (const update of updates) {
          if (this.stopping) break;
          await this.handle(update);
          await this.service.repo.transaction(s => { s.offset = update.update_id + 1; });
        }
      } catch {
        if (!this.stopping) {
          console.error('Telegram недоступен; повтор через 5 секунд');
          await new Promise(resolve => {
            const done = () => { clearTimeout(timer); this.controller.signal.removeEventListener('abort', done); resolve(); };
            const timer = setTimeout(done, 5000);
            this.controller.signal.addEventListener('abort', done, { once: true });
          });
        }
      }
    }
  }
  stop() { this.stopping = true; clearInterval(this.timer); this.controller.abort(); }
}
module.exports = { TelegramBot };
