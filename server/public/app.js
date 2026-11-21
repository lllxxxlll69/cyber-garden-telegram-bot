const el = id => document.getElementById(id);
function status(message, error = false) { el('status').textContent = message; el('status').className = error ? 'error' : ''; }
async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers } });
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      el('auth').hidden = false; el('dashboard').hidden = true;
      for (const id of ['code', 'integration-token']) { el(id).textContent = ''; el(id).hidden = true; }
    }
    throw Error(body.error || 'Ошибка запроса');
  }
  return body;
}
const date = timestamp => new Date(timestamp).toLocaleString('ru-RU');
function row(title, subtitle, action) {
  const root = document.createElement('div'); root.className = 'row';
  const content = document.createElement('div'), text = document.createElement('span'), small = document.createElement('small');
  text.textContent = title; small.textContent = subtitle; content.append(text, small); root.append(content);
  if (action) root.append(action);
  return root;
}
async function refresh() {
  const me = await api('/api/me');
  const [reports, deliveries, health] = await Promise.all([api('/api/reports'), api('/api/deliveries'), api('/health')]);
  el('auth').hidden = true; el('dashboard').hidden = false;
  el('telegram-state').textContent = health.telegramConfigured ? 'Токен Telegram настроен.' : 'Telegram отключён: укажите TELEGRAM_BOT_TOKEN в server/.env и перезапустите сервер.';
  el('reports').replaceChildren(...reports.map(report => {
    const link = document.createElement('a'); link.className = 'download'; link.textContent = 'Скачать PDF'; link.href = `/api/reports/${report.id}/pdf`;
    return row(report.title, `${date(report.created)} · находок: ${report.count}`, link);
  }));
  if (!reports.length) el('reports').textContent = 'Отчётов пока нет.';
  el('sessions').replaceChildren(...me.sessions.map(session => {
    const button = document.createElement('button'); button.className = 'secondary'; button.textContent = 'Завершить';
    button.onclick = () => run(async () => { await api(`/api/sessions/${session.id}`, { method: 'DELETE' }); await refresh(); });
    return row(`${{ web: 'Браузер', api: 'API / интеграция', telegram: 'Telegram', mobile: 'Android' }[session.kind]}${session.id === me.sessionId ? ' · текущая' : ''}`, `До ${date(session.expires)}${session.chatId ? ' · чат ' + session.chatId : ''}`, button);
  }));
  const states = { pending: 'В очереди', sent: 'Отправлен', cancelled: 'Сессия завершена', failed: 'Не удалось доставить. Запросите /report в боте.' };
  el('deliveries').replaceChildren(...deliveries.reverse().slice(0, 20).map(job => row(states[job.state], `${job.reportId} · попыток: ${job.attempts}`)));
  if (!deliveries.length) el('deliveries').textContent = 'Отправок пока нет. Подключите Telegram перед добавлением отчёта.';
}
async function run(action) {
  try { await action(); } catch (error) { status(error.message, true); }
}
el('auth-form').onsubmit = event => {
  event.preventDefault();
  const form = event.currentTarget, button = event.submitter;
  run(async () => {
    button.disabled = true;
    try {
      await api(`/api/${button.value}`, { method: 'POST', body: JSON.stringify({ login: form.elements.login.value, password: form.elements.password.value }) });
      form.reset(); await refresh(); status('Вход выполнен.');
    } finally { button.disabled = false; }
  });
};
el('logout').onclick = () => run(async () => {
  await api('/api/logout', { method: 'POST' }); el('dashboard').hidden = true; el('auth').hidden = false;
  el('code').textContent = ''; el('code').hidden = true; status('Вы вышли из аккаунта.');
  el('integration-token').textContent = ''; el('integration-token').hidden = true;
});
el('refresh').onclick = () => run(refresh);
el('integration').onclick = () => run(async () => {
  const result = await api('/api/sessions', { method: 'POST' });
  el('integration-token').textContent = `${result.token}\nДействует до ${date(result.session.expires)}`;
  el('integration-token').hidden = false; await refresh();
});
el('link').onclick = () => run(async () => {
  const result = await api('/api/telegram/code', { method: 'POST' });
  el('code').textContent = `/login ${result.code}\nДействует до ${date(result.expires)}`; el('code').hidden = false;
});
el('upload').onsubmit = event => {
  event.preventDefault();
  run(async () => {
    const file = el('report-file').files[0];
    if (!file || file.size > 2 * 1024 * 1024) throw Error('Выберите JSON размером до 2 МБ');
    const report = JSON.parse(await file.text());
    await api('/api/reports', { method: 'POST', body: JSON.stringify(report) });
    await refresh(); status('Отчёт сохранён. Доставка в активные Telegram-сессии выполняется в течение 15 секунд.');
  });
};
refresh().catch(error => { if (error.message !== 'Войдите в аккаунт') status(error.message, true); });
