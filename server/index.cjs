const path = require('node:path');
const { JsonRepository } = require('./store.cjs');
const { ReportService } = require('./service.cjs');
const { createServer } = require('./http.cjs');
const { TelegramBot } = require('./telegram.cjs');
const { WorkspaceService } = require('./workspace.cjs');

async function main() {
  const host = process.env.HOST || '127.0.0.1';
  const port = Number(process.env.PORT || 8787);
  const sessionHours = Number(process.env.SESSION_HOURS || 168);
  const allowedHosts=(process.env.ALLOWED_HOSTS||'').split(',').map(v=>v.trim()).filter(Boolean);
  if (!['127.0.0.1', 'localhost','0.0.0.0'].includes(host)||host==='0.0.0.0'&&!allowedHosts.length||allowedHosts.some(h=>!/^\d{1,3}(\.\d{1,3}){3}$/.test(h))) throw Error('Для HOST=0.0.0.0 задайте ALLOWED_HOSTS с локальным IPv4 компьютера');
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !Number.isFinite(sessionHours) || sessionHours < 1 || sessionHours > 720) throw Error('Проверьте PORT и SESSION_HOURS (1-720)');
  const repo = await new JsonRepository(process.env.DATA_DIR || path.join(__dirname, 'data')).open();
  const service = new ReportService(repo, { sessionHours });
  const workspace=new WorkspaceService(service,{llm:{endpoint:process.env.LLM_ENDPOINT||'http://127.0.0.1:11434/api/chat',model:process.env.LLM_MODEL||'',key:process.env.LLM_KEY||''},timezone:process.env.SCHEDULE_TIMEZONE||'Europe/Moscow'});
  await workspace.recover();
  const bot = process.env.TELEGRAM_BOT_TOKEN ? new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, service) : null;
  const server = createServer(service, { host, port, secureCookie: process.env.COOKIE_SECURE === 'true', botEnabled: !!bot, botConnected: () => bot?.connected === true, workspace, allowedHosts });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  } catch (error) { await repo.close(); throw error; }
  console.log(`Локальный сервер: http://${host}:${port}`);
  workspace.timer=setInterval(()=>workspace.schedule().catch(()=>console.error('Ошибка расписания')),15000);
  if (!bot) console.log('Telegram отключён: задайте TELEGRAM_BOT_TOKEN в server/.env');
  let botTask = Promise.resolve(), stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true; bot?.stop();
    await new Promise(resolve => server.close(resolve));
    await botTask;
    await workspace.close();
    while (bot?.delivering) await new Promise(resolve => setTimeout(resolve, 20));
    await repo.close();
  };
  process.once('SIGINT', () => shutdown().catch(() => { process.exitCode = 1; }));
  process.once('SIGTERM', () => shutdown().catch(() => { process.exitCode = 1; }));
  if (bot) botTask = bot.run().catch(() => {
    console.error('Не удалось запустить Telegram. Проверьте токен, сеть и отсутствие webhook/другого poller.');
    process.exitCode = 1; setImmediate(() => shutdown().catch(() => { process.exitCode = 1; }));
  });
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
