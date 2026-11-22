const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { AppError } = require('./service.cjs');
const { renderPdf } = require('./pdf.cjs');
async function jsonBody(request) {
  if (!(request.headers['content-type'] || '').startsWith('application/json')) throw new AppError(415, 'Требуется application/json');
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw new AppError(413, 'Максимум 2 МБ');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString()); }
  catch { throw new AppError(400, 'Некорректный JSON'); }
}
function createServer(service, { secureCookie = false, host = '127.0.0.1', port = 8787, botEnabled = false, botConnected = () => false, workspace = null, allowedHosts = [] } = {}) {
  const origins = new Set([`http://${host}:${port}`, `http://localhost:${port}`]);
  const cookie = raw => `garden_session=${raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${raw ? Math.floor(service.ttl / 1000) : 0}${secureCookie ? '; Secure' : ''}`;
  // Restrict brute force/registration before invoking password derivation.
  const rates = new Map();
  return http.createServer({ requestTimeout: 15000, headersTimeout: 10000 }, async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); };
    try {
      // Block DNS rebinding and cross-origin browser requests to the local API.
      const actualPort = res.socket.localPort;
      const hosts = new Set([`${host}:${actualPort}`, `127.0.0.1:${actualPort}`, `localhost:${actualPort}`, ...allowedHosts.map(h=>`${h}:${actualPort}`)]);
      if (!hosts.has(req.headers.host)) throw new AppError(403, 'Недопустимый Host');
      const origin = req.headers.origin;
      if (origin && !origins.has(origin) && ![...hosts].some(h=>origin===`http://${h}`)) throw new AppError(403, 'Недопустимый Origin');
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new AppError(403, 'Межсайтовые запросы запрещены');
      const url = new URL(req.url, `http://${req.headers.host}`);
      const method = req.method;
      if(method==='GET'&&url.pathname==='/mobile/app.apk'){
        let apk;try{apk=await fs.readFile(path.join(__dirname,'../mobile/output/CyberGarden-debug.apk'));}catch{throw new AppError(404,'APK ещё не собран');}
        res.writeHead(200,{'Content-Type':'application/vnd.android.package-archive','Content-Disposition':'attachment; filename="CyberGarden-debug.apk"','Content-Length':apk.length});res.end(apk);return;
      }
      if(method==='GET'&&url.pathname.startsWith('/mobile/')){
        res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'");
        const name=url.pathname==='/mobile/'?'index.html':url.pathname.slice('/mobile/'.length);
        if(!['index.html','app.js','app.css','JetBrainsMono-Regular.woff2'].includes(name))throw new AppError(404,'Файл не найден');
        const content=await fs.readFile(path.join(__dirname,'../mobile/android/app/src/main/assets',name));
        res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.js')?'text/javascript; charset=utf-8':name.endsWith('.woff2')?'font/woff2':'text/css; charset=utf-8'});res.end(content);return;
      }
      if (method === 'GET' && ['/', '/app.js', '/style.css'].includes(url.pathname)) {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        const content = await fs.readFile(path.join(__dirname, 'public', file));
        res.writeHead(200, { 'Content-Type': file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8' });
        res.end(content); return;
      }
      if (method === 'GET' && url.pathname === '/health') return send(200, { ok: true, telegramConfigured: botEnabled, telegramConnected: botConnected() });
      if (method === 'POST' && ['/api/register', '/api/login'].includes(url.pathname)) {
        const now = Date.now();
        for (const [key, value] of rates) if (value.until <= now) rates.delete(key);
        const key = req.socket.remoteAddress;
        const rate = rates.get(key) || { count: 0, until: now + 60000 };
        rates.set(key, rate);
        if (++rate.count > 20) throw new AppError(429, 'Слишком много запросов. Повторите через минуту.');
        const data = await jsonBody(req);
        const result = await service.login(data?.login, data?.password, url.pathname === '/api/register',data?.client==='android'?'mobile':'web');
        res.setHeader('Set-Cookie', cookie(result.token));
        return send(200, result);
      }
      const bearer = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1];
      const rawCookie = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('garden_session='))?.slice(15);
      const session = await service.authenticate(bearer || rawCookie);
      if(workspace){
        if(method==='GET'&&url.pathname==='/api/workspace')return send(200,{projects:await workspace.list(session,'projects'),workflows:await workspace.list(session,'workflows'),runs:await workspace.list(session,'runs'),llm:{configured:!!workspace.llm.model,model:workspace.llm.model||null},timezone:workspace.timezone});
        if(method==='POST'&&url.pathname==='/api/projects')return send(201,await workspace.addProject(session,await jsonBody(req)));
        if(method==='POST'&&url.pathname==='/api/workflows')return send(201,await workspace.saveWorkflow(session,await jsonBody(req)));
        const workflow=url.pathname.match(/^\/api\/workflows\/([\w-]+)$/);
        if(method==='PUT'&&workflow)return send(200,await workspace.saveWorkflow(session,await jsonBody(req),workflow[1]));
        if(method==='POST'&&url.pathname==='/api/runs'){const body=await jsonBody(req);return send(202,await workspace.start(session,body.workflowId));}
        const run=url.pathname.match(/^\/api\/runs\/([\w-]+)$/);
        if(method==='GET'&&run)return send(200,await workspace.owned(session,'runs',run[1]));
        const report=url.pathname.match(/^\/api\/reports\/([\w-]+)$/);
        if(method==='GET'&&report)return send(200,await service.report(session,report[1]));
        const deliver=url.pathname.match(/^\/api\/reports\/([\w-]+)\/send$/);
        if(method==='POST'&&deliver)return send(202,await workspace.sendReport(session,deliver[1]));
        if(method==='GET'&&url.pathname==='/api/templates')return send(200,await workspace.templates());
        if(method==='POST'&&url.pathname==='/api/templates')return send(201,await workspace.publish(session,await jsonBody(req)));
        if(method==='POST'&&url.pathname==='/api/generate'){const body=await jsonBody(req);return send(200,await workspace.generate(body.description));}
      }
      if (method === 'GET' && url.pathname === '/api/me') return send(200, { sessionId: session.id, sessions: await service.sessions(session),user:await service.repo.read(s=>{const u=s.users.find(x=>x.id===session.userId);return {id:u.id,login:u.login};}) });
      if (method === 'POST' && url.pathname === '/api/sessions') return send(201, await service.integrationSession(session));
      if (method === 'POST' && url.pathname === '/api/logout') {
        await service.revoke(session, session.id); res.setHeader('Set-Cookie', cookie('')); return send(200, { ok: true });
      }
      const revoke = url.pathname.match(/^\/api\/sessions\/([a-f0-9-]+)$/);
      if (method === 'DELETE' && revoke) { await service.revoke(session, revoke[1]); return send(200, { ok: true }); }
      if (method === 'POST' && url.pathname === '/api/telegram/code') return send(200, await service.createCode(session));
      if (method === 'GET' && url.pathname === '/api/reports') return send(200, await service.reports(session));
      if (method === 'POST' && url.pathname === '/api/reports') {
        const input = await jsonBody(req);
        const includeJson = input?.includeJson === true;
        const report = await service.saveReport(session, input, { includeJson });
        return send(201, { id: report.id, count: report.findings.length, delivery: 'queued_for_active_telegram_sessions', formats: includeJson ? ['pdf', 'json'] : ['pdf'] });
      }
      if (method === 'GET' && url.pathname === '/api/deliveries') {
        return send(200, await service.repo.read(s => s.deliveries.filter(j => s.reports.some(r => r.id === j.reportId && r.userId === session.userId)).slice(-100)));
      }
      const pdf = url.pathname.match(/^\/api\/reports\/([a-f0-9-]+)\/pdf$/);
      if (method === 'GET' && pdf) {
        const buffer = await renderPdf(await service.report(session, pdf[1]));
        res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="report-${pdf[1]}.pdf"` }); res.end(buffer); return;
      }
      throw new AppError(404, 'Маршрут не найден');
    } catch (error) {
      send(error instanceof AppError ? error.status : 500, { error: error instanceof AppError ? error.message : 'Внутренняя ошибка сервера' });
    }
  });
}
module.exports = { createServer };
