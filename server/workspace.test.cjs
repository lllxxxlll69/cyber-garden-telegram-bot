const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {JsonRepository}=require('./store.cjs'),{ReportService}=require('./service.cjs'),{WorkspaceService,defaultGraph}=require('./workspace.cjs'),{createServer}=require('./http.cjs');
async function setup(t){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'garden-workspace-')),repo=await new JsonRepository(directory).open(),reports=new ReportService(repo),workspace=new WorkspaceService(reports);
 t.after(async()=>{await workspace.close();await repo.close();await fs.rm(directory,{recursive:true,force:true});});
 const account=await reports.login('mobile-user','test-strong-password',true,'mobile'),session=await reports.authenticate(account.token);
 return {repo,reports,workspace,account,session};
}
test('mobile sessions are persisted, authenticated, revocable and isolated',async t=>{
 const {repo,reports,account,session,workspace}=await setup(t);assert.equal(session.kind,'mobile');
 const other=await reports.login('another-user','test-strong-password',true),otherSession=await reports.authenticate(other.token);
 const project=await workspace.addProject(session,{demo:true});
 await assert.rejects(workspace.owned(otherSession,'projects',project.id),{status:404});
 assert.deepEqual(await workspace.list(otherSession,'projects'),[]);
 await repo.close();await repo.open();assert.equal((await reports.authenticate(account.token)).kind,'mobile');
 await reports.revoke(session,session.id);await assert.rejects(reports.authenticate(account.token),{status:401});
});
test('workflow executes own scanners, persists node data counts and creates a PDF report queue',async t=>{
 const {repo,reports,workspace,session}=await setup(t),project=await workspace.addProject(session,{demo:true});
 const pairing=await reports.createCode(session);await reports.link(pairing.code,12345);
 const graph=defaultGraph(),workflow=await workspace.saveWorkflow(session,{name:'Учебная проверка',projectId:project.id,graph});
 const run=await workspace.start(session,workflow.id);await workspace.close();
 const done=await workspace.owned(session,'runs',run.id);
 assert.equal(done.state,'done');assert.equal(done.findings.length,3);assert.equal(done.events.filter(e=>e.state==='Готово').length,6);
 assert.equal(done.events.find(e=>e.id==='n3'&&e.state==='Готово').count,3);
 assert.equal((await reports.report(session,done.reportId)).findings.length,3);
 assert.equal(await repo.read(s=>s.deliveries.length),1);
 assert.ok(!JSON.stringify(done).includes('training-local-only'));
 const snapshot=await workspace.list(session,'projects');assert.equal(snapshot[0].files,undefined);
});
test('workflow validates graph and project input; notify branch can skip delivery',async t=>{
 const {repo,reports,workspace,session}=await setup(t);
 await assert.rejects(workspace.addProject(session,{name:'Not confirmed',files:{'a.kt':'text'}}),{status:400});
 await assert.rejects(workspace.addProject(session,{name:'Invalid path',confirmedTraining:true,files:{'../a.kt':'text'}}),{status:400});
 const project=await workspace.addProject(session,{demo:true}),graph=defaultGraph();
 await assert.rejects(workspace.saveWorkflow(session,{name:'Bad graph',projectId:project.id,graph:{...graph,edges:[]}}),{status:400});
 graph.nodes=graph.nodes.slice(0,4);graph.edges=graph.edges.slice(0,3);
 const pair=await reports.createCode(session);await reports.link(pair.code,12345);
 const workflow=await workspace.saveWorkflow(session,{name:'Без уведомления',projectId:project.id,graph});
 const run=await workspace.start(session,workflow.id);await workspace.close();const done=await workspace.owned(session,'runs',run.id);
 assert.equal(done.state,'done');assert.equal(await repo.read(s=>s.deliveries.length),0);
 assert.equal((await workspace.sendReport(session,done.reportId)).queued,1);
 const telegram=await reports.telegramSession(12345);await reports.revoke(session,telegram.id);
 await assert.rejects(workspace.sendReport(session,done.reportId),{status:409});
});
test('templates contain a graph only and AI generation requires a configured model',async t=>{
 const {workspace,session}=await setup(t),project=await workspace.addProject(session,{demo:true});
 const workflow=await workspace.saveWorkflow(session,{name:'Шаблон',projectId:project.id,graph:defaultGraph()});
 await workspace.publish(session,{workflowId:workflow.id,description:'Базовый сценарий'});
 const templates=await workspace.templates();assert.equal(templates.length,4);
 const comprehensive=templates.find(x=>x.id==='builtin-comprehensive');
 assert.deepEqual(comprehensive.graph.nodes.map(x=>x.type),['manual','secrets','sca','sast','ai']);
 assert.equal(templates.at(-1).projectId,undefined);assert.equal(templates.at(-1).userId,undefined);
 await assert.rejects(workspace.generate('Проверь секреты'),{status:400});
});
test('full scan template retains all built-in checks when saved and run',async t=>{
 const {repo,workspace,session}=await setup(t);
 const {demoFiles}=require('../garden/scanners.cjs');
 const files={...demoFiles,'application.properties':'debug=true','build.gradle.kts':'dependencies { implementation("org.apache.commons:commons-text:1.9") }'};
 const project=await workspace.addProject(session,{name:'Проверка шаблона',confirmedTraining:true,files});
 const template=(await workspace.templates()).find(item=>item.id==='builtin-full-scan');
 const workflow=await workspace.saveWorkflow(session,{name:template.name,projectId:project.id,graph:template.graph});
 assert.deepEqual(workflow.graph,template.graph);
 const run=await workspace.start(session,workflow.id);await workspace.close();
 const done=await workspace.owned(session,'runs',run.id);
 assert.equal(done.state,'done');
 assert.deepEqual(done.coverage.map(entry=>entry.kind),['secrets','sca','sast']);
 assert.equal(done.log.filter(entry=>entry.state==='Готово').length,9);
 assert.ok(done.findings.some(f=>f.rule.startsWith('custom-')&&f.file==='application.properties'));
 assert.ok(done.findings.some(f=>f.category==='SCA'&&f.reference==='CVE-2022-42889'));
 assert.equal(await repo.read(s=>s.deliveries.length),0);
});
test('daily schedule starts once per minute and interrupted runs recover explicitly',async t=>{
 const {workspace,session,repo}=await setup(t),project=await workspace.addProject(session,{demo:true});
 const time=new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Moscow',hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date());
 const graph=defaultGraph();graph.nodes[0].type='schedule';graph.nodes[0].time=time;
 await workspace.saveWorkflow(session,{name:'По расписанию',projectId:project.id,graph,enabled:true});
 await workspace.schedule();await workspace.close();await workspace.schedule();
 assert.equal((await workspace.list(session,'runs')).length,1);
 await repo.transaction(s=>{s.runs.push({id:'interrupted',userId:session.userId,state:'running'});});
 await workspace.recover();assert.equal((await workspace.owned(session,'runs','interrupted')).state,'error');
});
test('HTTP mobile workspace routes enforce sessions, LAN allowlist and account ownership',async t=>{
 const {reports,workspace,session,account}=await setup(t),server=createServer(reports,{port:0,workspace,allowedHosts:['192.168.1.2']});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
 const base='http://127.0.0.1:'+server.address().port,headers={Authorization:'Bearer '+account.token,'Content-Type':'application/json'};
 const request=(route,method='GET',body)=>fetch(base+route,{method,headers,...(body?{body:JSON.stringify(body)}:{})});
 assert.equal((await fetch(base+'/api/workspace')).status,401);
 assert.equal((await fetch(base+'/mobile/')).status,200);
 assert.equal((await fetch(base+'/mobile/../../.env')).status,401);
 const created=await request('/api/projects','POST',{demo:true});assert.equal(created.status,201);const project=await created.json();
 const workflow=await (await request('/api/workflows','POST',{name:'Mobile',projectId:project.id,graph:defaultGraph()})).json();
 const running=await request('/api/runs','POST',{workflowId:workflow.id});assert.equal(running.status,202);const run=await running.json();await workspace.close();
 const finished=await (await request('/api/runs/'+run.id)).json();assert.equal(finished.state,'done');
 const pdf=await request('/api/reports/'+finished.reportId+'/pdf');assert.equal(pdf.headers.get('content-type'),'application/pdf');
 const other=await reports.login('outsider','test-strong-password',true);assert.equal((await fetch(base+'/api/runs/'+run.id,{headers:{Authorization:'Bearer '+other.token}})).status,404);
 assert.equal((await request('/api/me')).status,200);assert.equal((await reports.sessions(session))[0].kind,'mobile');
});
