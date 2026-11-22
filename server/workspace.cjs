const {randomUUID}=require('node:crypto');
const {AppError}=require('./service.cjs');
const {plan,execute}=require('../garden/workflow.cjs');
const {fullScanTemplate}=require('../garden/workflow-templates.js');
const {demoFiles}=require('../garden/scanners.cjs');
const {resolveCatalog}=require('../garden/catalog.cjs');
const {services,post}=require('../garden/services.cjs');
const {importGithub}=require('../garden/github.cjs');
const fail=(code,message)=>{throw new AppError(code,message);};
const types=['manual','schedule','secrets','sca','sast','custom','condition','ai','notify'];
function defaultGraph({notify=true}={}){
 const steps=['manual','secrets','sca','sast','ai'];
 if(notify)steps.push('notify');
 return {nodes:steps.map((type,i)=>({id:'n'+i,type,x:30+i%2*210,y:30+Math.floor(i/2)*140})),edges:steps.slice(1).map((_,i)=>({from:'n'+i,to:'n'+(i+1),port:'next'}))};
}
function graphValue(value){
 try{plan(value);}catch(error){fail(400,error.message);}
 const graph={nodes:value.nodes.map(n=>({id:n.id,type:n.type,x:Math.max(0,Math.min(2500,Number(n.x)||0)),y:Math.max(0,Math.min(4000,Number(n.y)||0)),...(n.level?{level:n.level}:{}),...(n.count!==undefined?{count:n.count}:{}),...(n.pattern?{pattern:n.pattern}:{}),...(n.time?{time:n.time}:{})})),edges:value.edges.map(e=>({from:e.from,to:e.to,port:e.port}))};
 for(const [i,n] of graph.nodes.entries()){
  if(n.type==='custom'){
   const {title,needle,path,severity,fix,caseSensitive}=value.nodes[i].definition;
   n.definition={title,needle,path,severity,fix,caseSensitive};
  }
  if(!/^[\w-]{1,60}$/.test(n.id))fail(400,'Недопустимый идентификатор ноды');
  if(n.pattern&&(typeof n.pattern!=='string'||n.pattern.length>120||/\([^)]*[+*][^)]*\)[+*{]/.test(n.pattern)))fail(400,'Упростите регулярное выражение (до 120 символов)');
  if(n.type==='schedule'&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(n.time||''))fail(400,'Укажите время расписания HH:MM');
 }
 return graph;
}
const title=value=>{if(typeof value!=='string'||!value.trim()||value.length>120)fail(400,'Название: 1-120 символов');return value.trim();};
class WorkspaceService{
 constructor(reports,{llm={},timezone='Europe/Moscow',github=importGithub}={}){this.reports=reports;this.repo=reports.repo;this.llm=llm;this.timezone=timezone;this.github=github;this.tasks=new Set();this.starting=new Set();}
 async recover(){await this.repo.transaction(s=>{for(const run of s.runs)if(['queued','running'].includes(run.state)){run.state='error';run.error='Сервер перезапущен. Запустите проверку повторно.';run.finished=Date.now();}});}
 async list(session,key){return this.repo.read(s=>s[key].filter(x=>x.userId===session.userId).map(({files,catalog,...x})=>{if(key==='runs'){delete x.findings;delete x.events;delete x.log;delete x.diagnostics;}return {...x,...(files?{fileCount:Object.keys(files).length}:{})};}).reverse().slice(0,100));}
 async owned(session,key,id){const value=await this.repo.read(s=>s[key].find(x=>x.id===id&&x.userId===session.userId));if(!value)fail(404,'Объект не найден');return value;}
 async addProject(session,input){
  let files,name;
  const demo=!!input?.demo;
  let catalog=resolveCatalog(undefined,{demo}),customCatalog=false;
  if(demo){files=demoFiles;name='Учебный Kotlin-проект';}
  else{
   if(input?.confirmedTraining!==true)fail(400,'Подтвердите, что проект учебный и разрешён для проверки');
   name=title(input.name||'Учебный проект');
   if(input.url){const imported=await this.github({url:input.url,branch:input.branch,token:input.token});files=imported.files;name=imported.name;}
   else files=input.files;
   if(input.catalog!=null){try{catalog=resolveCatalog(input.catalog,{custom:true});customCatalog=true;}catch(error){fail(400,error.message);}}
  }
  if(!files||typeof files!=='object'||Array.isArray(files)||!Object.keys(files).length||Object.keys(files).length>500)fail(400,'Нужно от 1 до 500 учебных файлов');
  let size=0;const clean=Object.create(null);
  for(const [file,content] of Object.entries(files)){
   if(file.length>500||file.startsWith('/')||file.includes('\\')||file.split('/').some(p=>['..','.',''].includes(p))||!/\.(kt|kts|gradle|lockfile|toml|properties|yml|yaml|env|pem|key)$/i.test(file)||typeof content!=='string')fail(400,'Неподдерживаемый файл проекта');
   size+=Buffer.byteLength(content);if(size>1500000)fail(413,'Мобильный проект: не более 1,5 МБ исходников');clean[file]=content;
  }
  const project={id:randomUUID(),userId:session.userId,name,files:clean,catalog,demo,customCatalog,created:Date.now()};
  await this.repo.transaction(s=>{s.projects.push(project);});
  return {id:project.id,name,fileCount:Object.keys(clean).length};
 }
 async saveWorkflow(session,input,id){
  const graph=graphValue(input.graph),name=title(input.name),projectId=input.projectId;
  await this.owned(session,'projects',projectId);
  const entry={id:id||randomUUID(),userId:session.userId,name,projectId,graph,enabled:input.enabled===true,updated:Date.now()};
  return this.repo.transaction(s=>{
   if(id){const index=s.workflows.findIndex(x=>x.id===id&&x.userId===session.userId);if(index<0)fail(404,'Сценарий не найден');entry.lastSchedule=s.workflows[index].lastSchedule;s.workflows[index]=entry;}
   else s.workflows.push(entry);return entry;
  });
 }
 async start(session,workflowId){
  if(this.starting.size>=2||this.starting.has(session.userId))fail(429,'Дождитесь завершения текущей проверки');
  this.starting.add(session.userId);
  try{
   const workflow=await this.owned(session,'workflows',workflowId),project=await this.owned(session,'projects',workflow.projectId);
   const run={id:randomUUID(),userId:session.userId,workflowId,projectId:project.id,name:workflow.name,project:project.name,created:Date.now(),state:'running',events:[],reportId:null};
   await this.repo.transaction(s=>{s.runs.push(run);});
   const task=this.perform(session,run,workflow,project).finally(()=>{this.tasks.delete(task);this.starting.delete(session.userId);});
   this.tasks.add(task);return run;
  }catch(error){this.starting.delete(session.userId);throw error;}
 }
 async perform(session,run,workflow,project){
  let writes=Promise.resolve();
  const status=event=>{writes=writes.then(()=>this.repo.transaction(s=>{const row=s.runs.find(x=>x.id===run.id);row.events.push({...event,time:Date.now()});}));};
  try{
   const hooks=services(this.llm);let wantsDelivery=false;
   hooks.notify=async()=>{wantsDelivery=true;return 'PDF будет поставлен в очередь после завершения проверки';};
   const demo=project.demo??(project.name==='Учебный Kotlin-проект'&&project.files['build.gradle.kts']===demoFiles['build.gradle.kts']);
   const catalog=resolveCatalog(project.catalog,{demo,custom:project.customCatalog});
   const result=await execute(workflow.graph,project.files,catalog,hooks,status);
   await writes;
   const report=await this.reports.saveReport(session,{title:project.name+' · '+workflow.name,findings:result.findings}, {deliver:wantsDelivery&&result.ok});
   await this.repo.transaction(s=>{const row=s.runs.find(x=>x.id===run.id);Object.assign(row,{state:result.ok?'done':'error',finished:Date.now(),reportId:report.id,findings:result.findings,log:result.log,diagnostics:result.diagnostics,coverage:result.coverage});});
  }catch(error){
   await writes.catch(()=>{});
   await this.repo.transaction(s=>{const row=s.runs.find(x=>x.id===run.id);row.state='error';row.error=error instanceof AppError?error.message:'Не удалось выполнить проверку';row.finished=Date.now();});
  }
 }
 async sendReport(session,id){
  await this.reports.report(session,id);
  return this.repo.transaction(s=>{
   const targets=s.sessions.filter(x=>x.userId===session.userId&&x.kind==='telegram'&&!x.revoked&&x.expires>Date.now());
   if(!targets.length)fail(409,'Подключите Telegram в профиле');
   for(const target of targets)s.deliveries.push({id:randomUUID(),reportId:id,sessionId:target.id,state:'pending',attempts:0,next:Date.now()});
   return {queued:targets.length};
  });
 }
 async publish(session,input){
  const workflow=await this.owned(session,'workflows',input.workflowId);
  const template={id:randomUUID(),userId:session.userId,name:workflow.name,description:String(input.description||'').slice(0,500),graph:workflow.graph,created:Date.now()};
  await this.repo.transaction(s=>{s.templates.push(template);});return template;
 }
 async templates(){
  const {title,...full}=fullScanTemplate();
  return this.repo.read(s=>[
   {...full,name:title},
   {id:'builtin-comprehensive',name:'Проверка с объяснением AI',description:'SECRET, SCA и SAST с пояснениями настроенной модели.',graph:defaultGraph({notify:false})},
   {id:'builtin-security',name:'Проверка с отправкой отчёта',description:'SECRET, SCA и SAST, объяснение AI и отправка в Telegram.',graph:defaultGraph()},
   ...s.templates.slice(-97).map(({userId,...x})=>x)
  ]);
 }
 async generate(description){try{return await require('../garden/model.cjs').generate(post,this.llm,description);}catch(error){fail(400,this.llm.model?'Модель недоступна или вернула некорректный сценарий':'LLM не настроена на сервере. Задайте LLM_MODEL и LLM_ENDPOINT.');}}
 async schedule(){
  if(this.ticking)return;this.ticking=true;
  try{
   const parts=new Intl.DateTimeFormat('sv-SE',{timeZone:this.timezone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date());
   const day=parts.slice(0,10),time=parts.slice(-5),key=day+' '+time;
   const candidates=await this.repo.read(s=>s.workflows.filter(w=>w.enabled&&w.lastSchedule!==key&&w.graph.nodes.some(n=>n.type==='schedule'&&n.time===time)));
   for(const workflow of candidates){
    if(this.tasks.size>=2||this.starting.has(workflow.userId))continue;
    await this.repo.transaction(s=>{s.workflows.find(w=>w.id===workflow.id).lastSchedule=key;});
    await this.start({userId:workflow.userId},workflow.id).catch(()=>{});
   }
  }finally{this.ticking=false;}
 }
 async close(){clearInterval(this.timer);await Promise.allSettled([...this.tasks]);}
}
module.exports={WorkspaceService,defaultGraph,graphValue,types};
