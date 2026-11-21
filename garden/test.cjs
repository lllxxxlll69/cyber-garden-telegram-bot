const {test}=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {execute,plan}=require('./workflow.cjs'),{scan,demoFiles,demoCatalog,validateCatalog}=require('./scanners.cjs'),{services}=require('./services.cjs');
test('Демо и отрицательные примеры',()=>{
 for(const kind of ['sca','sast','secrets'])assert.equal(scan(kind,demoFiles).length,1);
 const files={'build.gradle.kts':'implementation("garden.training:demo-codec:1.2.0")','application.yml':'password: ${DB_PASSWORD}','Config.kt':'rules.requestMatchers("/health").permitAll()'};
 for(const kind of ['sca','sast','secrets'])assert.equal(scan(kind,files).length,0);
 assert.throws(()=>validateCatalog([{}]));
});
test('Ветвление, цикл и отключённый блок',async()=>{
 const nodes=['manual','sca','condition','notify','ai'].map(type=>({id:type,type}));
 const edge=(from,to,port='next')=>({from,to,port});
 const edges=[edge('manual','sca'),edge('sca','condition'),edge('condition','notify','yes'),edge('condition','ai','no')];
 const g={nodes,edges};let received;
 const r=await execute(g,demoFiles,demoCatalog,{notify:async rows=>{received=rows;}});
 assert.equal(r.ok,true);assert.equal(received.length,1);assert.equal(r.log.at(-1).state,'Пропущен');
 assert.throws(()=>plan({nodes,edges:edges.slice(1)}));assert.throws(()=>plan({nodes,edges:[...edges,edge('ai','condition')]}));
});
test('HTTP-доставка и отклонение неподтверждённого CVE',async()=>{
 let payload;
 const server=http.createServer(async(req,res)=>{const chunks=[];for await(const c of req)chunks.push(c);payload=JSON.parse(Buffer.concat(chunks));res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({items:[{id:0,advice:'CVE-9999-12345'}]})}}]}));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));try{
 const url='http://127.0.0.1:'+server.address().port,s=services({model:'test',endpoint:url,hook:url}),rows=scan('secrets',demoFiles);
 await s.notify(rows);assert.equal(payload.count,1);assert.ok(!JSON.stringify(payload).includes('training-local-only'));
 const result=await s.explain(rows);assert.equal(result.rows[0].advice,undefined);assert.match(result.detail,/отклонён/);
 }finally{server.close();}
});

test('Webhook использует отдельный токен сессии и не отправляет его локальному приёмнику',async()=>{
 const authorizations=[];
 const server=http.createServer((req,res)=>{authorizations.push(req.headers.authorization);req.resume();res.end('{}');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
   const url='http://127.0.0.1:'+server.address().port;
   await services({hook:url,hookKey:'session-token',key:'model-secret'}).notify([]);
   await services({hookKey:'session-token',key:'model-secret'},url).notify([]);
   assert.deepEqual(authorizations,['Bearer session-token',undefined]);
 }finally{server.close();}
});
