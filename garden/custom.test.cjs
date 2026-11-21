const {test}=require('node:test'),assert=require('node:assert/strict');
const {scanCustom,validateCustom}=require('./custom.cjs');
const {execute,plan}=require('./workflow.cjs');
const rule={title:'Запрет debug',needle:'debug=true',path:'.properties',severity:'medium',fix:'Отключить debug',caseSensitive:false};
test('Пользовательский блок: поиск, фильтр пути, регистр и безопасное evidence',()=>{
 const files={'app.properties':'ok\nDEBUG=true','src/Test.kt':'debug=true'};
 const rows=scanCustom(rule,files);assert.equal(rows.length,1);assert.equal(rows[0].line,2);
 assert.ok(!rows[0].evidence.includes('DEBUG=true'));
 assert.equal(scanCustom({...rule,caseSensitive:true},files).length,0);
 assert.equal(scanCustom({...rule,needle:'[.*]'},files).length,0);
 assert.throws(()=>validateCustom({...rule,needle:''}));
});
test('Пользовательский блок исполняется и переносится вместе со сценарием',async()=>{
 const graph={nodes:[{id:'start',type:'manual'},{id:'custom',type:'custom',definition:rule},{id:'notify',type:'notify'}],edges:[{from:'start',to:'custom',port:'next'},{from:'custom',to:'notify',port:'next'}]};
 let notified;
 const result=await execute(JSON.parse(JSON.stringify(graph)),{'app.properties':'debug=true'},[],{notify:async rows=>{notified=rows;return 'sent';}});
 assert.equal(result.ok,true);assert.equal(result.findings.length,1);assert.equal(notified[0].title,rule.title);
 graph.nodes[1].definition.severity='unknown';assert.throws(()=>plan(graph));
});
