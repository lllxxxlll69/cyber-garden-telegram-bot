const {test}=require('node:test'),assert=require('node:assert/strict');
const {repository,importGithub}=require('./github.cjs');

test('GitHub: rejects external addresses and credentials in URLs',()=>{
  assert.deepEqual(repository('https://github.com/team/project.git'),{owner:'team',name:'project'});
  for(const url of ['http://github.com/a/b','https://github.com.evil.test/a/b','https://token@github.com/a/b','https://github.com/a/b/tree/main'])assert.throws(()=>repository(url));
});
test('GitHub: imports a pinned snapshot, skips symlinks and build output',async()=>{
  const calls=[];
  const request=async(url,options)=>{
    calls.push({url,options});
    const data=url.includes('/commits/')?{sha:'commit-id',commit:{tree:{sha:'tree-id'}}}:
      url.includes('/git/trees/')?{tree:[
        {path:'src/App.kt',type:'blob',mode:'100644',size:5,sha:'blob-id'},
        {path:'build/App.kt',type:'blob',mode:'100644',size:5,sha:'ignored'},
        {path:'link.kt',type:'blob',mode:'120000',size:5,sha:'ignored'}
      ]}:{encoding:'base64',content:Buffer.from('hello').toString('base64')};
    return new Response(JSON.stringify(data));
  };
  const result=await importGithub({url:'https://github.com/team/project',branch:'feature/import',token:'test-token'},request);
  assert.equal(result.files['src/App.kt'],'hello');assert.equal(Object.keys(result.files).length,1);
  assert.equal(result.commit,'commit-id');assert.equal(calls.length,3);
  assert.ok(calls[0].url.endsWith('/commits/feature%2Fimport'));
  assert.ok(calls[1].url.includes('/trees/tree-id'));
  assert.equal(calls[0].options.headers.Authorization,'Bearer test-token');
  assert.ok(!JSON.stringify(result).includes('test-token'));
});
test('GitHub: rejects incomplete trees, oversized files and authorization failures',async()=>{
  for(const tree of [{truncated:true},{tree:[{path:'App.kt',type:'blob',mode:'100644',size:2000001,sha:'x'}]}]){
    await assert.rejects(importGithub({url:'https://github.com/a/b'},async url=>new Response(JSON.stringify(url.includes('/commits/')?{commit:{tree:{sha:'x'}}}:tree))));
  }
  await assert.rejects(importGithub({url:'https://github.com/a/b'},async()=>new Response('',{status:401})),/токен/);
});
