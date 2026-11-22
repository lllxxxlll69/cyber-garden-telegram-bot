function fullScanTemplate(){
 const presets=typeof module==='undefined'?gardenBlockPresets:require('./block-presets.js');
 const checks=[
  {type:'manual'}, {type:'secrets'}, {type:'sca'}, {type:'sast'},
  ...presets.map(definition=>({type:'custom',definition:{...definition}}))
 ];
 const nodes=checks.map((check,i)=>({
  ...check,id:'n'+i,x:42+(Math.floor(i/2)%2?1-i%2:i%2)*262,y:44+Math.floor(i/2)*148
 }));
 const edges=nodes.slice(1).map((node,i)=>({from:nodes[i].id,to:node.id,port:'next'}));
 return {
  id:'builtin-full-scan',
  title:'Полная проверка проекта',
  description:'SECRET, SCA, SAST и пять дополнительных проверок по тексту исходников. Запуск по кнопке.',
  graph:{nodes,edges}
 };
}
if(typeof module!=='undefined')module.exports={fullScanTemplate};
