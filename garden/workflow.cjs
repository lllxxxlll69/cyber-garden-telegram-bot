const {scan,levels}=require('./scanners.cjs');
const {validateCustom,scanCustom}=require('./custom.cjs');
const types=['custom','manual','schedule','secrets','sca','sast','condition','ai','notify'];
function plan(graph){
  if(!graph||!Array.isArray(graph.nodes)||!Array.isArray(graph.edges)||graph.nodes.length>64||graph.edges.length>256) throw Error('Некорректный граф');
  const nodes=new Map(graph.nodes.map(n=>[n.id,n]));
  if(nodes.size!==graph.nodes.length||graph.nodes.some(n=>!types.includes(n.type)||typeof n.id!=='string')) throw Error('Неизвестный или повторный блок');
  const starts=graph.nodes.filter(n=>['schedule','manual'].includes(n.type));
  if(starts.length!==1) throw Error('Нужен один стартовый блок');
  for(const n of graph.nodes){
    if(n.type==='custom')validateCustom(n.definition);
    if(n.level&&!levels.includes(n.level))throw Error('Неизвестная критичность');
    if(n.type==='condition'){
      if(!Number.isInteger(n.count??1)||(n.count??1)<0)throw Error('Проверьте порог числа находок');
      if(n.pattern)new RegExp(n.pattern);
    }
  }
  const pending=new Map(graph.nodes.map(n=>[n.id,0]));
  for(const e of graph.edges){
    if(!nodes.has(e.from)||!nodes.has(e.to)||e.to===starts[0].id||!(nodes.get(e.from).type==='condition'?['yes','no']:['next']).includes(e.port)) throw Error('Проверьте соединения блоков');
    pending.set(e.to,pending.get(e.to)+1);
  }
  const order=[starts[0]];
  for(const n of order) for(const e of graph.edges.filter(e=>e.from===n.id)){
    pending.set(e.to,pending.get(e.to)-1);
    if(!pending.get(e.to)) order.push(nodes.get(e.to));
  }
  if(order.length!==nodes.size||graph.nodes.some(n=>n!==starts[0]&&!graph.edges.some(e=>e.to===n.id))) throw Error('Соедините все блоки со стартом и удалите циклы');
  return order;
}
async function execute(graph,files,catalog,services,status=()=>{}){
  const order=plan(graph), inputs=new Map([[order[0].id,[]]]), all=new Map(), log=[];
  const key=f=>JSON.stringify([f.rule,f.file,f.line,f.reference]);
  for(const n of order){
    let rows=inputs.get(n.id), port='next', detail='';
    if(!rows){log.push({id:n.id,state:'Пропущен'});status(log.at(-1));continue;}
    status({id:n.id,state:'Выполняется'});
    try{
      if(['secrets','sca','sast'].includes(n.type)) rows=[...rows,...scan(n.type,files,catalog).filter(f=>levels.indexOf(f.severity)>=levels.indexOf(n.level||'info'))];
      if(n.type==='custom')rows=[...rows,...scanCustom(n.definition,files)];
      if(n.type==='condition'){
        const re=n.pattern?new RegExp(n.pattern,'i'):null;
        const pass=rows.filter(f=>levels.indexOf(f.severity)>=levels.indexOf(n.level||'high')&&(!re||re.test(f.file))).length>=Number(n.count??1);
        port=pass?'yes':'no';detail=pass?'Да':'Нет';
      }
      if(n.type==='ai' && rows.length) ({rows,detail}=await services.explain(rows));
      if(n.type==='notify') detail=await services.notify(rows);
      for(const f of rows) all.set(key(f),f);
      for(const e of graph.edges.filter(e=>e.from===n.id&&e.port===port)){
        const merged=new Map((inputs.get(e.to)||[]).map(f=>[key(f),f]));
        for(const f of rows) merged.set(key(f),{...merged.get(key(f)),...f});
        inputs.set(e.to,[...merged.values()]);
      }
      log.push({id:n.id,state:'Готово',detail,count:rows.length});
    }catch(err){log.push({id:n.id,state:'Ошибка',detail:err.message});status(log.at(-1));break;}
    status(log.at(-1));
  }
  return {time:new Date().toISOString(),findings:[...all.values()],log,ok:!log.some(l=>l.state==='Ошибка')};
}
module.exports={execute,plan};
