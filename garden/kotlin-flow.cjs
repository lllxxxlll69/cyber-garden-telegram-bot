const {identifier,has,calls,literal,bindings,references,split,statement}=require('./source-tokens.cjs');
const jdbcMethods=new Set(['query','queryForObject','queryForList','queryForMap','update','execute','executeQuery','executeUpdate','batchUpdate']);
const ownerColumn=/^(?:owner|organizer|user|account|tenant|customer|member|author|creator|created_by|createdby|principal)(?:_?(?:id|name|key))?$/i;
const sqlText=/^\s*(?:SELECT|INSERT|UPDATE|DELETE|CALL|WITH)\b/i;
const roles=new Set(['Principal','Authentication','AuthenticationPrincipal']);
const stringOperations=new Set(['trim','lowercase','uppercase','substring','replace','toString','format','plus','append']);
const empty={};
const maxDepth=6;
const maxCalls=256;

function jdbcReceivers(tokens){
  const result=new Set(['jdbcTemplate','namedParameterJdbcTemplate']);
  const types=new Set(['JdbcTemplate','NamedParameterJdbcTemplate','JdbcOperations','NamedParameterJdbcOperations','JdbcClient','Statement']);
  for(const [,type] of imports(tokens))if(types.has(type.name))types.add(type.alias);
  for(let i=0;i+2<tokens.length;i++)
    if(tokens[i+1].value===':'&&types.has(tokens[i+2].value))result.add(tokens[i].value);
  for(const b of bindings(tokens))if(b.expression.length===1&&result.has(b.expression[0].value))result.add(b.name);
  return result;
}

function packageName(tokens){
  const start=tokens.findIndex(t=>t.value==='package');
  return start<0?'':tokens.slice(start+1).filter(t=>t.line===tokens[start].line&&t.value!==';').map(t=>t.value).join('');
}
function imports(tokens){
  const names=new Map();
  for(const [i,t] of tokens.entries()){
    if(t.value!=='import')continue;
    const part=statement(tokens,i+1);
    const end=part.findIndex(x=>x.value==='as');
    const path=(end<0?part:part.slice(0,end)).map(x=>x.value).join('');
    const name=path.split('.').at(-1),alias=end<0?name:part[end+1]?.value;
    if(alias)names.set(alias,{path,name,alias});
  }
  return names;
}

function indexProject(kotlin){
  const classes=new Map(),byName=new Map(),roots=[];
  for(const file of kotlin){
    const pkg=packageName(file.tokens),aliases=imports(file.tokens);
    const context={...file,pkg,aliases,receivers:jdbcReceivers(file.tokens),classes:[]};
    for(const [i,t] of file.tokens.entries()){
      if(!['class','object','interface'].includes(t.value)||!identifier(file.tokens[i+1]?.value)||file.tokens[i-1]?.value==='::')continue;
      const name=file.tokens[i+1].value;
      let j=i+2;
      while(j<file.tokens.length&&!['{','class','object','interface',';','@','fun'].includes(file.tokens[j].value)){
        const current=file.tokens[j];
        // A new declaration on another line ends a bodyless class.
        if(current.line>file.tokens[j-1].line&&![':',',','where'].includes(current.value)&&![':',','].includes(file.tokens[j-1].value))break;
        j=(current.end??j)+1;
      }
      const body=file.tokens[j];
      if(body?.value!=='{'||body.end===undefined)continue;
      const cls={name,path:[pkg,name].filter(Boolean).join('.'),start:i,begin:j,end:body.end,methods:[],types:new Map()};
      for(let k=i;k<body.end;k++){
        const [word,colon,type]=file.tokens.slice(k,k+3);
        if(colon?.value===':'&&identifier(word.value)&&identifier(type?.value))cls.types.set(word.value,type.value);
        if(file.tokens[k].value==='fun'){
          const method=file.methods.find(f=>f.start===k);
          if(method)k=method.end-1;
        }
      }
      context.classes.push(cls);
      if(!classes.has(cls.path))classes.set(cls.path,[]);
      classes.get(cls.path).push(cls);
    }
    for(const fn of file.methods){
      fn.context=context;
      fn.cls=context.classes.filter(c=>fn.start>c.begin&&fn.start<c.end).at(-1);
      fn.types=new Map(fn.cls?.types);
      for(const p of fn.args)if(p.name&&p.type)fn.types.set(p.name,p.type);
      fn.cls?.methods.push(fn);
      if(!byName.has(fn.name))byName.set(fn.name,[]);
      byName.get(fn.name).push(fn);
      if(fn.args.some(p=>p.part.some(t=>['RequestParam','PathVariable'].includes(t.value))))roots.push(fn);
    }
  }
  return {classes,byName,roots};
}

function prepareArguments(call,fn){
  const result=new Map();
  for(const [index,arg] of call.args.entries()){
    const named=arg[1]?.value==='='&&identifier(arg[0]?.value);
    const param=named?fn.args.find(p=>p.name===arg[0].value):fn.args[index];
    if(!param?.name||result.has(param.name))return null;
    result.set(param.name,named?arg.slice(2):arg);
  }
  return fn.args.every(p=>result.has(p.name)||has(p.part,'='))?result:null;
}

function topLevelIndex(tokens,symbol){
  const offset=tokens[0]?.index??0;
  for(let i=0;i<tokens.length;i++){
    if(tokens[i].value===symbol)return i;
    if(tokens[i].end!==undefined&&tokens[i].end-offset<tokens.length)i=tokens[i].end-offset;
  }
  return -1;
}

function scanKotlinFlow(kotlin,add,diagnose){
  const {classes,byName,roots}=indexProject(kotlin);
  function resolve(fn,call,locals){
    let candidates;
    if(!call.receiver||call.receiver==='this'){
      candidates=fn.cls?.methods.filter(c=>c.name===call.token.value)??[];
      if(!call.receiver&&!candidates.length){
        const imported=fn.context.aliases.get(call.token.value);
        candidates=(byName.get(imported?.name??call.token.value)??[]).filter(c=>!c.cls&&
          (imported?[c.context.pkg,c.name].filter(Boolean).join('.')===imported.path:c.context.pkg===fn.context.pkg));
      }
    }else{
      const type=locals.get(call.receiver)?.type??fn.types.get(call.receiver)??call.receiver;
      const imported=fn.context.aliases.get(type);
      const path=imported?.path??[fn.context.pkg,type].filter(Boolean).join('.');
      candidates=(classes.get(path)??[]).flatMap(c=>c.methods.filter(m=>m.name===call.token.value));
    }
    return candidates.flatMap(fn=>{const args=prepareArguments(call,fn);return args?[[fn,args]]:[];});
  }
  for(const root of roots){
    const start=new Map();
    for(const {name,part} of root.args){
      if(!name)continue;
      start.set(name,{input:has(part,'RequestParam')?name:null,id:has(part,'PathVariable')?name:null,principal:part.some(t=>roles.has(t.value))});
    }
    const endpoint=root.annotations.some(t=>/^(?:Get|Post|Put|Patch|Delete|Request)Mapping$/.test(t));
    const read=root.annotations.includes('GetMapping')||root.annotationParts.some(a=>a.name==='RequestMapping'&&has(a.args,'GET'));
    let budget=maxCalls;
    const active=new Set();
    const warn=(fn,line,code,message)=>diagnose({category:'SAST',file:fn.context.file,line,code,message});
    function run(fn,values,entryProofs=[],entryUnknown=false){
      if(active.has(fn)||active.size>=maxDepth||budget--<=0){
        warn(fn,fn.token.line,'kotlin.flow-limit','Поток данных остановлен из-за рекурсии или лимита анализа вызовов.');
        return empty;
      }
      active.add(fn);
      const chain=[...active];
      const cache=new Map();
      const env=new Map(values);
      const proofs=[...entryProofs];
      let uncertain=entryUnknown,canReturnEarlier=false;
      let result=empty;
      function lookup(part,bindings=env,conditional=false){
        part=part??[];
        if(!part.length)return empty;
        if(part[0].value==='('&&part[0].end===part.at(-1).index)return lookup(part.slice(1,-1),bindings,conditional);
        if(part.length===1&&part[0].text===undefined)return bindings.get(part[0].value)??empty;
        const seen=[];
        const bare=part.filter(t=>t.text!==undefined);
        const callNames=new Set(part.filter((t,i)=>part[i+1]?.value==='(').map(t=>t.value));
        const candidates=[...calls(part,callNames)].filter(c=>!['if','when','require','check','for','while','return','throw'].includes(c.token.value));
        const covered=[];
        for(const call of candidates){
          if(covered.some(([a,b])=>call.start>a&&call.start<b))continue;
          const outcome=invoke(call,bindings,conditional);
          if(outcome!==null){
            covered.push([call.start,call.end]);
            seen.push(outcome);
          }
        }
        const remaining=part.filter((_,i)=>!covered.some(([a,b])=>i>=a&&i<=b));
        for(const name of references(remaining,bindings))seen.push(bindings.get(name));
        const string=part.length===1?literal(part):undefined;
        const source=seen.find(v=>v.input);
        const directMember=part.length===3&&part[1].value==='.'&&bindings.has(part[0].value);
        const row=seen.find(v=>v.row)?.row;
        const owner=part.length===1?seen[0]?.owner:directMember&&ownerColumn.test(part[2].value)?bindings.get(part[0].value).row:seen.find(v=>v.owner)?.owner;
        const firstSql=bare.find(t=>sqlText.test(t.text)&&remaining.includes(t));
        const distinctIds=new Set(seen.map(v=>v.id).filter(Boolean));
        const simpleValue=!bare.length&&(part.length===1||directMember||remaining.every(t=>t.value==='.')||covered.length&&remaining.length<=2&&remaining[1]?.value==='.');
        const singleCall=covered.length===1&&(!remaining.length||remaining.length===2&&remaining[1].value==='.');
        return {input:source?.input,id:distinctIds.size===1?distinctIds.values().next().value:null,principal:!!simpleValue&&seen.some(v=>v.principal),
          row,owner,sql:!!firstSql||seen.some(v=>v.sql),text:string??(singleCall?seen[0]?.text:undefined),
          origin:firstSql?{file:fn.context.file,line:firstSql.line}:seen.find(v=>v.origin)?.origin,
          type:seen.find(v=>v.type)?.type,proofs:singleCall?seen.flatMap(v=>v.proofs??[]):[],
          booleanProof:singleCall?seen.find(v=>v.booleanProof)?.booleanProof:null};
      }
      function invoke(call,bindings,conditional){
        if(cache.has(call.token.index))return cache.get(call.token.index);
        const recv=bindings.get(call.receiver);
        const isJdbc=jdbcMethods.has(call.token.value)&&call.receiver&&
          (fn.context.receivers.has(call.receiver)||recv?.jdbc||['executeQuery','executeUpdate'].includes(call.token.value));
        if(isJdbc){
          const query=lookup(call.args[0],bindings,conditional);
          const bound=call.args.slice(1);
          if(query.sql&&query.input){
            const origin=query.origin?.file===fn.context.file?query.origin.line:call.token.line;
            const construction=query.origin?.file!==fn.context.file&&query.origin?' Текст формируется в '+query.origin.file+':'+query.origin.line+'.':'';
            add(fn.context.file,origin,'sql-injection','high','Пользовательский ввод попадает в текст SQL',
              'Вход @RequestParam '+query.input+' проходит через '+chain.map(f=>f.name).join(' → ')+' в '+call.token.value+' (строка '+call.token.line+').'+construction,
              'Передайте пользовательские значения отдельными JDBC-параметрами.',call.token.line);
          }
          const text=query.text??'',select=/^\s*SELECT\b/i.test(text),write=/^\s*(?:UPDATE|DELETE)\b/i.test(text);
          const table=text.match(/\b(?:FROM|UPDATE)\s+([\w.]+)\b/i)?.[1]?.toLowerCase();
          const predicates=sqlPredicates(text,bound,bindings,arg=>lookup(arg,bindings,conditional));
          const keys=predicates.filter(p=>!ownerColumn.test(p.column)&&/(?:id|uuid|key|code|ref|number)$/i.test(p.column));
          const ids=new Set(keys.flatMap(p=>p.values.map(v=>v.id).filter(Boolean)));
          const fromId=table&&ids.size===1?{table,id:ids.values().next().value}:null;
          if(endpoint&&(!text||select&&read||write)&&!fromId&&bound.some(arg=>lookup(arg,bindings,conditional).id))
            warn(fn,call.token.line,'kotlin.owner-query-unsupported','Идентификатор из маршрута передаётся JDBC, но его связь с предикатом SQL не удалось разрешить.');
          const scalarOwner=select&&/^\s*SELECT\s+(?:\w+\.)?(\w+)\s+FROM\b/i.exec(text);
          const ownerOnly=!!scalarOwner&&ownerColumn.test(scalarOwner[1]);
          const ownerBound=fromId&&!/\bOR\b/i.test(text)&&predicates.some(p=>ownerColumn.test(p.column)&&
            p.values.length===1&&p.values[0].principal);
          const safePath=fromId&&proofs.some(p=>p.table===fromId.table&&p.id===fromId.id);
          if(endpoint&&fromId&&!ownerOnly&&(write||select&&read)&&!ownerBound&&!safePath){
            const message='Маршрут '+root.name+' ('+root.context.file+':'+root.token.line+') передаёт @PathVariable через '+chain.map(f=>f.name).join(' → ')+'. SQL не связывает объект с текущим пользователем.';
            if(uncertain)warn(fn,call.token.line,'kotlin.owner-guard-unknown',message+' Предшествующую внешнюю проверку подтвердить статически не удалось.');
            else add(fn.context.file,call.token.line,'object-authorization','high',write?'Изменение объекта без проверки владельца':'Чтение объекта без проверки владельца',
              message,'Проверяйте принадлежность объекта текущему пользователю до доступа или включите её в предикат SQL.',
              fn.context.tokens[call.token.index+call.end-call.start]?.line??call.token.line);
          }
          const outcome={row:fromId,owner:ownerOnly?fromId:null};
          cache.set(call.token.index,outcome);
          return outcome;
        }
        const targets=resolve(fn,call,bindings);
        if(targets.length>1){
          if(call.args.some(arg=>Array.from(references(arg,bindings)).some(key=>{const v=bindings.get(key);return v.input||v.id||v.principal;})))
            warn(fn,call.token.line,'kotlin.ambiguous-call','Для вызова '+call.token.value+' несколько подходящих объявлений. Поток по этому вызову не проверен.');
          cache.set(call.token.index,empty);
          return empty;
        }
        if(targets.length===1){
          const [target,params]=targets[0];
          const args=new Map(Array.from(params,([key,arg])=>[key,lookup(arg,bindings,conditional)]));
          const outcome=run(target,args,proofs,uncertain);
          cache.set(call.token.index,outcome);
          return outcome;
        }
        const projectCall=byName.has(call.token.value)||fn.types.has(call.receiver)||
          (call.receiver&&bindings.get(call.receiver)?.type);
        const tracked=call.args.some(arg=>Array.from(references(arg,bindings)).some(key=>{const v=bindings.get(key);return v.input||v.id||v.principal;}));
        if(projectCall&&tracked)
          warn(fn,call.token.line,'kotlin.unresolved-call','Вызов '+call.token.value+' не удалось однозначно связать с анализируемой реализацией.');
        // String conversions preserve taint, while unknown SQL builders are outside the supported semantics.
        if(!stringOperations.has(call.token.value)&&projectCall&&tracked){
          cache.set(call.token.index,empty);
          return empty;
        }
        return null;
      }
      function equality(condition,operator){
        const i=topLevelIndex(condition,operator);
        if(i<1||['||','&&'].some(token=>topLevelIndex(condition,token)>=0))return null;
        const left=lookup(condition.slice(0,i)),right=lookup(condition.slice(i+1));
        return left.owner&&right.principal?left.owner:right.owner&&left.principal?right.owner:null;
      }
      function step(part,conditional=false){
        const first=part[0];
        if(!first)return;
        if(['if','when','for','while','try'].includes(first.value)){
          const open=part[1],end=open?.value==='('?open.end-first.index:undefined;
          const tail=end!==undefined?part.slice(end+1):part.slice(1);
          const guarded=tail[0]?.value==='{'?tail.slice(1,tail[0].end-tail[0].index):tail;
          if(!conditional&&first.value==='if'&&['throw','return'].includes(guarded[0]?.value)){
            if(guarded[0].value==='return')canReturnEarlier=true;
            const proof=equality(part.slice(2,end),'!=');
            if(proof){
              proofs.push(proof);
              return;
            }
          }
          if(end!==undefined)lookup(part.slice(2,end),env,true);
          if(tail[0]?.value==='{'){
            const previous=new Map(env);
            const savedProofs=proofs.length;
            const wasUncertain=uncertain;
            if(!conditional)walk(guarded,true);
            else lookup(guarded,env,true);
            env.clear();
            for(const [name,value] of previous)env.set(name,value);
            proofs.length=savedProofs;
            uncertain=wasUncertain;
            const remaining=tail.slice(tail[0].end-tail[0].index+1);
            if(remaining[0]?.value==='else')lookup(remaining.slice(1),env,true);
          }else lookup(tail,new Map(env),true);
          return;
        }
        if(!conditional&&['require','check'].includes(first.value)&&part[1]?.value==='('){
          const condition=split(part,2,part[1].end-first.index)[0]??[];
          const proof=equality(condition,'==')??lookup(condition).booleanProof;
          if(proof)proofs.push(proof);
          else if([...calls(condition,new Set(condition.map(t=>t.value)))].some(call=>!resolve(fn,call,env).length&&call.receiver&&call.args.some(arg=>lookup(arg).id)))
            uncertain=true;
          return;
        }
        if(first.value==='return'||fn.expression){
          const expression=first.value==='return'?part.slice(1):part;
          result={...lookup(expression,env,conditional),booleanProof:equality(expression,'==')??lookup(expression,env,conditional).booleanProof};
          return;
        }
        const assignment=topLevelIndex(part,'=');
        const declaration=['val','var'].includes(first.value);
        if(assignment>0&&(declaration||assignment===1&&env.has(first.value))){
          const name=declaration?part[1].value:first.value;
          const expression=part.slice(assignment+1);
          const value=lookup(expression,env,conditional);
          const type=declaration&&part[2]?.value===':'?part[3]?.value:env.get(name)?.type;
          const alias=expression.length===1&&(fn.types.get(expression[0].value)??env.get(expression[0].value)?.type);
          const constructed=expression[1]?.value==='('?expression[0].value:null;
          env.set(name,{...value,type:type||alias||constructed||value.type,jdbc:value.jdbc||
            expression.length===1&&fn.context.receivers.has(expression[0].value),expression});
          return;
        }
        const invocation=[...calls(part,new Set([first.value,part[2]?.value]))].find(c=>c.end===part.length-1);
        const targets=invocation?resolve(fn,invocation,env):[];
        const outcome=lookup(part,env,conditional);
        if(!conditional&&invocation&&targets.length===1&&outcome.proofs?.length)proofs.push(...outcome.proofs);
        if(!conditional&&invocation&&!jdbcMethods.has(invocation.token.value)&&!targets.length&&invocation.args.some(a=>lookup(a).id)&&invocation.args.some(a=>lookup(a).principal)&&
          (invocation.receiver||byName.has(invocation.token.value)))uncertain=true;
      }
      function walk(body,conditional=false){
        for(let i=0;i<body.length;){
          const part=statement(body,i);
          i+=Math.max(part.length,1);
          step(part,conditional);
          if(part[0]?.value==='return'||part[0]?.value==='throw')break;
        }
      }
      if(fn.expression)step(fn.body);
      else walk(fn.body);
      active.delete(fn);
      return {...result,booleanProof:canReturnEarlier?null:result.booleanProof,proofs:canReturnEarlier?[]:proofs.slice(entryProofs.length)};
    }
    run(root,start);
  }
}

function sqlPredicates(sql,bound,env,value){
  const where=/\bWHERE\b([\s\S]*)/i.exec(sql);
  if(!where)return [];
  const predicates=[];
  let offset=where.index+where[0].indexOf(where[1]);
  for(const term of where[1].split(/\b(?:AND|OR)\b/i)){
    const match=/^\s*\(*\s*(?:\w+\.)?(\w+)\s*=\s*(?::(\w+)|(\?))/.exec(term);
    if(match){
      const values=[];
      if(match[3]){
        const index=(sql.slice(0,offset+term.indexOf('?')).match(/\?/g)??[]).length;
        // Row mappers and result class literals are not bound SQL parameters.
        const parameters=bound.filter(arg=>arg[0]?.value!=='{'&&!has(arg,'::')&&!arg.some((t,i)=>t.value===':'&&arg[i+1]?.value===':'));
        if(parameters[index])values.push(value(parameters[index]));
      }else{
        for(const param of bound){
          const expression=param.length===1?env.get(param[0].value)?.expression??param:param;
          for(const call of calls(expression,new Set(['mapOf','mutableMapOf','addValue','MapSqlParameterSource']))){
            if(literal(call.args[0])===match[2]&&call.args[1])values.push(value(call.args[1]));
            for(const a of call.args)
              if(a[0]?.text===match[2]&&a[1]?.value==='to')values.push(value(a.slice(2)));
          }
        }
      }
      predicates.push({column:match[1],values});
    }
    const after=sql.slice(offset+term.length).match(/^(?:AND|OR)/i)?.[0]??'';
    offset+=term.length+after.length;
  }
  return predicates;
}

module.exports={scanKotlinFlow};
