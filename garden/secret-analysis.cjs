const {tokensOf,calls,literal,bindings,identifier,references}=require('./source-tokens.cjs');
const password=/password|passwd|passphrase/i;
const apiKey=/api[-_.]?key/i;
const sensitive=/password|passwd|passphrase|secret|api[-_.]?key|token|credential|authorization|bearer/i;
const fix='Уберите значение из исходников, храните его в секретах окружения и замените действующие учётные данные.';
const placeholder=/^(?:null|none|changeme|change[-_ ]?me|todo|example|dummy|placeholder|redacted|your|replace[-_ ]?me|insert[-_ ]?here|not[-_ ]?set)(?:$|[-_ .].*)/i;
function actual(text){
  const value=text?.trim().replace(/^Bearer\s+/i,'');
  return !!value&&!/^(?:[$<*{\[]|System\.|getenv\b)/i.test(value)&&!placeholder.test(value)&&!/^x{3,}$/i.test(value);
}
function classify(text){
  const fallback=text.match(/^\s*\$\{[\w.-]+:([^{}]*)\}\s*$/);
  if(fallback)return actual(fallback[1])?'secret-fallback':null;
  return actual(text)&&!(/^[A-Z][A-Z_0-9]*_[A-Z_0-9]+$/.test(text)&&sensitive.test(text))?'literal':null;
}
function conditionsBefore(tokens,index){
  const collected=[];
  let crossedDeclaration=false;
  for(let i=index-2;i>=0&&i>=index-120;i--){
    if(tokens[i].open!==undefined){i=tokens[i].open;continue;}
    if(tokens[i].value===';'||tokens[i].value==='{'&&tokens[i].end===undefined)break;
    if(['class','object','fun'].includes(tokens[i].value)){
      if(crossedDeclaration)break;
      crossedDeclaration=true;
    }
    if(tokens[i].value!=='@')continue;
    const annotation=tokens[i+1]?.value,open=tokens[i+2];
    if(!['Profile','ConditionalOnProperty'].includes(annotation)||open?.end===undefined)continue;
    const part=tokens.slice(i+3,open.end);
    const safe=text=>typeof text==='string'&&/^[\w.!-]{1,100}$/.test(text)?text:null;
    if(annotation==='Profile'){
      const profiles=part.map(t=>safe(t.text)).filter(Boolean);
      collected.push(profiles.length?'@Profile('+profiles.join(', ')+')':'условие @Profile');
    }else{
      const find=key=>{
        const field=part.findIndex((t,k)=>t.value===key&&part[k+1]?.value==='=');
        return field<0?null:safe(part[field+2]?.text);
      };
      const prefix=find('prefix'),name=find('name')??find('value')??safe(part[0]?.text);
      const key=name&&[prefix,name].filter(Boolean).join('.');
      const missing=part.some((t,k)=>t.value==='matchIfMissing'&&part[k+2]?.value==='true');
      const state=find('havingValue')==='true'?' = true':find('havingValue')==='false'?' = false':' соответствует условию';
      collected.push(key?'@ConditionalOnProperty('+key+state+(missing?' или свойство отсутствует':'')+')':'условие @ConditionalOnProperty');
    }
  }
  return collected.reverse();
}
function headerUse(call){
  const header=literal(call.args[0]);
  if(call.token.value==='setBearerAuth'||call.token.value==='setBasicAuth')
    return {kind:'configuration-token',arg:call.args[0],label:'заголовок авторизации'};
  if(header&&(/^(?:authorization|proxy-authorization|x-api-key|api-key)$/i.test(header)||sensitive.test(header)))
    return {kind:apiKey.test(header)?'api-key':password.test(header)?'password':'configuration-token',
      arg:call.args[1],label:'заголовок учётных данных'};
  if(/^(?:AUTHORIZATION|PROXY_AUTHORIZATION)$/.test(call.args[0]?.at(-1)?.value??''))
    return {kind:'configuration-token',arg:call.args[1],label:'заголовок авторизации'};
}
const headers=new Set(['header','setHeader','addHeader','set','add','setBearerAuth','setBasicAuth']);
function* headerUses(tokens){
  for(const call of calls(tokens,headers)){
    const header=headerUse(call);
    if(header?.arg?.length)yield {...header,token:call.token};
  }
  for(let i=0;i<tokens.length;i++){
    if(tokens[i].value!=='to')continue;
    const header=headerUse({token:{value:'map'},args:[[tokens[i-1]],[tokens[i+1]]]});
      if(header?.arg[0])yield {...header,token:tokens[i]};
  }
}
function configEntries(source,yaml){
  const entries=[],parents=[];
  for(const [i,line] of source.split(/\r?\n/).entries()){
    const match=yaml?line.match(/^(\s*)([\w.-]+):(?:\s+(.*)|\s*)$/):line.match(/^(\s*)([\w.-]+)\s*[:=]\s*(.*)$/);
    if(!match)continue;
    const [,indent,key,raw]=match;
    while(parents.length&&parents.at(-1).indent>=indent.length)parents.pop();
    if(yaml&&(!raw?.trim()||raw.trim().startsWith('#'))){parents.push({key,indent:indent.length});continue;}
    const value=(raw||'').trim().replace(/^"((?:\\.|[^"\\])*)"\s*(?:#.*)?$/,'$1')
      .replace(/^'([^']*)'\s*(?:#.*)?$/,'$1').replace(/\s+#.*$/,'');
    entries.push({key:[...parents.map(x=>x.key),key].join('.'),value,line:i+1});
  }
  return entries;
}
function staticCredential(expression,known){
  if(!expression?.length)return null;
  const chunks=[];
  for(let i=0;i<expression.length;i++){
    const token=expression[i];
    if(i%2===1){if(token.value!=='+')return null;continue;}
    const value=token.text===undefined?known.get(token.value)?.value:token.text;
    if(value===undefined||/\$(?:\{|\w)/.test(value))return null;
    chunks.push(value);
  }
  return expression.length%2?chunks.join(''):null;
}
function encodedInput(expression,known){
  const text=expression.map(t=>t.value).join('');
  if(!/^(?:String\()?Base64\.(?:(?:get(?:Url|Mime)?Decoder\(\)\.)?decode)\(/.test(text))return false;
  const decode=expression.findIndex(t=>t.value==='decode');
  const end=expression[decode+1]?.end;
  const value=end===undefined?null:staticCredential(expression.slice(decode+2,end-expression[0].index),known);
  return typeof value==='string'&&value.length>=4&&/^[A-Za-z0-9+/_-]+={0,2}$/.test(value);
}
function environmentFallback(expression,known){
  const separator=expression.findIndex(t=>t.value==='?:');
  if(separator<0)return null;
  const left=expression.slice(0,separator);
  const call=[...calls(left,new Set(['getenv']))].find(c=>c.receiver==='System');
  if(!call||!actual(staticCredential(expression.slice(separator+1),known)))return null;
  return {line:expression[separator+1].line,sensitive:sensitive.test(literal(call.args[0])??'')};
}
function scanSecrets(files,diagnose=()=>{}){
  const findings=[],uses=new Map(),seen=new Set();
  function add(file,line,kind,title,description=title,severity='high'){
    const key=file+':'+line+':'+kind;
    if(seen.has(key))return;
    seen.add(key);
    findings.push({category:'SECRET',class:kind,rule:'secret.'+kind,file,line,title,description,fix,severity,reference:''});
  }
  for(const [file,source] of Object.entries(files)){
    if(!/\.kts?$/i.test(file))continue;
    const tokens=tokensOf(source),injections=[];
    const scopes=[];
    const scopeAt=new Map();
    for(const token of tokens){
      if(token.value==='}')scopes.pop();
      scopeAt.set(token.index,scopes.at(-1));
      if(token.value==='{'&&token.end!==undefined)scopes.push(token);
    }
    const visible=(entry,at)=>!entry.scope||at.index<=entry.scope.end&&at.index>entry.scope.index;
    for(const call of calls(tokens,new Set(['Value']))){
      if(tokens[call.start-1]?.value!=='@')continue;
      const injected=literal(call.args[0])?.match(/^\\?\$\{([\w.-]+)(?::([^{}]*))?\}$/);
      if(!injected)continue;
      const next=tokens.slice(call.end+1,call.end+12);
      const i=next.findIndex(t=>t.value==='val'||t.value==='var');
      const field=i<0?next[0]?.value:next[i+1]?.value;
      if(!identifier(field))continue;
      const contextual=conditionsBefore(tokens,call.start);
      const parent=tokens.slice(0,call.start).findLast(t=>t.value==='('&&t.end>call.end);
      const owner=parent&&tokens[parent.end+1]?.value==='{'?tokens[parent.end+1]:scopeAt.get(call.token.index);
      injections.push({key:injected[1],field,line:call.token.line,contextual,scope:owner});
      if(actual(injected[2])&&sensitive.test(injected[1]+' '+field))
        add(file,call.token.line,'secret-fallback','Секрет по умолчанию в @Value','Значение по умолчанию используется при отсутствии свойства.'+(contextual.length?' Активация: '+contextual.join(' и ')+'.':''));
    }
    const entries=[];
    function knownAt(token){
      const known=new Map();
      for(const entry of entries){
        if(entry.token.index>=token.index)break;
        if(visible(entry,token))known.set(entry.name,entry);
      }
      return known;
    }
    for(const entry of bindings(tokens)){
      const known=knownAt(entry.token);
      const direct=environmentFallback(entry.expression,known);
      const alias=entry.expression.length===1?known.get(entry.expression[0].value):null;
      const fallback=direct??alias?.fallback;
      if(direct&&(direct.sensitive||sensitive.test(entry.name)))
        add(file,direct.line,'secret-fallback','Встроенный секрет по умолчанию','Литеральный fallback используется при отсутствии переменной окружения. Значение скрыто.');
      const value=staticCredential(entry.expression,known);
      const recovered=value===null&&encodedInput(entry.expression,known)||
        entry.expression.some(t=>t.text===undefined&&known.get(t.value)?.recovered);
      entries.push({...entry,value:value??undefined,recovered,fallback,scope:scopeAt.get(entry.token.index)});
    }
    for(const use of headerUses(tokens)){
      const known=knownAt(use.token);
      const fallbacks=[environmentFallback(use.arg,known),...Array.from(references(use.arg,known),name=>known.get(name).fallback)];
      for(const fallback of fallbacks.filter(Boolean))
        add(file,fallback.line,'secret-fallback','Встроенный секрет по умолчанию','Литеральный fallback переменной окружения передаётся в '+use.label+' (строка '+use.token.line+'). Значение скрыто.');
      const name=use.arg.length===1&&use.arg[0].text===undefined?use.arg[0].value:null;
      for(const injection of injections.filter(x=>x.field===name&&x.line<=use.token.line&&visible(x,use.token))){
        if(!uses.has(injection.key))uses.set(injection.key,[]);
        uses.get(injection.key).push({...injection,file,use:use.token.line,kind:use.kind});
      }
      const entry=known.get(name),value=entry?.value??staticCredential(use.arg,known);
      const recovered=entry?.recovered||encodedInput(use.arg,known)||use.arg.length>1&&value!==null;
      if(!recovered&&!fallbacks.some(Boolean)&&[use.arg,entry?.expression??[]].some(part=>part.some(t=>t.value==='Base64')))
        diagnose({category:'SECRET',file,line:use.token.line,code:'secret.dynamic-recovery',message:'Вычисление заголовка использует Base64, но входные данные не удалось восстановить статически.'});
      if(recovered||actual(value)){
        const kind=recovered||entry?.expression.length>1?'recoverable-token':use.kind;
        add(file,entry?.token.line??use.token.line,kind,'Встроенные учётные данные для HTTP',
          'Значение восстанавливается из исходников и передаётся в '+use.label+' ('+file+':'+use.token.line+'). Значение скрыто.');
      }
    }
    for(const entry of entries){
      if(!sensitive.test(entry.name)||!actual(entry.value)||seen.has(file+':'+entry.token.line+':recoverable-token'))continue;
      const kind=password.test(entry.name)?'password':apiKey.test(entry.name)?'api-key':'configuration-token';
      add(file,entry.token.line,kind,'Секрет записан в исходниках');
    }
  }
  for(const [file,source] of Object.entries(files)){
    if(/\.(?:properties|ya?ml|env)$/i.test(file)){
      const profile=file.match(/(?:^|\/)application-([\w-]+)\.ya?ml$/i)?.[1];
      for(const entry of configEntries(source,/\.ya?ml$/i.test(file))){
        const links=uses.get(entry.key)??[];
        if(!links.length&&!sensitive.test(entry.key)&&!/^Bearer\s+/i.test(entry.value))continue;
        const type=classify(entry.value);
        if(!type)continue;
        const kind=type==='secret-fallback'?type:password.test(entry.key)?'password':apiKey.test(entry.key)?'api-key':links[0]?.kind??'configuration-token';
        const activation=profile?' Файл активируется профилем '+profile+'.':'';
        const details=links.length?' Использование: '+links.slice(0,4).map(link=>link.file+':'+link.use+' через @Value'+(link.contextual.length?' ('+link.contextual.join(' и ')+')':'')).join(', ')+'.':'';
        const title=type==='secret-fallback'?'Встроенный секрет по умолчанию':'Встроенный секрет в конфигурации';
        add(file,entry.line,kind,title,(type==='secret-fallback'?'Встроенное значение используется при отсутствии внешней настройки.':'Учётные данные записаны в конфигурации.')+activation+details+' Значение скрыто.');
      }
    }
    if(/\.(?:pem|key|kts?|properties|ya?ml|env)$/i.test(file)){
      for(const [i,line] of source.split(/\r?\n/).entries()){
        if(!/^\s*(?:\/\/|\*|#)/.test(line)&&/-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----/.test(line))
          add(file,i+1,'private-key','Закрытый ключ в проекте','Обнаружен заголовок закрытого ключа. Содержимое скрыто.','critical');
      }
    }
  }
  return findings;
}
module.exports={scanSecrets};
