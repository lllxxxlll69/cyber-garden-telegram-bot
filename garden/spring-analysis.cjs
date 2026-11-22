const {tokensOf,identifier,has,split,calls,literal,bindings,references,statement}=require('./source-tokens.cjs');
const {scanKotlinFlow}=require('./kotlin-flow.cjs');
const verbs=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE']);
const restrictions=new Set(['authenticated','fullyAuthenticated','hasRole','hasAnyRole','hasAuthority','hasAnyAuthority','denyAll','access']);

function functions(tokens){
  const result=[];
  const offset=tokens[0]?.index??0;
  for(let i=0;i+2<tokens.length;i++){
    const [keyword,name,open]=tokens.slice(i,i+3);
    if(keyword.value!=='fun'||!identifier(name.value)||open.value!=='('||open.end===undefined)continue;
    let after=open.end-offset+1;
    while(after<tokens.length&&!['=','{','}', ';','@','fun'].includes(tokens[after].value))after++;
    if(!['=','{'].includes(tokens[after]?.value))continue;
    const brace=tokens[after].value==='{';
    let end=brace?(tokens[after].end??Infinity)-offset:after+1;
    if(end>tokens.length)continue;
    if(!brace)end=after+1+statement(tokens,after+1).length;
    const args=split(tokens,i+3,open.end-offset).map(part=>{
      const colon=part.findIndex(t=>t.value===':');
      return {name:part[colon-1]?.value,type:part[colon+1]?.value,part};
    });
    const annotationParts=[];
    for(let j=i-1;j>=0&&j>i-100;j--){
      if(tokens[j].open!==undefined){j=tokens[j].open-offset;continue;}
      if(['{','}',';','=','fun','class'].includes(tokens[j].value))break;
      if(tokens[j].value==='@'){
        const open=tokens[j+2];
        annotationParts.push({name:tokens[j+1].value,args:open?.value==='('?tokens.slice(j+3,open.end-offset):[]});
      }
    }
    result.push({name:name.value,token:keyword,args,annotationParts,annotations:annotationParts.map(a=>a.name),
      body:tokens.slice(after+1,end),expression:!brace,start:i,end});
  }
  return result;
}

function routeContains(pattern,path){
  if(pattern==='/**'||pattern==='**')return true;
  const broad=pattern.split('/'),narrow=path.split('/');
  for(let i=0;i<broad.length;i++){
    if(broad[i]==='**'&&i===broad.length-1)return true;
    if(narrow[i]===undefined||narrow[i]==='**')return false;
    if(broad[i]==='*'||/^\{\w+\}$/.test(broad[i]))continue;
    if(broad[i]!==narrow[i])return false;
  }
  return broad.length===narrow.length;
}
function overlap(a,b){
  return routeContains(a,b)?b:routeContains(b,a)?a:null;
}
function routeRules(file,tokens,methods,diagnose){
  const groups=[];
  for(const token of tokens){
    if(token.value!=='authorizeHttpRequests')continue;
    const next=tokens[token.index+1];
    const lambda=next?.value==='{'?next:next?.value==='('?tokens[next.index+1]:null;
    if(lambda?.value!=='{'||lambda.end===undefined){
      diagnose({category:'SAST',file,line:token.line,code:'spring.security-dsl',message:'Форма authorizeHttpRequests не поддерживается.'});
      continue;
    }
    const fn=methods.find(f=>f.body[0]?.index<=token.index&&f.body.at(-1)?.index>=token.index);
    const matchers=[...calls(fn?.body??tokens,new Set(['securityMatcher','securityMatchers']))];
    const scopes=matchers.flatMap(c=>c.args.map(literal).filter(p=>p?.startsWith('/')));
    const scopeUnknown=matchers.some(c=>!c.args.length||c.args.some(a=>!literal(a)?.startsWith('/')));
    if(scopeUnknown)diagnose({category:'SAST',file,line:token.line,code:'spring.security-scope',message:'Область SecurityFilterChain задана выражением, которое не удалось разрешить.'});
    const rules=[];
    for(const call of calls(tokens.slice(lambda.index+1,lambda.end),new Set(['requestMatchers','antMatchers','anyRequest']))){
      const globalEnd=call.args.length||call.token.value==='anyRequest'?lambda.index+1+call.end:-1;
      if(globalEnd<0||tokens[globalEnd+1]?.value!=='.')continue;
      const operation=tokens[globalEnd+2]?.value;
      if(operation!=='permitAll'&&!restrictions.has(operation))continue;
      const method=call.args[0]?.at(-1)?.value;
      const paths=call.token.value==='anyRequest'?['/**']:call.args.map(literal).filter(p=>p?.startsWith('/'));
      if(!paths.length){
        diagnose({category:'SAST',file,line:call.token.line,code:'spring.request-matcher',message:'Шаблон или HTTP-метод requestMatchers не удалось разрешить.'});
        rules.push({method:null,path:'/**',operation:'unknown',token:call.token});
      }
      for(const path of paths)rules.push({method:verbs.has(method)?method:null,path,operation,token:call.token});
    }
    const order=fn?.annotationParts.find(a=>a.name==='Order')?.args.map(t=>t.value).join('');
    groups.push({rules,file,line:token.line,scopeUnknown,scopes:scopes.length?scopes:['/**'],order:/^-?\d+$/.test(order)?Number(order):Infinity});
  }
  return groups;
}
function activeChain(group,path,groups){
  if(groups.some(other=>other!==group&&!other.scopeUnknown&&other.order<group.order&&other.scopes.some(scope=>routeContains(scope,path))))
    return 'shadowed';
  if(groups.some(other=>other!==group&&other.order<=group.order&&(other.scopeUnknown||other.scopes.some(scope=>overlap(scope,path)))))
    return 'uncertain';
  return 'active';
}
function routeOrder(file,groups,allGroups,add,diagnose){
  for(const group of groups){
    const {rules,scopes,scopeUnknown}=group;
    if(scopeUnknown)continue;
    for(const [i,restricted] of rules.entries()){
      if(!restrictions.has(restricted.operation)||restricted.path==='/**')continue;
      const bypasses=new Map();
      for(const method of restricted.method?[restricted.method]:verbs){
        const previous=rules.slice(0,i);
        for(const earlier of previous){
          if(earlier.operation!=='permitAll'||earlier.method&&earlier.method!==method)continue;
          const intersection=overlap(earlier.path,restricted.path);
          const path=intersection&&scopes.map(scope=>overlap(scope,intersection)).find(Boolean);
          if(!path||previous.find(rule=>(!rule.method||rule.method===method)&&routeContains(rule.path,path))!==earlier)continue;
          const activation=activeChain(group,path,allGroups);
          if(activation==='uncertain')diagnose({category:'SAST',file,line:earlier.token.line,code:'spring.chain-order',message:'Порядок пересекающихся SecurityFilterChain для маршрута не подтверждён.'});
          if(activation!=='active')continue;
          if(!bypasses.has(earlier))bypasses.set(earlier,{path,methods:[]});
          bypasses.get(earlier).methods.push(method);
        }
      }
      for(const [earlier,{path,methods}] of bypasses)
        add(file,earlier.token.line,'route-authorization','high','Публичное правило перекрывает ограничение маршрута',
          (methods.length===verbs.size?'Любой стандартный HTTP-метод':methods.join(', '))+' '+path+' подпадает под более ранний permitAll для '+earlier.path+
          '. Для этого пересечения ограничение на строке '+restricted.token.line+' не применяется.',
          'Проверьте, является ли маршрут публичным по политике доступа, и скорректируйте порядок или шаблоны правил.',
          earlier.path===path&&earlier.path!==restricted.path?earlier.token.line:restricted.token.line);
    }
  }
}
function hostnameVerifiers(file,tokens,add){
  const alwaysTrue=part=>{
    const index=part.findIndex((t,i)=>t.value==='HostnameVerifier'&&part[i+1]?.value==='{');
    if(index<0)return false;
    const open=part[index+1],body=part.slice(index+2,open.end-part[0].index);
    const arrow=body.findIndex(t=>t.value==='->');
    return arrow>=0&&body.slice(arrow+1).filter(t=>t.value!==';').map(t=>t.value).join('')==='true';
  };
  const verifiers=new Set();
  for(const b of bindings(tokens))
    if(alwaysTrue(b.expression)||b.expression.length===1&&verifiers.has(b.expression[0].value))verifiers.add(b.name);
  const report=token=>add(file,token.line,'tls-verification','high','HTTPS-соединение принимает любое имя хоста',
    'К HTTPS-соединению подключён HostnameVerifier, возвращающий true для любого имени.',
    'Оставьте стандартную проверку имени хоста и используйте сертификат с корректным именем.');
  for(const call of calls(tokens,new Set(['setHostnameVerifier','setDefaultHostnameVerifier','hostnameVerifier'])))
    if(alwaysTrue(call.args[0]??[])||verifiers.has(call.args[0]?.[0]?.value))report(call.token);
  const connections=new Set([...bindings(tokens)].filter(b=>has(b.expression,'HttpsURLConnection')||has(b.expression,'openConnection')).map(b=>b.name));
  for(const [i,t] of tokens.entries()){
    if(t.value!=='hostnameVerifier'||tokens[i+1]?.value!=='=')continue;
    const expression=statement(tokens,i+2);
    if(!alwaysTrue(expression)&&!(expression.length===1&&verifiers.has(expression[0].value)))continue;
    const attached=tokens[i-1]?.value==='.'&&connections.has(tokens[i-2]?.value);
    const apply=tokens.slice(0,i).findLast((t,k)=>t.value==='{'&&t.end>i&&tokens[k-1]?.value==='apply');
    const receiver=apply&&tokens.slice(Math.max(0,apply.index-24),apply.index-1);
    if(attached||receiver&&(has(receiver,'HttpsURLConnection')||has(receiver,'openConnection')||connections.has(receiver.at(-2)?.value)))report(t);
  }
}
function tls(file,tokens,add){
  hostnameVerifiers(file,tokens,add);
  const contexts=[...bindings(tokens)].filter(entry=>entry.expression.some(t=>t.value==='SSLContext')).map(x=>x.name);
  if(!contexts.length)return;
  const initializers=[...calls(tokens,new Set(['init']))].filter(c=>contexts.includes(c.receiver));
  const clients=[...calls(tokens,new Set(['sslContext','setSSLContext','setSslContext']))];
  for(let i=0;i<tokens.length;i++){
    const t=tokens[i];
    if(t.value!=='X509TrustManager'||tokens[i+1]?.value!=='{'||tokens[i+1].end===undefined)continue;
    const open=tokens[i+1], trust=tokens.slice(Math.max(0,i-32),i);
    let binding;
    for(let j=trust.length-2;j>=0;j--){
      if(trust[j].value==='}'||trust[j].value==='{')break;
      if(trust[j].value==='val'||trust[j].value==='var'||trust[j].value==='class'){
        binding=trust[j+1].value;
        break;
      }
    }
    if(!binding)continue;
    const empty=functions(tokens.slice(open.index+1,open.end)).find(f=>f.name==='checkServerTrusted'&&!f.body.length);
    if(!empty)continue;
    const trustAliases=new Set([binding]);
    for(const entry of bindings(tokens))
      if(references(entry.expression,trustAliases).size)trustAliases.add(entry.name);
    const init=initializers.find(c=>references(c.args[1]??[],trustAliases).size);
    const client=init&&clients.find(c=>has(c.args[0]??[],init.receiver)&&c.token.index>init.token.index);
    if(client)add(file,empty.token.line,'tls-verification','high','HTTP-клиент использует TrustManager без проверки сертификата',
      'Пустой checkServerTrusted подключён к SSLContext на строке '+init.token.line+' и к HTTP-клиенту на строке '+client.token.line+'.',
      'Используйте стандартный TrustManager или доверенное хранилище сертификатов.',empty.token.line);
  }
}
function cors(file,tokens,groups,add,diagnose){
  const names=new Set(['addMapping','allowedOriginPatterns','allowedOrigins','allowCredentials','allowedMethods']);
  const policies=new Map(),registrations=[];
  for(const start of calls(tokens,new Set(['addMapping']))){
    const path=literal(start.args[0]);
    if(!path)continue;
    const config=new Map();
    let index=start.end+1;
    while(tokens[index]?.value==='.'&&names.has(tokens[index+1]?.value)&&tokens[index+2]?.end!==undefined){
      const name=tokens[index+1],end=tokens[index+2].end;
      config.set(name.value,{line:name.line,args:split(tokens,index+3,end)});
      index=end+1;
    }
    registrations.push({path,config,line:start.token.line});
  }
  for(const b of bindings(tokens)){
    if(b.expression.length===1&&policies.has(b.expression[0].value)){
      policies.set(b.name,policies.get(b.expression[0].value));
      continue;
    }
    const constructor=b.expression.findIndex(t=>t.value==='CorsConfiguration');
    const open=b.expression.find((t,i)=>i>constructor&&t.value==='{'&&b.expression[i-1]?.value==='apply');
    if(constructor<0||!open)continue;
    const config=new Map();
    for(let i=open.index+1;i<open.end;i++){
      const token=tokens[i];
      if(!names.has(token.value)||tokens[i+1]?.value!=='=')continue;
      const expression=statement(tokens,i+2,open.end);
      const list=[...calls(expression,new Set(['listOf','setOf','mutableListOf','arrayOf']))][0];
      config.set(token.value,{line:token.line,args:list?.args??[expression]});
    }
    policies.set(b.name,config);
  }
  for(const call of calls(tokens,new Set(['registerCorsConfiguration']))){
    const path=literal(call.args[0]),config=policies.get(call.args[1]?.[0]?.value);
    if(path&&config)registrations.push({path,config,line:call.token.line});
    else diagnose({category:'SAST',file,line:call.token.line,code:'spring.cors-registration',message:'Не удалось связать маршрут с локальной CorsConfiguration.'});
  }
  for(const {path,config,line} of registrations){
    const credentials=config.get('allowCredentials');
    if(credentials?.args[0]?.length!==1||!has(credentials.args[0],'true'))continue;
    const allowed=config.get('allowedMethods')?.args.map(literal);
    const origin=config.get('allowedOriginPatterns');
    const patterns=origin?.args.map(literal)??[];
    if(patterns.includes(undefined)||allowed?.includes(undefined)){
      diagnose({category:'SAST',file,line,code:'spring.cors-policy',message:'Список разрешённых origin или HTTP-методов не удалось разрешить.'});
      continue;
    }
    const any=patterns.includes('*'),wildcard=patterns.some(p=>/^https?:\/\/\*\./i.test(p??''));
    if(!any&&!wildcard)continue;
    const methods=!allowed||allowed.includes('*')?verbs:allowed;
    let ambiguous=false;
    const protectedRoute=groups.some(group=>!group.scopeUnknown&&group.rules.some((rule,i)=>{
      if(!restrictions.has(rule.operation)||rule.operation==='denyAll')return false;
      const shared=overlap(path,rule.path);
      if(!shared)return false;
      return group.scopes.some(scope=>{
        const candidate=overlap(scope,shared);
        if(!candidate)return false;
        const activation=activeChain(group,candidate,groups);
        if(activation!=='active'){
          ambiguous||=activation==='uncertain';
          return false;
        }
        return [...methods].some(method=>(!rule.method||method===rule.method)&&
          !group.rules.slice(0,i).some(earlier=>(!earlier.method||earlier.method===method)&&routeContains(earlier.path,candidate)));
      });
    }));
    if(ambiguous&&!protectedRoute)diagnose({category:'SAST',file,line,code:'spring.cors-chain',message:'По пересекающимся SecurityFilterChain нельзя однозначно связать CORS с приватным маршрутом.'});
    if(!protectedRoute)continue;
    const description=any?'В политике приватных маршрутов разрешён любой Origin с учётными данными.':
      'Политика приватных маршрутов допускает wildcard-поддомены. Риск возникает при контроле подходящего поддомена и передаче браузером учётных данных.';
    add(file,origin.line,'credentialed-cors',any?'high':'medium','Излишне широкий CORS с учётными данными',
      description+' Шаблон маршрутов: '+path+'.','Разрешите только явно доверенные origins или отключите передачу учётных данных.',credentials.line);
  }
}

function scanSpring(files,diagnose=()=>{}){
  const findings=[],seen=new Set();
  const add=(file,line,kind,severity,title,description,fix,last=line)=>{
    const key=[file,line,kind,description].join(':');
    if(seen.has(key))return;
    seen.add(key);
    const endLine=Math.min(last,line+14);
    findings.push({category:'SAST',class:kind,rule:kind,file,line,...(endLine>line?{endLine}:{}),severity,title,description,fix,reference:''});
  };
  const kotlin=Object.entries(files).filter(([file])=>/\.kt$/i.test(file)).map(([file,source])=>{
    const tokens=tokensOf(source);
    const methods=functions(tokens);
    return {file,tokens,methods,routes:routeRules(file,tokens,methods,diagnose)};
  });
  const groups=kotlin.flatMap(k=>k.routes);
  for(const {file,tokens,routes} of kotlin){
    tls(file,tokens,add);
    routeOrder(file,routes,groups,add,diagnose);
    cors(file,tokens,groups,add,diagnose);
  }
  scanKotlinFlow(kotlin,add,diagnose);
  return findings;
}
module.exports={scanSpring};
