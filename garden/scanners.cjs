const {scanGradle,validateCatalog,version,levels}=require('./gradle-analysis.cjs');
const {scanSecrets}=require('./secret-analysis.cjs');
const {scanSpring}=require('./spring-analysis.cjs');
const demoCatalog = [{module:'garden.training:demo-codec', introduced:'1.0.0', fixed:'1.2.0', id:'TRAINING-001', severity:'high'}];
const demoFiles = {
  'build.gradle.kts':'plugins { kotlin("jvm") version "2.0.21"; id("org.springframework.boot") version "3.3.5" }\ndependencies {\n    implementation("garden.training:demo-codec:1.1.0")\n}',
  'src/main/resources/application.yml':'spring:\n  datasource:\n    password: "training-local-only"',
  'src/main/kotlin/SecurityConfig.kt':'package garden.training\n\nfun configure(http: HttpSecurity) {\n    http.authorizeHttpRequests { rules ->\n        rules.anyRequest().permitAll()\n    }\n}'
};
// Keep strings for the rules and replace comments without changing line numbers.
function withoutCodeComments(source) {
  return source.replace(/"""[\s\S]*?(?:"""|$)|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|\/\/[^\r\n]*|\/\*[\s\S]*?(?:\*\/|$)/g, token =>
    token.startsWith('/') ? token.replace(/[^\r\n]/g, ' ') : token);
}
const kotlinReviewRules=[
  {pattern:/\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\(/,id:'process.command',severity:'medium',title:'Запуск внешнего процесса',fix:'Проверьте источник команды и аргументов. Ограничьте список разрешённых команд.'},
  {pattern:/\.\s*printStackTrace\s*\(/,id:'logging.stacktrace',severity:'low',title:'Прямой вывод трассировки стека',fix:'Проверьте, кто видит журнал. Исключите вывод чувствительных данных.'},
  {pattern:/\b(?:(?:allowCredentials|setAllowCredentials)\s*\(\s*true\s*\)|allowCredentials\s*=\s*true\b)/,id:'cors.credentials',severity:'low',title:'CORS разрешает передачу credentials',fix:'Проверьте, что разрешены только доверенные источники.'},
  {pattern:/\bMessageDigest\s*\.\s*getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)/i,id:'crypto.legacy-digest',severity:'medium',title:'Используется устаревшая хеш-функция',fix:'Проверьте назначение хеша. Для задач безопасности используйте современный алгоритм.'},
  {pattern:/\bNoopHostnameVerifier\s*(?:\.\s*INSTANCE\b|\()/,id:'tls.hostname-verification',severity:'high',title:'Используется проверяющий без валидации имени TLS-сервера',fix:'Используйте стандартную проверку имени хоста и цепочки сертификатов.'},
  {pattern:/\b(?:setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|allowUniversalAccessFromFileURLs\s*=\s*true\b)/,id:'webview.file-access',severity:'high',title:'WebView разрешает сетевой доступ из локальных файлов',fix:'Отключите универсальный доступ из файлов и ограничьте источники содержимого WebView.'}
];

function gradleVersionCatalog(source=''){
  const versions=new Map(), declarations=[];
  let section='';
  for(const line of source.split(/\r?\n/)){
    const header=line.match(/^\s*\[([\w.-]+)\]\s*(?:#.*)?$/);
    if(header){section=header[1];continue;}
    const entry=line.match(/^\s*(?:([\w.-]+)|["']([\w.-]+)["'])\s*=\s*(.*?)\s*$/);
    if(!entry)continue;
    const [,bare,quoted,value]=entry, name=bare||quoted;
    const literal=value.match(/^["']([^"']+)["']\s*(?:#.*)?$/)?.[1];
    if(section==='versions'&&literal&&version.test(literal))versions.set(name,literal);
    if(section==='libraries')declarations.push({name,value,literal});
  }
  const libraries=new Map();
  for(const {name,value,literal} of declarations){
    let module, declaredVersion;
    if(literal){
      const coordinate=literal.match(/^([\w.-]+:[\w.-]+):([^:]+)$/);
      if(coordinate)[,module,declaredVersion]=coordinate;
    }else{
      const fields=value.match(/^\{([^{}]*)\}\s*(?:#.*)?$/)?.[1];
      if(fields===undefined)continue;
      const columns=new Map([...fields.matchAll(/(?:^|,)\s*(module|group|name|version(?:\.ref)?)\s*=\s*["']([^"']*)["']/g)]
        .map(([,field,text])=>[field,text]));
      module=columns.get('module');
      if(!module&&columns.has('group')&&columns.has('name'))module=columns.get('group')+':'+columns.get('name');
      declaredVersion=columns.has('version.ref')?versions.get(columns.get('version.ref')):columns.get('version');
    }
    if(module&&/^[\w.-]+:[\w.-]+$/.test(module)&&version.test(declaredVersion))
      libraries.set(name.replace(/[-_.]+/g,'.'),{module,version:declaredVersion});
  }
  return libraries;
}

function scan(kind,files,catalog=demoCatalog,diagnose=()=>{}) {
  if(kind==='secrets')return scanSecrets(files,diagnose);
  if(kind==='sca')return scanGradle(files,catalog,gradleVersionCatalog(files['gradle/libs.versions.toml']),diagnose);
  if(kind!=='sast')return [];
  const findings=scanSpring(files,diagnose);
  const contextual=new Map();
  for(const f of findings){
    if(!contextual.has(f.file))contextual.set(f.file,[]);
    contextual.get(f.file).push(f);
  }
  for(const [file,source] of Object.entries(files)) {
    const kotlin=/\.kts?$/i.test(file);
    const config=/\.(?:properties|ya?ml)$/i.test(file);
    if(!kotlin&&!config)continue;
    const code=kotlin?withoutCodeComments(source):source;
    const covered=(kind,line)=>contextual.get(file)?.some(f=>f.class===kind&&f.line<=line&&line<=(f.endLine??f.line));
    const lines=code.split(/\r?\n/);
    lines.forEach((line,i)=>{
      const add=(rule,severity,title,fix,reference='')=>findings.push({category:'SAST',class:({'spring.public':'route-authorization','tls.hostname-verification':'tls-verification','sql.parameter':'sql-injection'})[rule]??rule,rule,severity,title,description:title,fix,reference,file,line:i+1});
      if(/^\s*(?:\/\/|\*|#)/.test(line)) return;
      if(kind==='sast' && kotlin){
        if(/\b(?:anyRequest|requestMatchers|csrf)\b/.test(line)){
          const context=lines.slice(i,i+7).join('\n').slice(0,3500);
          if(!/\bsecurityMatchers?\s*\(/.test(code)&&!covered('route-authorization',i+1)&&/^[^\n]*?\b(?:anyRequest\s*\(\s*\)|requestMatchers\s*\(\s*"\/\*\*"\s*\))\s*\.\s*permitAll\s*\(/.test(context))
            add('spring.public','high','Все маршруты разрешены без входа','Ограничьте публичные маршруты явным списком и потребуйте вход для остальных.');
          if(/^[^\n]*?\bcsrf\s*(?:\(\s*\)\s*\.\s*disable\s*\(|\{[^{}]*?\bdisable\s*\()/.test(context))
            add('spring.csrf','medium','Отключена защита CSRF','Проверьте способ аутентификации. Для сессий с cookie включите CSRF.');
        }
        const query=/\b(?:jdbcTemplate|executeQuery)\b/.test(line)&&lines.slice(i,i+7).join('\n').slice(0,3500)
          .match(/^[^\n]*?(?:\bjdbcTemplate\s*\.\s*(?:query\w*|update)|\bexecuteQuery)\s*\(\s*"((?:\\.|[^"\\\r\n])*)"\s*(\+)?/i);
        if(!covered('sql-injection',i+1)&&query&&(query[2]||/(?<!\\)\$(?:\w|\{)/.test(query[1])))
          add('sql.parameter','high','Данные подставляются в SQL','Передайте значения отдельными параметрами подготовленного запроса.');
        for(const rule of kotlinReviewRules){
          if(!rule.pattern.test(line))continue;
          if(rule.id==='cors.credentials'){
            if(!/\b(?:addCorsMappings|CorsConfiguration)\b/.test(code))
              diagnose({category:'SAST',file,line:i+1,code:'spring.cors-context',message:'Credentials разрешены. Связь с origin и приватным маршрутом не установлена.'});
          }else add(rule.id,rule.severity,rule.title,rule.fix);
        }
      }
      if(kind==='sast' && config && /^\s*debug\s*[:=]\s*["']?true["']?\s*(?:#.*)?$/i.test(line)){
        add('config.debug','low','Включён отладочный режим','Проверьте, что отладочный режим отключён в рабочем окружении.');
      }
    });
  }
  return findings;
}
function analyze(kind,files,catalog){
  const collected=new Map();
  const findings=scan(kind,files,catalog,d=>collected.set(JSON.stringify([d.file,d.line,d.code,d.message]),d));
  const extensions={
    secrets:/\.(?:kts?|properties|ya?ml|env|pem|key)$/i,
    sast:/\.(?:kts?|properties|ya?ml)$/i,
    sca:/\.(?:gradle(?:\.kts)?|properties|toml|lockfile)$/i
  };
  return {findings,diagnostics:[...collected.values()],
    coverage:{kind,fileCount:Object.keys(files).filter(f=>extensions[kind]?.test(f)).length}};
}
module.exports={scan,analyze,levels,demoFiles,demoCatalog,validateCatalog};
