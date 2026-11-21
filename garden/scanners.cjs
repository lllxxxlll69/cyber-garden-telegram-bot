const levels = ['info','low','medium','high','critical'];
const demoCatalog = [{module:'garden.training:demo-codec', introduced:'1.0.0', fixed:'1.2.0', id:'TRAINING-001', severity:'high'}];
const demoFiles = {
  'build.gradle.kts':'plugins { kotlin("jvm") version "2.0.21"; id("org.springframework.boot") version "3.3.5" }\ndependencies {\n    implementation("garden.training:demo-codec:1.1.0")\n}',
  'src/main/resources/application.yml':'spring:\n  datasource:\n    password: "training-local-only"',
  'src/main/kotlin/SecurityConfig.kt':'package garden.training\n\nfun configure(http: HttpSecurity) {\n    http.authorizeHttpRequests { rules ->\n        rules.anyRequest().permitAll()\n    }\n}'
};
function versionCompare(a,b) {
  const parse = v => v.split('.').map(Number);
  const left=parse(a), right=parse(b);
  for(let i=0;i<Math.max(left.length,right.length);i++) {
    const delta=(left[i]||0)-(right[i]||0);
    if(delta) return delta;
  }
  return 0;
}
const version = /^\d+(?:\.\d+){0,3}$/;
function validateCatalog(rows) {
  if(!Array.isArray(rows)||rows.length>5000||rows.some(r=>!r||typeof r.module!=='string'||!/^[-.\w]+:[-.\w]+$/.test(r.module)||!version.test(r.introduced)||!version.test(r.fixed)||versionCompare(r.introduced,r.fixed)>=0||typeof r.id!=='string'||!/^[-\w.]{1,80}$/.test(r.id)||!levels.includes(r.severity))) throw Error('Неверный формат справочника. См. пример в README.');
  return rows;
}
function scan(kind,files,catalog=demoCatalog) {
  const findings=[];
  const propertyVersions=new Map();
  for(const [file,source] of Object.entries(files)) if(file.endsWith('gradle.properties')){
    for(const m of source.matchAll(/^\s*([\w.]+)\s*=\s*([\d.]+)\s*$/gm))propertyVersions.set(m[1],m[2]);
  }
  for(const [file,source] of Object.entries(files)) {
    const variables=new Map([...source.matchAll(/\bval\s+(\w+)\s*=\s*"([\d.]+)"/g)].map(m=>[m[1],m[2]]));
    for(const [name,value] of propertyVersions) if(!variables.has(name)) variables.set(name,value);
    const lines=source.split(/\r?\n/);
    lines.forEach((line,i)=>{
      const add=(rule,severity,title,fix,reference='')=>findings.push({rule,severity,title,fix,reference,file,line:i+1});
      if(/^\s*(?:\/\/|\*|#)/.test(line)) return;
      if(kind==='secrets'){
        const match=line.match(/(?:[\w.-]*(?:password|passwd|secret|api[_-]?key|token))["']?\s*(?::\s*String\s*)?[:=]\s*(?:["']([^"'\n]+)["']|([^\s#,;}]+))/i);
        const value=match&&(match[1]||match[2]);
        if(value && (match[1]||/\.(?:properties|ya?ml|env)$|(?:^|\/)\.env$/.test(file)) && !/^(?:\$|<|\*|null$|changeme$|getenv\b|System\.)/i.test(value)) add('secret.literal','high','Секрет записан в исходниках','Вынесите значение в хранилище секретов и замените выданные учётные данные.');
        if(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) add('secret.private-key','critical','Закрытый ключ в проекте','Удалите ключ из проекта и отзовите его.');
      }
      if(kind==='sca' && file.endsWith('.gradle.kts')){
        for(const m of line.matchAll(/["']([\w.-]+:[\w.-]+):([^"']+)["']/g)){
          const v=m[2].replace(/\$\{?(\w+)\}?/g,(s,k)=>variables.get(k)||s);
          if(!version.test(v)) continue;
          for(const r of catalog.filter(r=>r.module===m[1]&&versionCompare(v,r.introduced)>=0&&versionCompare(v,r.fixed)<0))
            add('sca.range',r.severity,'Зависимость '+r.module+' '+v,'Обновите зависимость до '+r.fixed+' или совместимой исправленной версии.',r.id);
        }
      }
      if(kind==='sast' && file.endsWith('.kt')){
        const context=lines.slice(Math.max(0,i-2),i+1).join(' ').replace(/\s+/g,' ');
        if(/permitAll\s*\(/.test(line)&&/(?:anyRequest\s*\(\s*\)|requestMatchers\s*\(\s*"\/\*\*"\s*\))\s*\.\s*permitAll\s*\(/.test(context)) add('spring.public','high','Все маршруты разрешены без входа','Ограничьте публичные маршруты явным списком и потребуйте вход для остальных.');
        if(/csrf\s*(?:\([^)]*\)\s*\.|\{[^}]*?)disable\s*\(/.test(line)) add('spring.csrf','medium','Отключена защита CSRF','Проверьте способ аутентификации. Для сессий с cookie включите CSRF.');
        if(/(?:jdbcTemplate\s*\.\s*(?:query\w*|update)|executeQuery)\s*\(\s*"[^"]*(?:\$\w|\$\{|"\s*\+)/i.test(line)) add('sql.parameter','high','Данные подставляются в SQL','Передайте значения отдельными параметрами подготовленного запроса.');
      }
    });
  }
  return findings;
}
module.exports={scan,levels,demoFiles,demoCatalog,validateCatalog};
