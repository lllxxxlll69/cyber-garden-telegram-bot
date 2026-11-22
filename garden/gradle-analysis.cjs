const {tokensOf,bindings,split,calls}=require('./source-tokens.cjs');
const levels=['info','low','medium','high','critical'];
const version=/^\d+(?:\.\d+)*$/;
const numeric=value=>typeof value==='string'&&value.length<=100&&version.test(value);
const coordinate=/^[\w.-]+:[\w.-]+$/;
function compare(a,b){
  const left=a.split('.'),right=b.split('.');
  for(let i=0;i<Math.max(left.length,right.length);i++){
    const x=BigInt(left[i]||0),y=BigInt(right[i]||0);
    if(x!==y)return x<y?-1:1;
  }
  return 0;
}
function validateCatalog(input){
  const native=!Array.isArray(input)&&input?.formatVersion===1&&input.ecosystem==='Maven'&&input.versionFormat==='numeric-dot-separated';
  const rows=native?input.vulnerabilities:input;
  const invalid=()=>{throw Error('Неверный формат справочника Maven. См. README.');};
  if(!Array.isArray(rows)||rows.length>5000)invalid();
  return rows.map(row=>{
    if(!row||typeof row!=='object')invalid();
    const module=native?row.group+':'+row.artifact:row.module;
    const severity=typeof row.severity==='string'?row.severity.toLowerCase():'';
    const id=(native&&Array.isArray(row.aliases)&&row.aliases.find(x=>typeof x==='string'&&/^CVE-\d{4}-\d+$/.test(x)))||row.id;
    if(typeof module!=='string'||!coordinate.test(module)||typeof id!=='string'||!/^[-\w.]{1,80}$/.test(id)||!levels.includes(severity))invalid();
    if(native&&(typeof row.group!=='string'||typeof row.artifact!=='string'))invalid();
    const ranges=row.ranges??[{lower:row.introduced,upper:row.fixed,lowerInclusive:true,upperInclusive:false}];
    if(!Array.isArray(ranges)||!ranges.length||ranges.length>100||ranges.some(r=>
      !r||!(r.lower===null||numeric(r.lower))||!numeric(r.upper)||
      typeof r.lowerInclusive!=='boolean'||typeof r.upperInclusive!=='boolean'||
      (r.lower!==null&&(compare(r.lower,r.upper)>0||compare(r.lower,r.upper)===0&&!(r.lowerInclusive&&r.upperInclusive)))))invalid();
    const fixedVersions=row.fixedVersions??(row.fixed?[row.fixed]:[]);
    if(!Array.isArray(fixedVersions)||fixedVersions.length>100||fixedVersions.some(v=>!numeric(v)))invalid();
    return {module,id,severity,ranges,fixedVersions};
  });
}
function affected(value,{lower,upper,lowerInclusive,upperInclusive}){
  const lo=lower===null?1:compare(value,lower),hi=compare(value,upper);
  return (lo>0||lo===0&&lowerInclusive)&&(hi<0||hi===0&&upperInclusive);
}
const configuration=/^(?:[A-Za-z_]\w*)?(?:implementation|api|runtimeOnly|compileOnly|annotationProcessor|kapt|ksp|classpath)$/i;
function dependencies(source,libraries,properties,onUnresolved){
  const tokens=tokensOf(source),values=new Map(properties),result=[];
  function resolve(part){
    const property=part?.map(token=>token.value).join('').match(/^providers\.gradleProperty\(["']([\w.-]+)["']\)\.get\(\)$/);
    if(property)return properties.get(property[1]);
    if(part?.length!==1)return undefined;
    const single=part[0];
    if(single.text===undefined)return values.get(single.value);
    let unknown=false;
    const value=single.value.startsWith("'")?single.text:single.text.replace(/\$(?:\{([\w.]+)\}|(\w+))/g,(_,braced,bare)=>{
      const resolved=values.get(braced||bare);
      if(resolved===undefined)unknown=true;
      return resolved??'';
    });
    return unknown?undefined:value;
  }
  const definitions=[...bindings(tokens)];
  for(let pass=0;pass<5;pass++){
    for(const entry of definitions){
      const value=resolve(entry.expression);
      if(value!==undefined)values.set(entry.name,value);
    }
  }
  const scopes=tokens.flatMap((t,i)=>t.value==='dependencies'&&tokens[i+1]?.value==='{'&&tokens[i+1].end!==undefined?[[i+2,tokens[i+1].end]]:[]);
  for(const [start,end] of scopes.length?scopes:[[0,tokens.length]]){
    for(let j=start;j<end;j++){
      const token=tokens[j],next=tokens[j+1];
      const isAdd=token.value==='add'&&next?.value==='(';
      if(!isAdd&&!configuration.test(token.value)||tokens[j-1]?.value==='.') {
        if(token.end!==undefined)j=token.end;
        continue;
      }
      const parenthesized=next?.value==='('&&next.end!==undefined;
      if(!parenthesized&&next?.text===undefined&&next?.value!=='libs')continue;
      let argumentsEnd=parenthesized?next.end:j+2;
      if(!parenthesized&&next.value==='libs'){
        while(argumentsEnd+1<end&&tokens[argumentsEnd].value==='.')argumentsEnd+=2;
      }
      const args=parenthesized?split(tokens,j+2,argumentsEnd):[tokens.slice(j+1,argumentsEnd)];
      const config=isAdd?resolve(args.shift()):token.value;
      if(!config||!configuration.test(config)){
        if(isAdd)onUnresolved(token.line,'gradle.configuration','Не удалось разрешить конфигурацию add(...).');
        if(parenthesized)j=argumentsEnd;
        continue;
      }
      const named=new Map(args.filter(a=>a[1]?.value==='=').map(a=>[a[0].value,resolve(a.slice(2))]));
      const alias=args[0]?.map(t=>t.value).join('').match(/^libs\.([\w.]+)$/)?.[1];
      const catalogEntry=alias?libraries.get(alias):undefined;
      const raw=resolve(args[0]);
      const match=(raw??args[0]?.[0]?.text)?.match(/^([\w.-]+:[\w.-]+)(?::([^:]+))?$/);
      const module=catalogEntry?.module??(named.has('group')&&named.has('name')?named.get('group')+':'+named.get('name'):match?.[1]);
      let declared=catalogEntry?.version??named.get('version')??match?.[2];
      const closure=tokens[argumentsEnd+(parenthesized?1:0)];
      if(closure?.value==='{'&&closure.end!==undefined){
        for(let i=closure.index+1;i<closure.end;i++){
          const open=tokens[i+1];
          if(tokens[i].value!=='version'||open?.value!=='{'||open.end===undefined)continue;
          for(const call of calls(tokens.slice(open.index+1,open.end),new Set(['strictly'])))
            declared=resolve(call.args[0]);
          i=open.end;
        }
        j=closure.end;
      }else if(parenthesized)j=argumentsEnd;
      if(module&&coordinate.test(module)&&!module.startsWith('undefined:')&&!module.endsWith(':undefined'))
        result.push({module,declared,line:token.line,configuration:config});
      else if(!['project','files','fileTree'].includes(args[0]?.[0]?.value))
        onUnresolved(token.line,'gradle.declaration','Форма объявления зависимости или её координаты не разрешены.');
    }
  }
  return result;
}

function readLock(source=''){
  const entries=new Map();
  for(const line of source.split(/\r?\n/)){
    const match=line.match(/^\s*([\w.-]+:[\w.-]+):([^=\s]+)\s*=\s*([^#]*)/);
    if(!match)continue;
    const [,module,value,configs]=match;
    if(!entries.has(module))entries.set(module,[]);
    entries.get(module).push({value,configs:configs.split(',').map(x=>x.trim())});
  }
  return entries;
}
function lockedVersion(entries,configurationName){
  if(!entries?.length)return undefined;
  const parts=configurationName.match(/^(.*?)(implementation|api|runtimeOnly|compileOnly)$/i);
  const prefix=parts?.[1]??'';
  const classpath=name=>prefix?prefix+name[0].toUpperCase()+name.slice(1):name;
  const applicable=new Set([configurationName]);
  if(parts&&parts[2].toLowerCase()!=='compileonly')applicable.add(classpath('runtimeClasspath'));
  if(parts&&parts[2].toLowerCase()!=='runtimeonly')applicable.add(classpath('compileClasspath'));
  const candidates=new Set(entries.filter(entry=>entry.configs.some(name=>applicable.has(name))).map(entry=>entry.value));
  if(!candidates.size)return undefined;
  return candidates.size===1?candidates.values().next().value:null;
}
function scanGradle(files,catalog,libraries,diagnose=()=>{}){
  const advisories=new Map(),findings=[];
  for(const item of validateCatalog(catalog)){
    if(!advisories.has(item.module))advisories.set(item.module,[]);
    advisories.get(item.module).push(item);
  }
  for(const [file,source] of Object.entries(files)){
    if(!/\.gradle(?:\.kts)?$/i.test(file)||/^(?:.*\/)?settings\.gradle(?:\.kts)?$/i.test(file))continue;
    const directory=file.slice(0,file.lastIndexOf('/')+1);
    const properties=new Map();
    for(const text of [files['gradle.properties'],files[directory+'gradle.properties']]){
      for(const [,name,value] of (text||'').matchAll(/^\s*([\w.]+)\s*=\s*([^\s#]+)\s*$/gm))properties.set(name,value);
    }
    const lock=readLock(files[directory+'gradle.lockfile']??files['gradle.lockfile']);
    const seen=new Set();
    const onUnresolved=(line,code,message)=>diagnose({category:'SCA',file,line,code,message});
    for(const {module,declared,line,configuration:config} of dependencies(source,libraries,properties,onUnresolved)){
      const locked=lockedVersion(lock.get(module),config);
      const value=locked===undefined?declared:locked;
      if(!numeric(value)){
        onUnresolved(line,locked===null?'gradle.ambiguous-lock':'gradle.unresolved-version',
          locked===null?'В lockfile несколько применимых версий '+module+'.':'Не удалось статически получить числовую версию '+module+'.');
        continue;
      }
      for(const item of advisories.get(module)||[]){
        if(!item.ranges.some(range=>affected(value,range)))continue;
        const key=[module,value,item.id].join(':');
        if(seen.has(key))continue;
        seen.add(key);
        const [group,artifact]=module.split(':');
        const fixed=item.fixedVersions.filter(v=>compare(v,value)>0&&!item.ranges.some(r=>affected(v,r))).sort(compare)[0];
        findings.push({
          category:'SCA',rule:'sca.range',file,line,group,artifact,version:value,reference:item.id,severity:item.severity,
          title:'Зависимость '+module+' '+value,
          description:'Явно объявленная зависимость. Версия '+value+(locked===undefined?' из объявления':' из gradle.lockfile')+' входит в диапазон справочника. Достижимость уязвимого кода не оценивалась.',
          fix:fixed?'Обновите зависимость до '+fixed+' или совместимой исправленной версии.':'Выберите совместимую версию вне затронутых диапазонов справочника.'
        });
      }
    }
  }
  return findings;
}
module.exports={scanGradle,validateCatalog,version,levels};
