const supported=/\.(?:kts?|properties|ya?ml|env|pem|key)$/i;
const excluded=new Set(['.git','.gradle','build','out','node_modules','.idea','target']);

function repository(raw){
  let u;try{u=new URL(raw);}catch{throw Error('Введите ссылку https://github.com/владелец/репозиторий');}
  const match=u.pathname.match(/^\/([\w.-]+)\/([\w.-]+?)\/?$/);
  if(u.protocol!=='https:'||u.hostname!=='github.com'||u.port||u.username||u.password||u.search||u.hash||!match)
    throw Error('Нужна ссылка на корень репозитория GitHub. Ветку укажите отдельно.');
  const owner=match[1],name=match[2].replace(/\.git$/,'');
  if(!name||[owner,name].some(v=>v==='.'||v==='..'))throw Error('Некорректная ссылка репозитория');
  return {owner,name};
}

async function importGithub(options,request=fetch){
  const {owner,name}=repository(options.url);
  const token=String(options.token||'').trim(),ref=String(options.branch||'').trim()||'HEAD';
  if(token.length>512||/[\r\n]/.test(token)||ref.length>200)throw Error('Некорректные параметры импорта');
  const base=`https://api.github.com/repos/${owner}/${name}`;
  const deadline=AbortSignal.timeout(120000);
  async function api(suffix){
    let response;
    try{response=await request(base+suffix,{headers:{Accept:'application/vnd.github+json',...(token?{Authorization:'Bearer '+token}:{})},redirect:'error',signal:deadline});}
    catch{throw Error('Не удалось связаться с GitHub. Проверьте сеть и повторите импорт.');}
    if(response.status===404)throw Error('Репозиторий или ветка не найдены. Для приватного проекта укажите токен с доступом к содержимому.');
    if(response.status===401)throw Error('GitHub отклонил токен. Проверьте его срок действия и права.');
    if(response.status===403||response.status===429)throw Error('GitHub ограничил запросы или запретил доступ. Проверьте права токена либо повторите позже.');
    if(!response.ok)throw Error('Ошибка GitHub: HTTP '+response.status);
    const declared=Number(response.headers.get('content-length'));
    if(declared>12000000)throw Error('Ответ GitHub слишком большой');
    let length=0;const chunks=[];
    for await(const chunk of response.body){length+=chunk.length;if(length>12000000)throw Error('Ответ GitHub слишком большой');chunks.push(Buffer.from(chunk));}
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  }
  const commit=await api('/commits/'+encodeURIComponent(ref));
  const tree=await api('/git/trees/'+encodeURIComponent(commit.commit.tree.sha)+'?recursive=1');
  if(tree.truncated)throw Error('Репозиторий слишком большой: GitHub вернул неполное дерево. Откройте локальную папку.');
  const entries=tree.tree.filter(e=>e.type==='blob'&&e.mode!=='120000'&&supported.test(e.path)&&!e.path.split('/').some(p=>excluded.has(p)));
  let bytes=0;
  for(const e of entries){
    if(e.path.startsWith('/')||e.path.includes('\\')||e.path.split('/').some(p=>!p||p==='.'||p==='..'))throw Error('Недопустимый путь в репозитории');
    if(e.size>2000000||(bytes+=e.size)>16000000||entries.length>1500)throw Error('Лимит импорта: 1500 файлов, 16 МБ суммарно, 2 МБ на файл');
  }
  if(!entries.length)throw Error('В репозитории нет поддерживаемых исходников Kotlin или конфигураций');
  const files=Object.create(null);let index=0,actual=0;
  await Promise.all(Array.from({length:Math.min(4,entries.length)},async()=>{
    while(index<entries.length){
      const entry=entries[index++],blob=await api('/git/blobs/'+encodeURIComponent(entry.sha));
      if(blob.encoding!=='base64')throw Error('GitHub вернул неподдерживаемое содержимое файла');
      const data=Buffer.from(blob.content,'base64');actual+=data.length;
      if(data.length>2000000||actual>16000000)throw Error('Превышен лимит размера проекта');
      files[entry.path]=data.toString('utf8');
    }
  }));
  return {files,name:owner+'/'+name,commit:commit.sha};
}
module.exports={repository,importGithub};
