function endpoint(raw){
  const u=new URL(raw);
  if(u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname))) throw Error('Для удалённых сервисов требуется HTTPS');
  return u;
}
async function post(url,body,key,timeout){
  const res=await fetch(endpoint(url),{method:'POST',redirect:'error',headers:{'Content-Type':'application/json',...(key?{Authorization:'Bearer '+key}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(timeout)});
  if(!res.ok) throw Error('HTTP '+res.status);
  return res;
}
function services(cfg,localHook){
  return {
    async explain(rows){
      if(!cfg.model) return {rows,detail:'Модель не выбрана · рекомендации правил'};
      // References are rendered exclusively from the original evidence.
      const groups=[...new Map(rows.map(f=>[f.rule+'|'+f.title,f])).values()].slice(0,24);
      try{
        const data=groups.map(({title,fix},id)=>({id,title,fix}));
        const parsed=await require('./model.cjs').complete(post,cfg,[{role:'system',content:'Объясни разработчику риски по-русски. Только JSON {"items":[{"id":0,"advice":"одно практическое предложение"}]}. Используй только данные правил. Не указывай файлы, строки, версии или идентификаторы уязвимостей.'},{role:'user',content:JSON.stringify(data)}]);

        if(!Array.isArray(parsed.items)||parsed.items.length!==groups.length) throw Error();
        const advice=new Map();
        for(const item of parsed.items){
          if(!Number.isInteger(item.id)||!groups[item.id]||advice.has(item.id)||typeof item.advice!=='string'||!item.advice.trim()||item.advice.length>600||/CVE|GHSA|[\\/]|\.(?:kt|yml|java|properties)\b|строк\w*\s*\d/i.test(item.advice)) throw Error();
          advice.set(item.id,item.advice);
        }
        return {rows:rows.map(f=>{const i=groups.findIndex(g=>g.title===f.title&&g.rule===f.rule);return i<0?f:{...f,advice:advice.get(i)};}),detail:cfg.model+' · '+advice.size+' групп'};
      }catch{return {rows,detail:'Ответ модели недоступен или отклонён · рекомендации правил'};}
    },
    async notify(rows){
      await post(cfg.hook||localHook,{event:'security.report',time:new Date().toISOString(),count:rows.length,findings:rows},cfg.hook?cfg.hookKey:null,10000);
      return cfg.hook?'Webhook доставлен':'Доставлено в локальный HTTP-приёмник';
    }
  };
}
module.exports={services,endpoint,post};
