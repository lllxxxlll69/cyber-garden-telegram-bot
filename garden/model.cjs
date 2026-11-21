async function complete(post,cfg,messages){
 if(!cfg.model)throw Error('Выберите модель в настройках подключений');
 const native=new URL(cfg.endpoint).pathname==='/api/chat';
 const options=native?{...(/^qwen2\.5(?::|$)/.test(cfg.model)?{}:{think:false}),format:'json',options:{temperature:0,num_predict:800,num_ctx:4096}}:{temperature:0,max_tokens:1200,response_format:{type:'json_object'}};
 const res=await post(cfg.endpoint,{model:cfg.model,stream:false,messages,...options},cfg.key,180000);
 const reply=await res.json();
 return JSON.parse(native?reply.message.content:reply.choices[0].message.content);
}
async function generate(post,cfg,description){
 if(typeof description!=='string'||description.length>1200||!description.trim())throw Error('Введите описание до 1200 символов');
 const plan=await complete(post,cfg,[{role:'system',content:'Переведи запрос в JSON вида {"start":"manual","time":"14:00","checks":["secrets","sca","sast"],"explain":true,"notify":true}. start manual или schedule. checks включает только нужные типы в порядке выполнения. Верни строго JSON.'},{role:'user',content:description}]);
 if(!['manual','schedule'].includes(plan.start)||!Array.isArray(plan.checks)||!plan.checks.length||plan.checks.some(k=>!['sca','sast','secrets'].includes(k))||typeof plan.explain!=='boolean'||typeof plan.notify!=='boolean'||(plan.start==='schedule'&&!/^([01]\d|2[0-3]):[0-5]\d$/.test(plan.time)))throw Error('Модель вернула некорректный сценарий');
 const steps=[plan.start,...new Set(plan.checks),...(plan.explain?['ai']:[]),...(plan.notify?['notify']:[])];
 return {nodes:steps.map((type,i)=>({id:'n'+i,type,x:28+(Math.floor(i/3)%2?2-i%3:i%3)*198,y:36+Math.floor(i/3)*150,...(type==='schedule'?{time:plan.time}:{})})),edges:steps.slice(1).map((_,i)=>({from:'n'+i,to:'n'+(i+1),port:'next'}))};
}
module.exports={complete,generate};
