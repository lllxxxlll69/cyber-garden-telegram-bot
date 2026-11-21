const {levels}=require('./scanners.cjs');
function validateCustom(rule){
  if(!rule||typeof rule!=='object')throw Error('Настройте пользовательский блок');
  for(const [key,max] of [['title',100],['needle',500],['fix',1000],['path',200]]){
    if(typeof rule[key]!=='string'||rule[key].length>max||(['title','needle','fix'].includes(key)&&!rule[key].trim()))throw Error('Проверьте название, искомый текст и рекомендацию блока');
  }
  if(!levels.includes(rule.severity)||typeof rule.caseSensitive!=='boolean')throw Error('Проверьте критичность и регистр поиска');
  if(/[\r\n]/.test(rule.needle))throw Error('Искомый текст должен занимать одну строку');
  return rule;
}
function scanCustom(definition,files){
  const rule=validateCustom(definition),rows=[];
  const needle=rule.caseSensitive?rule.needle:rule.needle.toLocaleLowerCase();
  const fingerprint=require('node:crypto').createHash('sha256').update(JSON.stringify(rule)).digest('hex').slice(0,16);
  for(const [file,source] of Object.entries(files)){
    if(rule.path&&!file.includes(rule.path))continue;
    const lines=source.split(/\r?\n/);
    for(let i=0;i<lines.length;i++){
      const line=rule.caseSensitive?lines[i]:lines[i].toLocaleLowerCase();
      if(line.includes(needle))rows.push({rule:'custom-'+fingerprint,title:rule.title,file,line:i+1,severity:rule.severity,
        evidence:'Совпадение пользовательского правила (содержимое скрыто)',fix:rule.fix});
      if(rows.length>=500)throw Error('Более 500 совпадений: уточните пользовательское правило');
    }
  }
  return rows;
}
module.exports={validateCustom,scanCustom};
