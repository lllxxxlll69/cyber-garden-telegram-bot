// Bounded, non-executing lexer for the Kotlin and Gradle forms used by the rules.
function tokensOf(source) {
  const tokens=[], stack=[];
  const pattern=/\s+|\/\/[^\r\n]*|\/\*|"""[\s\S]*?(?:"""|$)|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[\w]+|->|==|!=|&&|\|\||\?:|[^\s]/g;
  let line=1;
  for(let match;(match=pattern.exec(source));){
    let value=match[0];
    if(value==='/*'){
      let depth=1, end=pattern.lastIndex;
      while(end<source.length&&depth){
        if(source.startsWith('/*',end)){depth++;end+=2;}
        else if(source.startsWith('*/',end)){depth--;end+=2;}
        else end++;
      }
      value=source.slice(match.index,end);
      pattern.lastIndex=end;
    }
    if(!/^\s|^\/[/*]/.test(value)){
      const token={value,line,index:tokens.length};
      if(/^["']/.test(value)){
        const quote=value.startsWith('"""')?3:1;
        token.text=value.slice(quote,-quote);
      }
      tokens.push(token);
      if(['(','[','{'].includes(value))stack.push(token);
      if(({')':'(',']':'[','}':'{'})[value]===stack.at(-1)?.value&&stack.length){
        const open=stack.pop(); open.end=token.index;token.open=open.index;
      }
    }
    for(const ch of value)if(ch==='\n')line++;
  }
  return tokens;
}

const identifier=value=>typeof value==='string'&&/^[A-Za-z_]\w*$/.test(value);
const has=(tokens,symbol)=>tokens.some(t=>t.text===undefined&&t.value===symbol);
function split(tokens,start,end,delimiter=','){
  const parts=[];
  const offset=tokens[0]?.index??0;
  let begin=start;
  for(let i=start;i<end;i++){
    const token=tokens[i];
    if(token.end!==undefined&&token.end-offset<end){i=token.end-offset;continue;}
    if(token.value===delimiter){parts.push(tokens.slice(begin,i));begin=i+1;}
  }
  if(begin<end)parts.push(tokens.slice(begin,end));
  return parts;
}
function* calls(tokens,names){
  const offset=tokens[0]?.index??0;
  for(let i=0;i+1<tokens.length;i++){
    const token=tokens[i],open=tokens[i+1];
    if(names.has(token.value)&&open.value==='('&&open.end!==undefined){
      const end=open.end-offset;
      if(end<tokens.length)yield {token,start:i,end,args:split(tokens,i+2,end),receiver:tokens[i-1]?.value==='.'?tokens[i-2]?.value:undefined};
    }
  }
}
function literal(part){return part?.length===1?part[0].text:undefined;}
function statement(tokens,start,limit=tokens.length){
  const offset=tokens[0]?.index??0;
  let end=start;
  for(;end<limit;end++){
    const t=tokens[end],prev=tokens[end-1];
    if(t.value===';'||t.value==='}')break;
    if(end>start&&t.line>prev.line&&!['.','+','?:'].includes(t.value)&&!['=','+','.','->','?:'].includes(prev.value))break;
    if(t.end!==undefined&&t.end-offset<limit)end=t.end-offset;
  }
  return tokens.slice(start,end);
}
function* bindings(tokens,start=0,end=tokens.length){
  for(let i=start;i+2<end;i++){
    const [keyword,name]=tokens.slice(i,i+2);
    if(!['val','var','def'].includes(keyword.value)||!identifier(name.value))continue;
    let equals=i+2;
    while(equals<end&&(tokens[equals].line===name.line||tokens[equals].value==='=')&&!['=',',','(',')','{','}',';'].includes(tokens[equals].value))equals++;
    if(tokens[equals]?.value==='='&&equals+1<end)
      yield {name:name.value,token:name,expression:statement(tokens,equals+1,end)};
  }
}
function references(part,names){
  const result=new Set();
  for(const t of part){
    if(t.text===undefined){if(names.has(t.value))result.add(t.value);continue;}
    for(const m of t.text.matchAll(/(\\*)\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*))/g)){
      if(m[1].length%2===0&&names.has(m[2]||m[3]))result.add(m[2]||m[3]);
    }
  }
  return result;
}
module.exports={tokensOf,identifier,has,split,calls,literal,statement,bindings,references};
