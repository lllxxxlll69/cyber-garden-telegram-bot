const fs=require('node:fs/promises');

const normalize=path=>path.replace(/\\/g,'/');
const overlaps=(a,b)=>normalize(a.path)===normalize(b.path)&&a.line<=(b.endLine??b.line)&&b.line<=(a.endLine??a.line);
function matches(actual,expected){
  if(actual.category!==expected.category)return false;
  if(actual.category==='SCA')return normalize(actual.path)===normalize(expected.path)&&
    ['group','artifact','version'].every(key=>actual[key]===expected[key])&&expected.advisoryIds.includes(actual.advisoryId);
  return actual.class===expected.class&&[expected,...(expected.alternateLocations??[])].some(location=>overlaps(actual,location));
}

function compare(actual,truth){
  const candidates=truth.findings.map(expected=>actual.findings.flatMap((finding,i)=>matches(finding,expected)?[i]:[]));
  const assigned=new Map();
  function assign(expected,visited){
    for(const i of candidates[expected]){
      if(visited.has(i))continue;
      visited.add(i);
      if(!assigned.has(i)||assign(assigned.get(i),visited)){
        assigned.set(i,expected);
        return true;
      }
    }
    return false;
  }
  const matched=[],missing=[];
  for(const [i,row] of truth.findings.entries())(assign(i,new Set())?matched:missing).push(row.id);
  const extra=actual.findings.filter((_,i)=>!assigned.has(i));
  const controls=(truth.controls??[]).filter(row=>row.expectedFinding===false&&
    actual.findings.some(f=>matches(f,row)||f.category===row.category&&row.classAliases?.includes(f.class)&&overlaps(f,row)))
    .map(row=>row.id);
  const byCategory=Object.fromEntries(['SECRET','SAST','SCA'].map(category=>[category,{
    matched:truth.findings.filter(r=>r.category===category&&matched.includes(r.id)).length,
    missing:truth.findings.filter(r=>r.category===category&&missing.includes(r.id)).length,
    extra:extra.filter(r=>r.category===category).length
  }]));
  return {byCategory,matched,missing,extra,controls};
}

async function main(){
  const [result,reference]=process.argv.slice(2);
  if(!reference)throw Error('node garden/compare-findings.cjs RESULT.json GROUND-TRUTH.json');
  const [actual,truth]=await Promise.all([result,reference].map(file=>fs.readFile(file,'utf8').then(JSON.parse)));
  console.log(JSON.stringify(compare(actual,truth),null,2));
}
if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=2;});
module.exports={compare};
