const fs=require('node:fs/promises');
const {readProject}=require('./io.cjs'),{execute}=require('./workflow.cjs'),{services}=require('./services.cjs'),{validateCatalog}=require('./scanners.cjs');
const {bundledCatalog}=require('./catalog.cjs');
async function main(){
 const [directory,workflow,advisories]=process.argv.slice(2);
 if(!workflow)throw Error('node garden/cli.cjs PROJECT WORKFLOW.json [CATALOG.json]');
 const files=await readProject(directory),graph=JSON.parse(await fs.readFile(workflow,'utf8')),catalog=advisories?validateCatalog(JSON.parse(await fs.readFile(advisories,'utf8'))):bundledCatalog;
 const hooks=services({endpoint:process.env.LLM_ENDPOINT,model:process.env.LLM_MODEL,key:process.env.LLM_KEY,hook:process.env.REPORT_WEBHOOK,hookKey:process.env.REPORT_WEBHOOK_KEY});
 if(!process.env.REPORT_WEBHOOK)hooks.notify=async()=>{throw Error('Задайте REPORT_WEBHOOK для блока уведомления');};
 const report=await execute(graph,files,catalog,hooks);
 console.log(JSON.stringify(report,null,2));
 process.exitCode=!report.ok?2:report.findings.some(f=>f.severity==='critical')?1:0;
}
main().catch(e=>{console.error(e.message);process.exitCode=2;});
