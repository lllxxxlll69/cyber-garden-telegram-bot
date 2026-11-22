const fs=require('node:fs/promises');
const path=require('node:path');
const {readProject}=require('./io.cjs');
const {analyze,validateCatalog}=require('./scanners.cjs');

const kinds={SECRET:'secrets',SAST:'sast',SCA:'sca'};

function submission(findings){
  return {findings:findings.map(f=>{
    const common={category:f.category,path:f.file,severity:f.severity.toUpperCase(),description:f.description,remediation:f.fix};
    if(f.category==='SCA')return {...common,group:f.group,artifact:f.artifact,version:f.version,advisoryId:f.reference};
    return {...common,class:f.class,line:f.line,...(f.endLine?{endLine:f.endLine}:{})};
  })};
}

function readableReport(findings,project,files,baseline,diagnostics=[],coverage=[]){
  const lines=['# Отчёт Cyber Garden','',`Проект \`${project}\`. Прочитано файлов: ${files}. Проверка статическая. Значения секретов скрыты.`,''];
  if(baseline){
    lines.push('## До и после','',
      'Старый анализатор не принимал исходный формат справочника кейса. Для базового SCA-прогона использована совместимая проекция диапазонов с включённой нижней и исключённой верхней границами. Повторный прогон использовал полный справочник без преобразования.','',
      '| Категория | До | После |','| --- | ---: | ---: |');
    for(const [category,kind] of Object.entries(kinds))
      lines.push(`| ${category} | ${baseline.findings[kind].length} | ${findings.filter(f=>f.category===category).length} |`);
    lines.push('', 'Базовые находки','');
    for(const [category,kind] of Object.entries(kinds)){
      for(const f of baseline.findings[kind])
        lines.push(`- ${category} · \`${f.file}:${f.line}\` · ${f.rule}${f.reference?' · '+f.reference:''}`);
    }
    lines.push('',...(baseline.notes??[]).map(note=>'- '+note),'');
  }
  lines.push('## Находки','');
  if(!findings.length)lines.push('Находок нет.','');
  for(const f of findings){
    const location=f.file+':'+f.line+(f.endLine?'–'+f.endLine:'');
    const label=f.category==='SCA'?`${f.group}:${f.artifact}:${f.version} · ${f.reference}`:f.class;
    lines.push(`### ${f.category} · ${label}`,'',`\`${location}\` · **${f.severity.toUpperCase()}**`,'',f.description,'','**Исправление**. '+f.fix,'');
  }
  if(coverage.length){
    lines.push('## Покрытие и диагностика','');
    for(const [category,kind] of Object.entries(kinds)){
      const run=coverage.find(c=>c.kind===kind);
      if(run)lines.push(`- ${category}. Файлов подходящих типов — ${run.fileCount}.`);
    }
    lines.push('');
    if(!diagnostics.length)lines.push('Диагностических сообщений нет.','');
    for(const d of diagnostics)lines.push(`- ${d.category} · \`${d.file}:${d.line}\` · \`${d.code}\`. ${d.message}`);
    lines.push('');
  }
  lines.push('## Ограничения','',
    '- SECRET. Анализ покрывает текстовые значения и локально восстанавливаемые выражения. Профили и условия из поддерживаемых аннотаций отражаются в описании. Эффективное окружение работающего приложения не проверяется.',
    '- SAST. Отслеживаются цепочки Kotlin глубиной до шести функций, распространённые формы JDBC и простые SQL-условия. Сложный полиморфизм, SpEL, прокси, JPA и собственные матчеры требуют отдельного анализа. Порядок правил показывает фактический приоритет. Назначение публичных исключений нужно сверять с политикой доступа.',
    '- SCA. Проверяются явно объявленные зависимости с разрешимой числовой версией. Неоднозначные записи lockfile, вычисляемые Gradle-скрипты, динамические версии и транзитивные зависимости вне покрытия. Попадание в диапазон CVE не доказывает достижимость уязвимого кода.',
    '');
  return lines.join('\n');
}

async function main(){
  const [project,catalogFile,jsonFile,reportFile,baselineFile]=process.argv.slice(2);
  if(!reportFile)throw Error('node garden/submission.cjs PROJECT CATALOG.json OUTPUT.json REPORT.md [BASELINE.json]');
  const [files,catalog,baseline]=await Promise.all([
    readProject(project),fs.readFile(catalogFile,'utf8').then(text=>validateCatalog(JSON.parse(text))),
    baselineFile?fs.readFile(baselineFile,'utf8').then(JSON.parse):null
  ]);
  const analyses=Object.values(kinds).map(kind=>analyze(kind,files,catalog));
  const findings=analyses.flatMap(result=>result.findings)
    .sort((a,b)=>a.category.localeCompare(b.category)||a.file.localeCompare(b.file)||a.line-b.line);
  await Promise.all([
    fs.writeFile(jsonFile,JSON.stringify(submission(findings),null,2)+'\n','utf8'),
    fs.writeFile(reportFile,readableReport(findings,path.basename(path.resolve(project)),Object.keys(files).length,baseline,
      analyses.flatMap(result=>result.diagnostics),analyses.map(result=>result.coverage)),'utf8')
  ]);
}

if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=2;});
module.exports={submission,readableReport};
