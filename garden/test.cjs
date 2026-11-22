const {test}=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {execute,plan}=require('./workflow.cjs'),{scan,demoFiles,demoCatalog,validateCatalog}=require('./scanners.cjs'),{services}=require('./services.cjs');
test('Демо и отрицательные примеры',()=>{
 for(const kind of ['sca','sast','secrets'])assert.equal(scan(kind,demoFiles).length,1);
 const files={'build.gradle.kts':'implementation("garden.training:demo-codec:1.2.0")','application.yml':'password: ${DB_PASSWORD}','Config.kt':'rules.requestMatchers("/health").permitAll()'};
 for(const kind of ['sca','sast','secrets'])assert.equal(scan(kind,files).length,0);
 assert.throws(()=>validateCatalog([{}]));
});
test('Ветвление, цикл и отключённый блок',async()=>{
 const nodes=['manual','sca','condition','notify','ai'].map(type=>({id:type,type}));
 const edge=(from,to,port='next')=>({from,to,port});
 const edges=[edge('manual','sca'),edge('sca','condition'),edge('condition','notify','yes'),edge('condition','ai','no')];
 const g={nodes,edges};let received;
 const r=await execute(g,demoFiles,demoCatalog,{notify:async rows=>{received=rows;}});
 assert.equal(r.ok,true);assert.equal(received.length,1);assert.equal(r.log.at(-1).state,'Пропущен');
 assert.throws(()=>plan({nodes,edges:edges.slice(1)}));assert.throws(()=>plan({nodes,edges:[...edges,edge('ai','condition')]}));
});
test('Расширенные правила, многострочные конструкции и сохранение номеров строк',()=>{
 const files={
   'Security.kt':[
     '/* commented out:',
     'rules.anyRequest().permitAll()',
     '*/',
     'rules.anyRequest()',
     '    .permitAll()',
     'http.csrf { config ->',
     '    config.disable()',
     '}',
     'jdbcTemplate.queryForObject("SELECT value FROM demo WHERE id = ?", Int::class.java, id)',
     'jdbcTemplate.queryForObject("SELECT value FROM demo WHERE id = " + id, Int::class.java)',
     'ProcessBuilder(command)',
     'problem.printStackTrace()',
     'cors.allowCredentials = true',
     'MessageDigest.getInstance("MD5")',
     'rules.requestMatchers("/health").permitAll()'
   ].join('\n'),
   'application.yml':'# debug: true\ndebug: true',
   'build.gradle':['/*','implementation "garden.training:demo-codec:1.0.0"','*/','def demoVersion = "1.1.0"','implementation "garden.training:demo-codec:$demoVersion"'].join('\n'),
   'pki/example.pem':'-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC-TEST-DATA\n-----END ENCRYPTED PRIVATE KEY-----'
 };
 assert.deepEqual(scan('sast',files).map(f=>[f.rule,f.line]),[
   ['spring.public',4],['spring.csrf',6],['sql.parameter',10],['process.command',11],
   ['logging.stacktrace',12],['crypto.legacy-digest',14],['config.debug',2]
 ]);
 assert.deepEqual(scan('sca',files).map(f=>[f.rule,f.line,f.reference]),[['sca.range',5,'TRAINING-001']]);
 assert.deepEqual(scan('secrets',files).map(f=>[f.rule,f.line]),[['secret.private-key',1]]);
 assert.doesNotMatch(JSON.stringify(scan('secrets',files)),/SYNTHETIC-TEST-DATA/);
});
test('Gradle сопоставляет используемые алиасы с версиями справочника',()=>{
 const files={
   'gradle/libs.versions.toml':[
     '[versions]',
     'old = "1.1.0"',
     'fixed = "1.2.0"',
     '[libraries]',
     'demo-old = { module = "garden.training:demo-codec", version.ref = "old" }',
     'demo-fixed = { group = "garden.training", name = "demo-codec", version.ref = "fixed" }',
     'demo-unused = "garden.training:demo-codec:1.0.0"',
     'demo-missing = { module = "garden.training:demo-codec", version.ref = "unknown" }'
   ].join('\n'),
   'app/build.gradle.kts':'implementation(libs.demo.old)\nimplementation(libs.demo.fixed)\n// implementation(libs.demo.unused)\nimplementation(libs.demo.missing)',
   'tools/build.gradle':'testImplementation libs.demo.old'
 };
 assert.deepEqual(scan('sca',files).map(f=>[f.file,f.line,f.reference]),[
   ['app/build.gradle.kts',1,'TRAINING-001'],['tools/build.gradle',1,'TRAINING-001']
 ]);
 assert.equal(scan('sca',files,[]).length,0);
});
test('Анализ указывает начало многострочного SQL-вызова и распознаёт рискованные настройки',()=>{
 const lines=[
   'jdbcTemplate.queryForObject(',
   '    "SELECT value FROM demo WHERE name = " + name,',
   '    String::class.java',
   ')',
   'jdbcTemplate.queryForObject(',
   '    "SELECT value FROM demo WHERE name = ?",',
   '    String::class.java, name',
   ')',
   'val verifier = NoopHostnameVerifier.INSTANCE',
   'view.settings.allowUniversalAccessFromFileURLs = true',
   'view.settings.allowUniversalAccessFromFileURLs = false'
 ];
 assert.deepEqual(scan('sast',{'Config.kt':lines.join('\n')}).map(f=>[f.rule,f.line]),[
   ['sql.parameter',1],['tls.hostname-verification',9],['webview.file-access',10]
 ]);
});
test('HTTP-доставка и отклонение неподтверждённого CVE',async()=>{
 let payload;
 const server=http.createServer(async(req,res)=>{const chunks=[];for await(const c of req)chunks.push(c);payload=JSON.parse(Buffer.concat(chunks));res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({items:[{id:0,advice:'CVE-9999-12345'}]})}}]}));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));try{
 const url='http://127.0.0.1:'+server.address().port,s=services({model:'test',endpoint:url,hook:url}),rows=scan('secrets',demoFiles);
 await s.notify(rows);assert.equal(payload.count,1);assert.ok(!JSON.stringify(payload).includes('training-local-only'));
 const result=await s.explain(rows);assert.equal(result.rows[0].advice,undefined);assert.match(result.detail,/отклонён/);
 }finally{server.close();}
});

test('Webhook использует отдельный токен сессии и не отправляет его локальному приёмнику',async()=>{
 const authorizations=[];
 const server=http.createServer((req,res)=>{authorizations.push(req.headers.authorization);req.resume();res.end('{}');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
   const url='http://127.0.0.1:'+server.address().port;
   await services({hook:url,hookKey:'session-token',key:'model-secret'}).notify([]);
   await services({hookKey:'session-token',key:'model-secret'},url).notify([]);
   assert.deepEqual(authorizations,['Bearer session-token',undefined]);
 }finally{server.close();}
});

test('SECRET связывает конфигурацию с @Value и скрывает исходные, составные и декодируемые значения',()=>{
 const files={
   'application-stage.yml':['service:', '  bearer: "fixture-profile-73"', '  password: YOUR_PASSWORD','  token: PROD_ACCESS_TOKEN'].join('\n'),
   'application.properties':['service.password=fixture-pass-27','service.token=${SERVICE_TOKEN:fixture-fallback-61}','service.other-token=${SERVICE_TOKEN}'].join('\n'),
   'Client.kt':[
     '@Profile("stage")',
     '@ConditionalOnProperty(prefix = "service", name = "enabled", havingValue = "true")',
     'class Client(@Value("\\${service.bearer}") val session: String) {',
     '  fun call() { headers.setBearerAuth(session) }',
     '}',
     'fun another() {',
     '  val source = "Y3JlZ" + "GVudGlhbA=="',
     '  headers.setBearerAuth(String(Base64.getDecoder().decode(source)))',
     '  headers.setHeader("X-Api-Key", "left-" + "right-123")',
     '}',
     'fun ordinary(token: String) { headers.setBearerAuth(token) }'
   ].join('\n')
 };
 const rows=scan('secrets',files);
 assert.deepEqual(rows.filter(f=>f.file==='application.properties').map(f=>[f.class,f.line]),[['password',1],['secret-fallback',2]]);
 const profile=rows.filter(f=>f.file==='application-stage.yml');
 assert.equal(profile.length,1);
 assert.match(profile[0].description,/@Profile\(stage\).*@ConditionalOnProperty\(service.enabled = true\)/);
 assert.deepEqual(rows.filter(f=>f.file==='Client.kt').map(f=>[f.class,f.line]),[['recoverable-token',8],['recoverable-token',9]]);
 const printed=JSON.stringify(rows);
 for(const text of ['fixture-profile-73','fixture-pass-27','fixture-fallback-61','Y3JlZ','left-','right-123'])assert.ok(!printed.includes(text));
});

test('SAST учитывает поток ввода, частичную параметризацию, методы и порядок правил',()=>{
 const files={'Query.kt':[
   'fun unsafe(@RequestParam code: String) {',
   '  val q = "SELECT * FROM venue WHERE listed = :listed AND code = " + code',
   '  namedParameterJdbcTemplate.query(q, mapOf("listed" to true))',
   '}',
   'fun safe(@RequestParam code: String) {',
   '  val q = "SELECT * FROM venue WHERE code = :code"',
   '  namedParameterJdbcTemplate.query(q, mapOf("code" to code))',
   '}',
   'fun interpolation(@RequestParam term: String) {',
   '  val alias = term.trim()',
   '  val q = "SELECT * FROM venue WHERE name = ${alias}"',
   '  jdbcTemplate.query(q)',
   '}'
 ].join('\n'),
 'Rules.kt':[
   'http.authorizeHttpRequests { rules ->',
   '  rules.requestMatchers(HttpMethod.POST, "/event/**").permitAll()',
   '  rules.requestMatchers(HttpMethod.GET, "/event/closed").hasRole("STAFF")',
   '  rules.requestMatchers("/event/export").hasRole("STAFF")',
   '  rules.requestMatchers("/profile/secret").hasRole("STAFF")',
   '  rules.requestMatchers("/profile/**").permitAll()',
   '}'
 ].join('\n')};
 const rows=scan('sast',files);
 assert.deepEqual(rows.filter(f=>f.class==='sql-injection').map(f=>[f.line,f.endLine]),[[2,3],[11,12]]);
 const routes=rows.filter(f=>f.class==='route-authorization');
 assert.deepEqual(routes.map(f=>[f.line,f.endLine]),[[2,4]]);
 assert.match(routes[0].description,/POST \/event\/export/);
 assert.ok(!rows.some(f=>f.rule==='spring.csrf'));
});

test('SAST проверяет связь владельца с пользователем, а также TLS и CORS в контексте',()=>{
 const files={
   'Endpoints.kt':[
     '@RestController class Endpoints(val records: Records) {',
     '@DeleteMapping("/records/{key}")',
     'fun remove(@PathVariable key: UUID, user: Principal) { records.remove(key, user.name) }',
     '}'
   ].join('\n'),
   'Records.kt':[
     'class Records(val db: NamedParameterJdbcTemplate) {',
     'fun remove(key: UUID, requester: String) {',
     '  db.update("DELETE FROM datum WHERE id = :id AND owner_id = :who", mapOf("id" to key, "who" to requester))',
     '  db.update("DELETE FROM datum WHERE id = :id", mapOf("id" to key))',
     '  db.update("DELETE FROM datum WHERE id = :id AND owner_id = :who", mapOf("id" to key, "who" to key))',
     '  val current = requester',
     '  val params = MapSqlParameterSource().addValue("id", key).addValue("who", current)',
     '  db.update("DELETE FROM datum WHERE id = :id AND owner_id = :who", params)',
     '}',
     '}'
   ].join('\n'),
   'Tls.kt':[
     'val unsafe = object : X509TrustManager { override fun checkServerTrusted() {} }',
     'val unused = object : X509TrustManager { override fun checkServerTrusted() {} }',
     'val safe = object : X509TrustManager { override fun checkServerTrusted() { delegate.checkServerTrusted() } }',
     'val ctx = SSLContext.getInstance("TLS")',
     'ctx.init(null, arrayOf(unsafe), null)',
     'HttpClient.newBuilder().sslContext(ctx).build()'
   ].join('\n'),
   'Cors.kt':[
     'http.authorizeHttpRequests { rules -> rules.requestMatchers("/records/**").authenticated() }',
     'fun addCorsMappings(registry: CorsRegistry) {',
     ' registry.addMapping("/records/**").allowedOriginPatterns("https://*.test.example").allowCredentials(true)',
     ' registry.addMapping("/other/**").allowedOriginPatterns("*").allowCredentials(true)',
     ' registry.addMapping("/records/specific").allowedOrigins("https://trusted.example").allowCredentials(true)',
     ' registry.addMapping("/records/path").allowedOriginPatterns("*").allowCredentials(false)',
     ' registry.addMapping("/records/export").allowedOriginPatterns("*").allowCredentials(true)',
     '}'
   ].join('\n')
 };
 const rows=scan('sast',files);
 const hits=kind=>rows.filter(r=>r.class===kind);
 assert.deepEqual(hits('object-authorization').map(r=>r.line),[4,5]);
 assert.deepEqual(hits('tls-verification').map(r=>r.line),[1]);
 assert.deepEqual(hits('credentialed-cors').map(r=>r.line),[3,7]);
 assert.match(hits('credentialed-cors')[0].description,/контроле .*поддомена.*передаче браузером/);
 assert.match(hits('credentialed-cors')[1].description,/любой Origin/);
});

test('SCA разрешает Kotlin DSL, применяет lockfile только к объявлениям и различает границы',()=>{
 const row=(artifact,lower,upper,lowerInclusive,upperInclusive)=>({
    group:'org.fixture',artifact,id:'GHSA-1234-'+artifact,aliases:['CVE-2026-'+(1234+artifact.length)],
    severity:'MEDIUM',ranges:[{lower,upper,lowerInclusive,upperInclusive}],fixedVersions:[]
 });
 const catalog={formatVersion:1,ecosystem:'Maven',versionFormat:'numeric-dot-separated',vulnerabilities:[
   row('coordinate',null,'1.2',false,true),row('named','1.0','2.0',false,false),
   row('strict','1.0','2.0',true,false),row('locked','1.0','2.0',true,false),
   row('updated','1.0','2.0',true,false),row('transitive','1.0','2.0',true,false)
 ]};
 const files={'build.gradle.kts':[
    'val groupId = "org.fixture"',
    'val v = "1.2"',
    'dependencies {',
    '  implementation("$groupId:coordinate:$v")',
    '  implementation(group = groupId, name = "named", version = "1.0")',
    '  api(group = groupId, name = "strict") { version { strictly(v) } }',
    '  implementation("$groupId:locked:2.0")',
    '  implementation("$groupId:updated:1.1")',
    '  // implementation("org.fixture:transitive:1.1")',
    '}'
 ].join('\n'),'gradle.lockfile':[
    'org.fixture:locked:1.9=runtimeClasspath',
    'org.fixture:updated:2.0=runtimeClasspath',
    'org.fixture:transitive:1.5=runtimeClasspath'
 ].join('\n')};
 const rows=scan('sca',files,catalog);
 assert.deepEqual(rows.map(r=>[r.artifact,r.version,r.line]),[['coordinate','1.2',4],['strict','1.2',6],['locked','1.9',7]]);
 const {submission,readableReport}=require('./submission.cjs');
 const output=submission(rows);
 assert.ok(output.findings.every(f=>f.advisoryId.startsWith('CVE-')&&!('line' in f)));
 assert.match(readableReport(rows,'fixture',2),/build\.gradle\.kts:7/);
 assert.deepEqual(submission([]),{findings:[]});
});

test('Проверку владельца доказывают реализация, идентификатор объекта и выполнение до SQL',()=>{
 const {analyze}=require('./scanners.cjs');
 const routes=[
   ['a','checkOwnership(key, who.name)'],
   ['b','enforce(key, who.name)'],
   ['c','allowed(key, who.name)'],
   ['d','if (condition) { enforce(key, who.name) }'],
   ['e','require(allowed(key, who.name))'],
   ['f','enforce(other, who.name)'],
   ['g','policy.enforce(key, who.name)'],
   ['h','enforce(key, who.name)'],
   ['i','require(!allowed(key, who.name))'],
   ['j','require(enabled || allowed(key, who.name))'],
   ['k','returnsWithoutThrow(key, who.name)'],
   ['l','require(sometimesAllowed(key, who.name))'],
   ['m','val owner = db.queryForObject("SELECT owner_id FROM entry WHERE id = ?", String::class.java, key)\nif (owner != who.name) return']
 ];
 const rows=routes.map(([name,guard])=>{
   const mutation='db.update("DELETE FROM entry WHERE id = ?", key)';
   const steps=name==='h'?[mutation,guard]:[guard,mutation];
   return '@DeleteMapping("/'+name+'/{key}")\nfun '+name+'(@PathVariable key: Long, @PathVariable other: Long, who: Principal) {\n'+steps.join('\n')+'\n}';
 });
 const files={'Endpoint.kt':[
   'class Endpoint(val db: JdbcTemplate, val policy: ExternalPolicy) {',
   '  fun checkOwnership(key: Long, who: String) {}',
   '  fun enforce(key: Long, who: String) {',
   '    val owner = db.queryForObject("SELECT owner_id FROM entry WHERE id = ?", String::class.java, key)',
   '    require(owner == who)',
   '  }',
   '  fun allowed(key: Long, who: String): Boolean {',
   '    val owner = db.queryForObject("SELECT owner_id FROM entry WHERE id = ?", String::class.java, key)',
   '    return owner == who',
   '  }',
   '  fun returnsWithoutThrow(key: Long, who: String) {',
   '    val owner = db.queryForObject("SELECT owner_id FROM entry WHERE id = ?", String::class.java, key)',
   '    if (owner != who) return',
   '  }',
   '  fun sometimesAllowed(key: Long, who: String): Boolean {',
   '    if (enabled) return true',
   '    return allowed(key, who)',
   '  }',
   ...rows,'}'
 ].join('\n')};
 const r=analyze('sast',files);
 assert.deepEqual(r.findings.filter(f=>f.class==='object-authorization').map(f=>f.description.match(/Маршрут (\w+)/)[1]),['a','c','d','f','h','i','j','k','l']);
 assert.ok(r.diagnostics.some(d=>d.code==='kotlin.owner-guard-unknown'&&d.message.includes('Маршрут g')));
});

test('SQL-поток проходит алиасы, именованные аргументы, перенос по пакетам и возвращаемые значения',()=>{
 const {analyze}=require('./scanners.cjs');
 const files={
   'Routes.kt':[
     'package web','import app.Facade as Bridge',
     'class Routes(val layer: Bridge) {',
     ' @GetMapping("/lookup")',
     ' fun lookup(@RequestParam search: String) {',
     '   val copy = layer',
     '   copy.search(value = search.trim())',
     ' }',
     '}'
   ].join('\n'),
   'Facade.kt':[
     'package app','import data.Rows',
     'class Facade(val storage: Rows) {',
     ' fun search(value: String) {',
     '   val text = shape(value)',
     '   storage.raw(text)',
     '   storage.safe(value)',
     ' }',
     ' fun shape(word: String): String =',
     '   "SELECT id FROM entry WHERE code = " + word',
     '}'
   ].join('\n'),
   'Repository.kt':[
     'package data','import org.springframework.jdbc.core.JdbcTemplate as Database',
     'class Rows(val db: Database) {',
     ' fun raw(sql: String) = db.queryForList(sql)',
     ' fun safe(word: String) = db.queryForList("SELECT id FROM entry WHERE code = ?", word)',
     '}'
   ].join('\n')
 };
 const r=analyze('sast',files);
 const rows=r.findings.filter(f=>f.class==='sql-injection');
 assert.deepEqual(rows.map(f=>[f.file,f.line]),[['Repository.kt',4]]);
 assert.match(rows[0].description,/lookup → search → raw.*Facade\.kt:10/);
 assert.deepEqual(r.diagnostics,[]);
});

test('Перегрузка и цикл ограничивают поток и возвращают диагностику отдельно от находок',()=>{
 const {analyze}=require('./scanners.cjs');
 const report=analyze('sast',{'Flow.kt':[
   'fun controller(@RequestParam data: String) {',
   '  decode(data)',
   '  revive(data)',
   '}',
   'fun decode(text: String) {}',
   'fun decode(text: Int) {}',
   'fun revive(text: String) = loop(text)',
   'fun loop(text: String) = revive(text)'
 ].join('\n')});
 assert.deepEqual(report.findings,[]);
 assert.deepEqual(report.diagnostics.map(d=>d.code),['kotlin.ambiguous-call','kotlin.flow-limit']);
});

test('CORS использует применимую цепочку и метод, а публичный маршрут перекрывает только пересекающееся правило',()=>{
 const {analyze}=require('./scanners.cjs');
 const r=analyze('sast',{'Security.kt':[
   '@Order(1)',
   'fun public(http: HttpSecurity) = http.securityMatcher("/open/**").authorizeHttpRequests { r ->',
   '  r.anyRequest().permitAll()',
   '}.build()',
   '@Order(2)',
   'fun privateScope(http: HttpSecurity) = http.securityMatcher("/closed/**").authorizeHttpRequests { r ->',
   '  r.requestMatchers(GET, "/closed/catalog").permitAll()',
   '  r.requestMatchers(GET, "/open/catalog").permitAll()',
   '  r.requestMatchers(POST, "/closed/catalog").hasRole("ADMIN")',
   '  r.requestMatchers(GET, "/closed/**").hasRole("ADMIN")',
   '}.build()',
   'fun cors() {',
   '  val policy = CorsConfiguration().apply {',
   '    allowedOriginPatterns = listOf("https://*.example.test")',
   '    allowCredentials = true',
   '    allowedMethods = listOf("GET")',
   '  }',
   '  val alias = policy',
   '  source.registerCorsConfiguration("/open/catalog", alias)',
   '  source.registerCorsConfiguration("/closed/catalog", alias)',
   '  source.registerCorsConfiguration("/closed/records", alias)',
   '}'
 ].join('\n')});
 assert.deepEqual(r.findings.filter(f=>f.class==='route-authorization').map(f=>f.line),[7]);
 const cors=r.findings.filter(f=>f.class==='credentialed-cors');
 assert.equal(cors.length,1);
 assert.match(cors[0].description,/поддомена.*браузером.*\/closed\/records/);
 assert.deepEqual(r.diagnostics,[]);
});

test('Elvis, HTTPS hostname verifier и Gradle add дают находки только при выполнении условий правила',()=>{
 const {analyze}=require('./scanners.cjs');
 const secrets=analyze('secrets',{'Connector.kt':[
   'fun request() {',
   '  val fallback = System.getenv("FIXTURE_HEADER")',
   '    ?: "fake-credential-241"',
   '  val value = fallback',
   '  headers.set("Authorization", "Bearer $value")',
   '  val token = System.getenv("OTHER_TOKEN") ?: "YOUR_TOKEN"',
   '  headers.set("Authorization", "Bearer $token")',
   '}'
 ].join('\n')});
 assert.deepEqual(secrets.findings.map(f=>[f.class,f.line]),[['secret-fallback',3]]);
 assert.ok(!JSON.stringify(secrets).includes('fake-credential-241'));
 const tls=analyze('sast',{'Connector.kt':[
   'val unused = HostnameVerifier { _, _ -> true }',
   'fun connect() {',
   '  val socket = url.openConnection() as HttpsURLConnection',
   '  val test = HostnameVerifier { _, _ -> true }',
   '  val alias = test',
   '  socket.hostnameVerifier = alias',
   '  socket.hostnameVerifier = HostnameVerifier { host, session -> delegate.verify(host, session) }',
   '}'
 ].join('\n')});
 assert.deepEqual(tls.findings.map(f=>[f.class,f.line]),[['tls-verification',6]]);
 const gradle=analyze('sca',{
   'build.gradle.kts':[
     'val oldVersion = providers.gradleProperty("legacy").get()',
     'val missing = providers.gradleProperty("missing").get()',
     'dependencies {',
     '  add("implementation", "garden.training:demo-codec:$oldVersion")',
     '  implementation("site.example:something:$missing")',
     '  implementation("site.example:new-api:latest.release")',
     '  implementation(project(":core"))',
     '  implementation("garden.training:demo-codec:1.1.0") { version { strictly(missing) } }',
     '}'
   ].join('\n'),'gradle.properties':'legacy=1.1.0'
 });
 assert.deepEqual(gradle.findings.map(f=>[f.version,f.line]),[['1.1.0',4]]);
 assert.deepEqual(gradle.diagnostics.map(d=>[d.code,d.line]),[['gradle.unresolved-version',5],['gradle.unresolved-version',6],['gradle.unresolved-version',8]]);
 const standaloneCors=analyze('sast',{'Cors.kt':'cors.allowCredentials = true'});
 assert.deepEqual(standaloneCors.findings,[]);
 assert.equal(standaloneCors.diagnostics[0].code,'spring.cors-context');
});

test('Сверка учебного формата учитывает альтернативное место, дубликаты, точный класс и CVE/GHSA',()=>{
 const {compare}=require('./compare-findings.cjs');
 const secret={category:'SECRET',path:'Secret.kt',class:'password',line:4};
 const dependency={category:'SCA',path:'build.gradle.kts',group:'org.test',artifact:'sample',version:'1.0',advisoryId:'CVE-2026-1234'};
 const truth={findings:[
   {...secret,id:'secret',path:'Other.kt',line:10,alternateLocations:[{path:'Secret.kt',line:3,endLine:5}]},
   {...dependency,id:'dependency',advisoryIds:['GHSA-sample','CVE-2026-1234']},
   {id:'miss',category:'SAST',path:'Web.kt',class:'sql-injection',line:6,classAliases:['CWE-89']}
 ],controls:[]};
 const result=compare({findings:[secret,secret,dependency,{category:'SAST',path:'Web.kt',class:'CWE-89',line:6}]},truth);
 assert.deepEqual(result.matched,['secret','dependency']);
 assert.deepEqual(result.missing,['miss']);
 assert.equal(result.extra.length,2);
});
test('Встроенный Maven заменяет старый демо-справочник, а пользовательский остаётся активным',()=>{
 const {demoCatalog,validateCatalog}=require('./scanners.cjs');
 const {bundledCatalog,resolveCatalog}=require('./catalog.cjs');
 const savedDemo=validateCatalog(demoCatalog);
 assert.equal(resolveCatalog(),bundledCatalog);
 assert.equal(resolveCatalog(savedDemo),bundledCatalog);
 assert.equal(resolveCatalog(savedDemo,{demo:true}),demoCatalog);
 assert.deepEqual(resolveCatalog(savedDemo,{custom:true}),savedDemo);
 assert.deepEqual(resolveCatalog([],{custom:true}),[]);
});
