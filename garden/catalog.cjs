const {demoCatalog,validateCatalog}=require('./scanners.cjs');
const bundledCatalog=validateCatalog(require('./maven-advisories.json'));
const legacyDemoKey=JSON.stringify(validateCatalog(demoCatalog));
const isDemoCatalog=catalog=>JSON.stringify(catalog)===legacyDemoKey||JSON.stringify(catalog)===JSON.stringify(demoCatalog);

function resolveCatalog(catalog,{demo=false,custom}={}){
 if(custom===false||catalog===undefined)return demo?demoCatalog:bundledCatalog;
 const validated=validateCatalog(catalog);
 if(custom===undefined&&isDemoCatalog(validated))
  return demo?demoCatalog:bundledCatalog;
 return validated;
}

module.exports={bundledCatalog,resolveCatalog,isDemoCatalog};
