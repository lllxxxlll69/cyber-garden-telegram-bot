const fs=require('node:fs/promises');
const path=require('node:path');
async function readProject(root){
  const files=Object.create(null); let bytes=0,count=0;
  async function walk(dir){
    for(const entry of await fs.readdir(dir,{withFileTypes:true})){
      const full=path.join(dir,entry.name);
      if(entry.isDirectory()&&!['.git','.gradle','build','out','node_modules','.idea','target'].includes(entry.name)) await walk(full);
      else if(entry.isFile()&&/(?:\.kt[s]?|\.properties|\.ya?ml|\.env|\.pem|\.key)$/i.test(entry.name)){
        const size=(await fs.stat(full)).size;
        if(size>2e6||(bytes+=size)>16e6||++count>1500) throw Error('Превышен лимит импорта (1500 файлов, 16 МБ суммарно, 2 МБ на файл)');
        files[path.relative(root,full).split(path.sep).join('/')]=await fs.readFile(full,'utf8');
      }
    }
  }
  await walk(root);
  if(!count) throw Error('В папке нет поддерживаемых исходников или конфигурации');
  return files;
}
module.exports={readProject};
