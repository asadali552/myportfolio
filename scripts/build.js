const fs = require('node:fs');
fs.rmSync('dist', {recursive:true,force:true});
fs.cpSync('frontend','dist/client',{recursive:true});
fs.mkdirSync('dist/server',{recursive:true});
fs.copyFileSync('scripts/worker.mjs','dist/server/index.js');
console.log('Built portfolio assets and backend bridge.');
