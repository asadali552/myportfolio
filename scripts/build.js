const fs = require('node:fs');
fs.rmSync('dist', { recursive: true, force: true });
fs.cpSync('frontend', 'dist', { recursive: true });
console.log('Static portfolio built in dist/');
