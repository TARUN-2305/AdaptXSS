import esbuild from 'esbuild';
import { readFileSync, existsSync } from 'fs';

let base64Seed = '';
if (existsSync('./dist/seed_model.json')) {
  const seedModel = readFileSync('./dist/seed_model.json');
  base64Seed = seedModel.toString('base64');
}

esbuild.build({
  entryPoints: ['src/index.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'AdaptXSS',
  outfile: 'dist/adaptxss.min.js',
  define: {
    'SEED_MODEL_JSON': `'${base64Seed}'`
  }
}).then(() => console.log('Build complete'))
  .catch((e) => { console.error(e); process.exit(1); });
