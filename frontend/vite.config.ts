import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// マルチページ構成 (https://vite.dev/guide/build.html#multi-page-app)。
// production build では rollupOptions.input でエントリ HTML を明示する必要がある
// (dev server は root の *.html を自動検出するが、build は別)。
//
// base: './' により dist/ を任意のサブディレクトリ配下にデプロイしても動作する
// (mixhost 上で /personal-pqc-drive/frontend/dist/ のような階層に置く想定)。
export default defineConfig({
  base: './',
  build: {
    target: 'es2022',
    sourcemap: true,
    rollupOptions: {
      input: {
        main:  resolve(import.meta.dirname, 'index.html'),
        setup: resolve(import.meta.dirname, 'setup.html'),
      },
    },
  },
});
