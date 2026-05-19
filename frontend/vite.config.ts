import { defineConfig } from 'vite';

// 現フェーズではエントリ HTML は未作成。Vite はプロジェクトルートおよび
// サブディレクトリにある *.html を自動的にマルチページのエントリとして扱う
// (https://vite.dev/guide/build.html#multi-page-app)。
// 後で index.html / setup.html / download.html を追加すれば、追加設定不要で
// それぞれが独立したエントリポイントとしてビルドされる。
export default defineConfig({
  // dist/ を任意のサブディレクトリ配下にデプロイしても動くよう、
  // 全アセット参照を相対パス (./assets/...) で生成する。
  // mixhost 上で /personal-pqc-drive/frontend/dist/ のような階層に置く想定。
  base: './',
  build: {
    target: 'es2022',
    sourcemap: true,
  },
});
