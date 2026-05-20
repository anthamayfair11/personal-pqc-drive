# デプロイ手順 (mixhost)

Personal PQC Drive を mixhost(cPanel + PHP-FPM 環境)へ配置する手順。
ローカルでフロントをビルドし、`frontend/dist/` と `backend/` と `storage/` を
サーバーへ転送する。

## 1. 前提

- **ホスティング**: mixhost(共有、cPanel ベース、PHP-FPM、SSH 利用可)
- **PHP**: 8.x(本リポジトリは PHP 8.3 で検証)
- **HTTPS**: 必須(理由は §8)。mixhost の AutoSSL で取得済みであること
- **ローカル**: Node.js(`npm run build` が通る環境)
- **Composer 不要**: バックエンドは外部ライブラリゼロ

## 2. 本番ディレクトリ構成

フロントの `fetch` は本番ビルドで `BACKEND_BASE = 'backend'` という相対パスで
バックエンドを呼ぶ(`frontend/src/upload.ts` / `download.ts`。`import.meta.env.PROD`
でローカル用 `'../../backend'` と切り替え)。このため **`frontend/dist/` の中身を
`personal-pqc-drive/` 直下に展開し、`backend/` と同階層に置く**(URL を短く保つため)。

```
<ドキュメントルート>/personal-pqc-drive/
├── setup.html         受信者: 鍵生成・公開鍵エクスポート
├── upload.html        送信者: 暗号化・アップロード
├── download.html      受信者: 復号・保存
├── index.html         開発用テストページ (本番では削除推奨)
├── assets/            *.js (ハッシュ付き)
├── backend/
│   ├── upload.php
│   ├── download.php
│   ├── confirm.php
│   ├── sweep.php
│   ├── config.php             ★ サーバー上で作成 (git 管理外)
│   ├── config.example.php     (除外でも可)
│   ├── .htaccess
│   └── .user.ini
└── storage/
    └── .htaccess              直接アクセス禁止 (中身はサーバー上で生成)
```

本番 URL(ドキュメントルート `~/public_html`、ドメイン xenonsegawa.com の例):

- `https://xenonsegawa.com/personal-pqc-drive/setup.html`
- `https://xenonsegawa.com/personal-pqc-drive/upload.html`
- `https://xenonsegawa.com/personal-pqc-drive/download.html`

> **配置階層を変える場合**: `setup.html` 等と `backend/` が同階層である前提
> (`BACKEND_BASE='backend'`)。階層関係を変えるなら `frontend/src/upload.ts` /
> `download.ts` の `BACKEND_BASE` を書き換えて再ビルドすること。

## 3. ローカルでのビルド

```bash
cd frontend
npm install        # 初回のみ
npm run build      # tsc --noEmit && vite build → frontend/dist/ を生成
```

`dist/` に 4 つの HTML とハッシュ付き JS が出力されれば成功。

### ローカルでの本番ビルド確認 (任意)

`npm run build` の出力は `BACKEND_BASE='backend'`(直下配置前提)なので、
ローカルの `frontend/dist/` 階層からは backend へパスが届かない。
シンボリックリンクで橋渡しすると、PHP ビルトインサーバでそのまま確認できる:

```bash
# frontend/dist/backend → ../../backend (dist 配下なので .gitignore 対象)
# ※ build のたびに dist がクリアされるので、build 後に張り直す
ln -sfn ../../backend frontend/dist/backend

# プロジェクトルートを serve (100MB アップロードを許可)
php -d upload_max_filesize=100M -d post_max_size=110M -S localhost:8888 -t .

# ブラウザで:
#   http://localhost:8888/frontend/dist/setup.html
#   http://localhost:8888/frontend/dist/upload.html
#   http://localhost:8888/frontend/dist/download.html
```

> `npm run dev`(Vite dev server)では `BACKEND_BASE='../../backend'` になるが、
> dev server は PHP を実行しないため、PHP 連携の確認には上記の
> production build + symlink 方式を使う。

## 4. アップロード (rsync over SSH)

SSH 接続情報(`<user>@<host>`、ポート、鍵)は cPanel で確認する。
以下は機能別に 3 回 rsync する例。`<remote>` は配置先
(例: `~/public_html/personal-pqc-drive`)。

```bash
# プロジェクトルートで実行

# (1) フロントのビルド成果物を personal-pqc-drive/ 直下へ。
#     backend/ と storage/ を誤って消さないよう --delete から除外。
#     frontend/dist/backend (ローカル確認用 symlink) もこの除外で送られない。
rsync -avz --delete \
  --exclude 'backend' \
  --exclude 'storage' \
  frontend/dist/ \
  <user>@<host>:<remote>/

# (2) バックエンド (テストスクリプトと本番 config は除外)
rsync -avz \
  --exclude 'test_sweep.php' \
  --exclude 'config.php' \
  backend/ \
  <user>@<host>:<remote>/backend/

# (3) storage は .htaccess のみ転送 (暗号化済みファイルはサーバー上で生成)
rsync -avz \
  storage/.htaccess \
  <user>@<host>:<remote>/storage/.htaccess
```

ポート指定が必要な場合は `-e "ssh -p <port>"` を付ける。

> **注意**: `--delete` は (1) のみに付けている。`backend/` に `--delete` を
> 付けると、サーバー上で作成した `config.php` が消えるため付けない。

cPanel のファイルマネージャや FTP でも可だが、その場合も
**`test_sweep.php` をアップロードしない**こと(`.gitignore` 同様の方針)。

## 5. config.php の作成

`config.php` は git 管理外(`.gitignore`)なのでサーバー上で作る。

```bash
ssh <user>@<host>
cd <remote>/backend
cp config.example.php config.php
# 必要なら編集 (TTL や上限の調整)
```

デフォルト値(`config.example.php`):

| キー | デフォルト | 説明 |
|---|---|---|
| `storage_dir` | `__DIR__/../storage` | 保管先。構成どおりなら変更不要 |
| `max_file_size` | 100 MB | 1 ファイル上限 |
| `default_ttl_seconds` | 24 時間 | 有効期限 |
| `max_total_storage` | 1 GB | storage 全体の上限 |
| `id_length` | 16 | 発行 ID 長(64進16桁 ≒ 96bit) |

> mixhost の規約は大量・長期保管を想定していない。`max_total_storage` は
> 控えめ(数百 MB 程度)に下げてもよい(§13)。

## 6. パーミッションと storage の書き込み権限

PHP(`upload.php` / `sweep.php` / `confirm.php`)が `storage/` に
読み書きできる必要がある。mixhost は suEXEC/PHP-FPM で「PHP 実行ユーザー =
アカウントのユーザー」なので、通常は所有者権限で足りる。

```bash
ssh <user>@<host>
cd <remote>

# ディレクトリ 755 / ファイル 644
find frontend/dist backend storage -type d -exec chmod 755 {} \;
find frontend/dist backend storage -type f -exec chmod 644 {} \;

# storage は書き込みが必要 (所有者書き込みは 755 に含まれる)
chmod 755 storage
```

`storage/` に PHP が書けない場合は 500 `INTERNAL_ERROR` が返る(§12)。

## 7. PHP アップロードサイズ上限

PHP のデフォルト `upload_max_filesize` / `post_max_size` は 2〜8 MB の
ことが多く、100 MB を受けるには引き上げが必要。

- 本リポジトリは `backend/.user.ini`(PHP-FPM 用)と `backend/.htaccess`
  (mod_php 用)の両方に 100 MB 設定を入れてある
- **mixhost は PHP-FPM** なので `.user.ini` が効く。ただし反映に数分の
  キャッシュ遅延がある(`user_ini.cache_ttl`)
- 即時反映したい/確実にしたい場合は cPanel の **MultiPHP INI Editor** で
  `upload_max_filesize=100M`, `post_max_size=110M` を設定

確認:

```bash
ssh <user>@<host>
cd <remote>/backend
php -i | grep -E 'upload_max_filesize|post_max_size'
```

> CLI の `php -i` と Web(PHP-FPM)で値が異なることがある。最終的には
> ブラウザから 100 MB 近いファイルを実際に上げて確認するのが確実。

## 8. HTTPS

HTTPS は必須:

- `upload.html` のアップロード後 URL コピーは `navigator.clipboard` を使い、
  **セキュアコンテキスト(HTTPS or localhost)でしか動かない**
- 盗聴対策(脅威モデル上 HTTPS 前提)

mixhost の AutoSSL(Let's Encrypt)で証明書が発行済みであることを cPanel で
確認する。`http://` でアクセスされたら `https://` へリダイレクトする設定を
推奨(cPanel の "Force HTTPS Redirect")。

> 暗号処理自体(`crypto.getRandomValues` / `@noble/*`)は HTTP でも動くが、
> URL コピーが使えず UX が落ちる。必ず HTTPS で運用する。

## 9. 動作確認

ブラウザで以下を順に確認(エンドツーエンド)。URL は
`https://xenonsegawa.com/personal-pqc-drive/{setup,upload,download}.html`:

1. `setup.html` を開く → 「鍵ペアを生成して保管」→ 公開鍵 JSON をダウンロード
2. `upload.html` を開く → 公開鍵 JSON を読み込み → ファイル選択 → 「暗号化」
   → 「サーバーにアップロードして URL 取得」→ 共有 URL 表示
3. 共有 URL を別タブで開く → 「サーバーから取得中…」→ 復号成功 →
   「サーバー上のファイルは削除されました」表示
4. 同じ URL を再度開く → 404(プライマリ削除が効いている証拠)

SSH 側でも storage を観察できる:

```bash
ssh <user>@<host>
ls -la <remote>/storage/        # アップロード直後は {id}.ppqd と {id}.meta.json
                                # ダウンロード後は消えている
```

## 10. 自動削除の挙動(cron 不使用)

削除はハイブリッド方式(`docs/` の実装方針どおり):

- **プライマリ**: 受信者が URL から復号成功した瞬間に `confirm.php` が叩かれ即削除
- **フォールバック**: `upload.php` / `download.php` へのアクセス時に `sweep.php`
  が期限切れ(24h 超)・孤児・壊れたファイルを掃除

**注意点**: sweep は「アクセス駆動」なので、サイトに全くアクセスが無いと
期限切れファイルが残り続ける。実運用では誰かがアップロード/ダウンロードする
たびに掃除されるため通常は問題ないが、長期間放置されるサイトで確実に消したい
場合は cron で定期実行する選択肢もある(本プロジェクトは方針として cron 不使用):

```bash
# (任意) cron を使う場合の例: 1時間ごとに sweep を CLI 実行する小スクリプトを
# 別途用意して回す。デフォルト方針では不要。
```

## 11. 再デプロイ(更新時)

- **フロントだけ変更**: `npm run build` → §4 の (1) のみ再実行
- **バックエンドだけ変更**: §4 の (2) のみ再実行(`config.php` は
  `--exclude` で保護されるので消えない)
- ハッシュ付き JS(`assets/*.js`)はビルドごとにファイル名が変わるため、
  `--delete` 付きの (1) で古いアセットが除去される

## 12. トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| アップロードが 413 / 失敗 | PHP のサイズ上限(§7)。`.user.ini` 反映待ち or MultiPHP INI Editor |
| アップロードで 500 `INTERNAL_ERROR` | `storage/` に PHP が書けない。パーミッション/所有者を確認(§6) |
| `upload.php` が 404 | `setup.html` 等と `backend/` が同階層に無い(§2)。本番ビルドの `BACKEND_BASE='backend'` 前提どおりに直下配置できているか |
| URL コピーが効かない | HTTP でアクセスしている。HTTPS にする(§8) |
| storage に直アクセスできてしまう | `storage/.htaccess` が転送されていない、または `AllowOverride` 無効。mixhost は通常 `All` |
| ダウンロードが 410 | 有効期限切れ(正常)。24h 超のファイル |
| 期限切れファイルが消えない | sweep はアクセス駆動(§10)。誰かがアクセスすれば消える |

## 13. セキュリティ・規約上の注意

- mixhost の利用規約は**大量・長期のファイル保管を想定していない**。
  `max_total_storage` を控えめにし、TTL(24h)を延ばしすぎないこと
- `storage/` には暗号化済みバイナリしか置かれない(ゼロ知識)。万一流出しても
  受信者の秘密鍵が無い限り復号不可
- `backend/test_sweep.php` は**本番に置かない**(CLI 専用、`.gitignore` 除外)
- `index.html`(テストページ)は開発用。本番では削除推奨
- `config.php` には今後 DB 認証情報等を入れる可能性がある。git 管理外を維持
