/**
 * download.ts - 受信者ダウンロード画面: .ppqd ファイルを復号して保存
 *
 * UI フロー:
 *   ページロード → hasKeyPair() で分岐
 *     - 鍵なし: setup.html へ誘導
 *     - 鍵あり: 鍵 createdAt 表示 + D&D エリア表示
 *   ファイル D&D / 選択 → 自動復号 → メタデータ表示 + 保存ボタン
 *
 * 復号データはモジュールスコープ変数に保持し、保存ボタンで何度でもダウンロード
 * できる。「クリア」ボタンか、リロードで明示的にメモリから消える。
 *
 * プレビューは本ステップでは未実装 (次ステップ preview.ts で MIME 別に対応)。
 */

import { decryptAsRecipient } from './crypto.ts';
import {
  getKeyPairCreatedAt,
  hasKeyPair,
  loadKeyPair,
} from './keystore.ts';
import {
  CryptoError,
  KeystoreError,
  type DecryptResult,
} from './types.ts';

// =============================================================================
// 状態 (モジュールスコープ、リロードで消失)
// =============================================================================

let decryptedResult: DecryptResult | null = null;

// =============================================================================
// DOM 取得
// =============================================================================

const errorEl         = document.getElementById('error')           as HTMLDivElement;
const noKeyPanel      = document.getElementById('no-key-panel')    as HTMLElement;
const keyPanel        = document.getElementById('key-panel')       as HTMLElement;
const dropzonePanel   = document.getElementById('dropzone-panel')  as HTMLElement;
const loadingPanel    = document.getElementById('loading-panel')   as HTMLElement;
const loadingIdEl     = document.getElementById('loading-id')      as HTMLElement;
const resultPanel     = document.getElementById('result-panel')    as HTMLElement;
const keyCreatedAtEl  = document.getElementById('key-created-at')  as HTMLParagraphElement;
const dropzone        = document.getElementById('dropzone')        as HTMLElement;
const fileInput       = document.getElementById('file-input')      as HTMLInputElement;
const selectFileBtn   = document.getElementById('select-file-btn') as HTMLButtonElement;
const serverNoteEl    = document.getElementById('server-note')     as HTMLParagraphElement;
const metaNameEl      = document.getElementById('meta-name')       as HTMLElement;
const metaSizeEl      = document.getElementById('meta-size')       as HTMLElement;
const metaMimeEl      = document.getElementById('meta-mime')       as HTMLElement;
const metaSentAtEl    = document.getElementById('meta-sent-at')    as HTMLElement;
const saveBtn         = document.getElementById('save-btn')        as HTMLButtonElement;
const clearBtn        = document.getElementById('clear-btn')       as HTMLButtonElement;

// =============================================================================
// ユーティリティ
// =============================================================================

function showError(message: string): void {
  errorEl.textContent = message;
  errorEl.style.display = 'block';
}

function clearError(): void {
  errorEl.textContent = '';
  errorEl.style.display = 'none';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function pad2(n: number): string {
  return n.toString().padStart(2, '0');
}

function formatDateTime(d: Date): string {
  return (
    `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}`
  );
}

// =============================================================================
// 表示制御
// =============================================================================

function renderNoKey(): void {
  noKeyPanel.style.display = 'block';
  keyPanel.style.display = 'none';
  dropzonePanel.style.display = 'none';
  resultPanel.style.display = 'none';
}

function renderKeyAvailable(createdAt: Date | null): void {
  noKeyPanel.style.display = 'none';
  keyPanel.style.display = 'block';
  dropzonePanel.style.display = 'block';
  keyCreatedAtEl.textContent = createdAt
    ? `${formatDateTime(createdAt)} 生成 の鍵を使用`
    : '生成日時不明の鍵を使用';
}

function renderResult(result: DecryptResult, fromUrl: boolean): void {
  resultPanel.style.display = 'block';
  metaNameEl.textContent = result.metadata.name;
  metaSizeEl.textContent = formatBytes(result.metadata.size);
  metaMimeEl.textContent = result.metadata.mime || '(unknown)';
  const sentAt = new Date(result.metadata.sentAt);
  metaSentAtEl.textContent = Number.isNaN(sentAt.getTime())
    ? result.metadata.sentAt
    : formatDateTime(sentAt);

  // URL から取得した場合のみ「1 回限りの受け渡しが完了した」ことを示す
  // (ローカル D&D はサーバー上に存在しないため何も表示しない)
  if (fromUrl) {
    serverNoteEl.textContent = '✓ サーバーから受信完了。サーバー上のファイルは削除されました';
    serverNoteEl.style.display = 'block';
  } else {
    serverNoteEl.style.display = 'none';
  }
}

/**
 * 受領確認: confirm.php を叩いてサーバー上のファイルを削除する (プライマリ削除)。
 * ベストエフォート: 失敗してもユーザーには通知しない (フォールバックで 24h 後に消える)。
 * 5 秒でタイムアウトする。
 */
async function confirmReceipt(id: string): Promise<void> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${BACKEND_BASE}/confirm.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
      signal: controller.signal,
    });
    if (!response.ok) {
      console.warn(`[confirm] サーバー削除に失敗 (HTTP ${response.status})`);
    }
  } catch (e) {
    console.warn('[confirm] 受領確認リクエストに失敗しました', e);
  } finally {
    window.clearTimeout(timeout);
  }
}

function hideResult(): void {
  resultPanel.style.display = 'none';
}

function showLoading(id: string): void {
  loadingPanel.style.display = 'block';
  loadingIdEl.textContent = `id=${id}`;
}

function hideLoading(): void {
  loadingPanel.style.display = 'none';
}

// =============================================================================
// エラーメッセージ変換
// =============================================================================

/**
 * CryptoError.code に応じた利用者向けメッセージ。
 *
 * UNSUPPORTED_VERSION / UNSUPPORTED_ALGORITHM の数値部分は CryptoError.message
 * 内にデバッグ用詳細が含まれているので、固定文言の後に括弧書きで添える。
 */
function mapCryptoError(e: CryptoError): string {
  switch (e.code) {
    case 'INVALID_MAGIC':
      return 'このファイルは Personal PQC Drive で暗号化されたものではありません';
    case 'UNSUPPORTED_VERSION':
      return `このファイルのバージョンに対応していません (詳細: ${e.message})`;
    case 'UNSUPPORTED_ALGORITHM':
      return `このファイルのアルゴリズムに対応していません (詳細: ${e.message})`;
    case 'PACKAGE_TOO_SHORT':
    case 'INVALID_METADATA_BLOCK_LENGTH':
      return 'ファイル形式が壊れています';
    case 'METADATA_DECRYPT_FAILED':
      return 'あなたの鍵では復号できません。送信者が別の公開鍵を使って暗号化した可能性があります';
    case 'BODY_DECRYPT_FAILED':
      return 'ファイル本体が破損しているか、改ざんされている可能性があります';
    case 'INVALID_METADATA_JSON':
      return 'メタデータの形式が不正です';
    default: {
      const _exhaustive: never = e.code;
      return `復号に失敗しました (${(_exhaustive as string) ?? e.message})`;
    }
  }
}

function mapKeystoreError(e: KeystoreError): string {
  switch (e.code) {
    case 'STORAGE_UNAVAILABLE':
      return 'シークレットウィンドウや古いブラウザでは利用できません';
    case 'NOT_FOUND':
      return '鍵ペアが見つかりません。setup.html で生成してください';
    case 'STORAGE_FAILED':
      return 'ストレージからの読み取りに失敗しました';
    case 'SCHEMA_MISMATCH':
      return '保存形式が古いか壊れています。setup.html でリセットしてやり直してください';
    case 'EXPORT_INVALID':
      return '鍵のエクスポートに失敗しました';
    default: {
      const _exhaustive: never = e.code;
      return `ストレージエラー: ${(_exhaustive as string) ?? e.message}`;
    }
  }
}

function handleError(e: unknown): void {
  console.error(e);
  if (e instanceof CryptoError) {
    showError(mapCryptoError(e));
  } else if (e instanceof KeystoreError) {
    showError(mapKeystoreError(e));
  } else {
    showError(`予期しないエラー: ${(e as Error)?.message ?? String(e)}`);
  }
}

// =============================================================================
// 復号フロー
// =============================================================================

/**
 * バックエンド API のベースパス。ビルド mode で切り替える。
 * - 本番 (npm run build): 'backend' (dist の中身を直下配置)
 * - dev / ローカル: '../../backend' (frontend/dist 階層から見た相対)
 * 詳細は upload.ts のコメントおよび docs/deployment.md を参照。
 */
const BACKEND_BASE = import.meta.env.PROD ? 'backend' : '../../backend';

/**
 * URL クエリ ?id= から指定された ID のファイルをサーバーから取得し、復号フローへ流す。
 * 既存の handleFile(File) と同じく Uint8Array に変換した後 decryptAsRecipient に渡す。
 */
async function handleIdFromUrl(id: string): Promise<void> {
  clearError();
  hideResult();
  decryptedResult = null;
  showLoading(id);

  try {
    const response = await fetch(`${BACKEND_BASE}/download.php?id=${encodeURIComponent(id)}`);
    if (!response.ok) {
      const errPayload = await response.json().catch(() => null) as
        | { error?: string; message?: string }
        | null;
      // ステータス別の利用者向けメッセージ
      if (response.status === 404) {
        showError('指定された URL のファイルが見つかりません (削除済みか URL が誤っている可能性)');
      } else if (response.status === 410) {
        showError('このファイルは有効期限が切れています');
      } else if (response.status === 400) {
        showError(`URL の形式が不正です: ${errPayload?.message ?? ''}`);
      } else {
        showError(
          `サーバーから取得失敗 (${response.status}): ${errPayload?.message ?? response.statusText}`,
        );
      }
      return;
    }
    const buf = await response.arrayBuffer();
    const packed = new Uint8Array(buf);

    const kp = await loadKeyPair();
    if (!kp) {
      showError('鍵ペアが見つかりません。setup.html で生成してください');
      renderNoKey();
      return;
    }

    const result = decryptAsRecipient(packed, kp.sec);
    decryptedResult = result;
    renderResult(result, true);
    // 復号成功後、バックグラウンドで受領確認 (サーバー上のファイルを削除)
    void confirmReceipt(id);
  } catch (e) {
    // ネットワーク失敗時など (fetch 自体が throw)
    if (e instanceof CryptoError) {
      showError(mapCryptoError(e));
    } else if (e instanceof KeystoreError) {
      showError(mapKeystoreError(e));
    } else {
      console.error(e);
      showError(`URL からの取得失敗: ネットワーク経由でサーバーに到達できませんでした`);
    }
  } finally {
    hideLoading();
  }
}

async function handleFile(file: File): Promise<void> {
  clearError();
  hideResult();
  // 前の復号結果は新しいファイル選択時点で破棄 (メモリを引きずらない)
  decryptedResult = null;

  try {
    const buf = await file.arrayBuffer();
    const packed = new Uint8Array(buf);

    const kp = await loadKeyPair();
    if (!kp) {
      showError('鍵ペアが見つかりません。setup.html で生成してください');
      renderNoKey();
      return;
    }

    const result = decryptAsRecipient(packed, kp.sec);
    decryptedResult = result;
    renderResult(result, false);
  } catch (e) {
    handleError(e);
  }
}

// =============================================================================
// 保存 / クリア
// =============================================================================

function handleSave(): void {
  if (!decryptedResult) {
    showError('復号データがありません');
    return;
  }
  clearError();

  // 型アサーションの理由は upload.ts と同じ (TypeScript 5.7+ の
  // Uint8Array<ArrayBufferLike> ジェネリック対応)。ランタイムコピーは発生しない。
  const blob = new Blob([decryptedResult.plaintext as Uint8Array<ArrayBuffer>], {
    type: decryptedResult.metadata.mime || 'application/octet-stream',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = decryptedResult.metadata.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function handleClear(): void {
  decryptedResult = null;
  hideResult();
  fileInput.value = '';
  clearError();
}

// =============================================================================
// 初期化
// =============================================================================

async function init(): Promise<void> {
  try {
    const present = await hasKeyPair();
    if (!present) {
      renderNoKey();
      // URL に id があっても鍵が無いと復号できないので setup.html へ誘導するだけ
      return;
    }
    const createdAt = await getKeyPairCreatedAt();
    renderKeyAvailable(createdAt);

    // URL クエリ ?id= があれば自動取得 + 復号フロー
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    if (id !== null && id !== '') {
      // URL に id がある形式は厳密に英数字+ハイフン+アンダースコアに限る
      // (backend と同じ正規表現で事前にチェックして無駄なリクエストを避ける)
      if (/^[A-Za-z0-9_\-]{1,64}$/.test(id)) {
        await handleIdFromUrl(id);
      } else {
        showError('URL の id パラメータの形式が不正です');
      }
    }
  } catch (e) {
    // ストレージ自体が使えない (STORAGE_UNAVAILABLE 等) は全パネル非表示で
    // エラー表示のみとする
    noKeyPanel.style.display = 'none';
    keyPanel.style.display = 'none';
    dropzonePanel.style.display = 'none';
    handleError(e);
  }
}

// イベント配線
selectFileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  const f = fileInput.files?.[0];
  if (f) void handleFile(f);
});

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('dragover');
});
dropzone.addEventListener('dragleave', (e) => {
  if (e.target === dropzone) {
    dropzone.classList.remove('dragover');
  }
});
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  const f = e.dataTransfer?.files?.[0];
  if (f) void handleFile(f);
});

// ページ全体での誤ドロップ防止
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

saveBtn.addEventListener('click', handleSave);
clearBtn.addEventListener('click', handleClear);

void init();
