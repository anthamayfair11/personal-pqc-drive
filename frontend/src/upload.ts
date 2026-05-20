/**
 * upload.ts - 送信者画面: 受信者公開鍵で D&D ファイルを暗号化 + アップロード
 *
 * UI フロー:
 *   ステップ A: 公開鍵 JSON ファイルを選択 → 厳密にバリデート → メモリへ保持
 *   ステップ B: ファイル D&D / 選択 → 「暗号化」
 *   暗号化結果: 暗号化済みデータを保持して、「ダウンロード」「サーバーへアップロード」を選択
 *   アップロード結果: 共有 URL を表示 + クリップボードコピー
 *
 * 状態 (pubKeyState, selectedFile, lastPacked) はモジュールスコープ。
 * リロードで全消失 (送信のエフェメラル性と整合)。
 */

import { encryptForRecipient } from './crypto.ts';
import {
  CryptoError,
  type FileMetadata,
  type ReceiverPublicKeys,
} from './types.ts';

// =============================================================================
// 定数
// =============================================================================

const MAX_FILE_SIZE = 100 * 1024 * 1024;       // 100 MB 上限
const EXPECTED_X25519_PK_LEN = 32;             // RFC 7748
const EXPECTED_MLKEM_PK_LEN = 1184;            // NIST FIPS 203 Table 2
const PUBKEY_FILE_TYPE = 'personal-pqc-drive-recipient-pubkey';
const PUBKEY_FILE_VERSION = 1;
const OUTPUT_FILENAME_PREFIX = 'ppqd-';
const OUTPUT_FILENAME_SUFFIX = '.ppqd';
const RANDOM_NAME_LEN = 8;

/**
 * バックエンド API のベースパス (dist/upload.html から見た相対パス)。
 *
 * 配置例:
 *   /personal-pqc-drive/frontend/dist/upload.html  ← このページ
 *   /personal-pqc-drive/backend/upload.php         ← フェッチ先
 * の相対関係。dev 時も PHP ビルトインサーバ (php -S -t プロジェクトルート) で
 * 同じパス解決になるよう設計。
 */
const BACKEND_BASE = '../../backend';

// =============================================================================
// 状態 (モジュールスコープ、リロードで消失)
// =============================================================================

interface PubKeyState {
  pub: ReceiverPublicKeys;
  createdAt: string;
  identifier: string;
}

let pubKeyState: PubKeyState | null = null;
let selectedFile: File | null = null;
let lastPacked: Uint8Array | null = null;

// =============================================================================
// DOM 取得
// =============================================================================

const errorEl            = document.getElementById('error')                as HTMLDivElement;
const stepA              = document.getElementById('step-a')               as HTMLElement;
const pubkeyInfo         = document.getElementById('pubkey-info')          as HTMLElement;
const stepB              = document.getElementById('step-b')               as HTMLElement;
const encryptResultPanel = document.getElementById('encrypt-result')       as HTMLElement;
const uploadResultPanel  = document.getElementById('upload-result-panel')  as HTMLElement;
const loadPubkeyBtn      = document.getElementById('load-pubkey-btn')      as HTMLButtonElement;
const pubkeyInput        = document.getElementById('pubkey-input')         as HTMLInputElement;
const pubkeyCreatedAtEl  = document.getElementById('pubkey-created-at')    as HTMLParagraphElement;
const pubkeyIdEl         = document.getElementById('pubkey-id')            as HTMLElement;
const reloadPubkeyLink   = document.getElementById('reload-pubkey-link')   as HTMLAnchorElement;
const dropzone           = document.getElementById('dropzone')             as HTMLElement;
const fileInput          = document.getElementById('file-input')           as HTMLInputElement;
const selectFileBtn      = document.getElementById('select-file-btn')      as HTMLButtonElement;
const fileInfoEl         = document.getElementById('file-info')            as HTMLElement;
const fileNameEl         = document.getElementById('file-name')            as HTMLElement;
const fileSizeEl         = document.getElementById('file-size')            as HTMLElement;
const fileMimeEl         = document.getElementById('file-mime')            as HTMLElement;
const encryptBtn         = document.getElementById('encrypt-btn')          as HTMLButtonElement;
const encryptStatsEl     = document.getElementById('encrypt-stats')        as HTMLElement;
const downloadBtn        = document.getElementById('download-btn')         as HTMLButtonElement;
const uploadBtn          = document.getElementById('upload-btn')           as HTMLButtonElement;
const shareUrlEl         = document.getElementById('share-url')            as HTMLElement;
const expireAtEl         = document.getElementById('expire-at')            as HTMLElement;
const copyUrlBtn         = document.getElementById('copy-url-btn')         as HTMLButtonElement;

const ENCRYPT_LABEL = '暗号化';
const UPLOAD_LABEL  = 'サーバーにアップロードして URL 取得';
const COPY_LABEL    = 'URL をコピー';

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

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

/** 36 文字集合 × 8 文字 ≒ 41 bit。ローカル保存時のファイル名衝突回避用 */
function randomAlphanumeric(len: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = '';
  for (const b of bytes) {
    out += chars[b % chars.length];
  }
  return out;
}

// =============================================================================
// 公開鍵 JSON バリデーション
// =============================================================================

class PubKeyValidationError extends Error {
  override readonly name = 'PubKeyValidationError';
  constructor(
    public readonly field: string,
    message: string,
  ) {
    super(message);
  }
}

function validateAndParsePubkey(json: unknown): PubKeyState {
  if (typeof json !== 'object' || json === null) {
    throw new PubKeyValidationError('root', 'JSON のルートがオブジェクトではありません');
  }
  const obj = json as Record<string, unknown>;

  if (obj.type !== PUBKEY_FILE_TYPE) {
    throw new PubKeyValidationError(
      'type',
      `type が "${PUBKEY_FILE_TYPE}" ではありません (got: ${JSON.stringify(obj.type)})`,
    );
  }
  if (obj.version !== PUBKEY_FILE_VERSION) {
    throw new PubKeyValidationError(
      'version',
      `version が ${PUBKEY_FILE_VERSION} ではありません (got: ${JSON.stringify(obj.version)})`,
    );
  }
  if (typeof obj.x_pk_b64 !== 'string') {
    throw new PubKeyValidationError('x_pk_b64', 'x_pk_b64 が文字列ではありません');
  }
  if (typeof obj.m_pk_b64 !== 'string') {
    throw new PubKeyValidationError('m_pk_b64', 'm_pk_b64 が文字列ではありません');
  }
  if (typeof obj.createdAt !== 'string') {
    throw new PubKeyValidationError('createdAt', 'createdAt が文字列ではありません');
  }

  let x_pk: Uint8Array;
  let m_pk: Uint8Array;
  try {
    x_pk = base64ToBytes(obj.x_pk_b64);
  } catch {
    throw new PubKeyValidationError('x_pk_b64', 'x_pk_b64 が有効な Base64 ではありません');
  }
  try {
    m_pk = base64ToBytes(obj.m_pk_b64);
  } catch {
    throw new PubKeyValidationError('m_pk_b64', 'm_pk_b64 が有効な Base64 ではありません');
  }
  if (x_pk.length !== EXPECTED_X25519_PK_LEN) {
    throw new PubKeyValidationError(
      'x_pk_b64',
      `x_pk のバイト長が不正: ${x_pk.length} bytes (期待: ${EXPECTED_X25519_PK_LEN})`,
    );
  }
  if (m_pk.length !== EXPECTED_MLKEM_PK_LEN) {
    throw new PubKeyValidationError(
      'm_pk_b64',
      `m_pk のバイト長が不正: ${m_pk.length} bytes (期待: ${EXPECTED_MLKEM_PK_LEN})`,
    );
  }

  return {
    pub: { x_pk, m_pk },
    createdAt: obj.createdAt,
    identifier: obj.x_pk_b64.slice(0, 16),
  };
}

// =============================================================================
// 表示制御
// =============================================================================

function renderPubkeyLoaded(state: PubKeyState): void {
  stepA.style.display = 'none';
  pubkeyInfo.style.display = 'block';
  stepB.style.display = 'block';

  const d = new Date(state.createdAt);
  pubkeyCreatedAtEl.textContent = Number.isNaN(d.getTime())
    ? `生成日時: ${state.createdAt}`
    : `${formatDateTime(d)} 生成`;
  pubkeyIdEl.textContent = state.identifier;
}

function renderPubkeyEmpty(): void {
  stepA.style.display = 'block';
  pubkeyInfo.style.display = 'none';
  stepB.style.display = 'none';
  encryptResultPanel.style.display = 'none';
  uploadResultPanel.style.display = 'none';
  pubKeyState = null;
  selectedFile = null;
  lastPacked = null;
  pubkeyInput.value = '';
  fileInput.value = '';
  fileInfoEl.style.display = 'none';
  encryptBtn.disabled = true;
}

function renderEncrypted(originalSize: number, packedSize: number): void {
  encryptResultPanel.style.display = 'block';
  uploadResultPanel.style.display = 'none';
  encryptStatsEl.textContent =
    `元サイズ ${formatBytes(originalSize)} → 暗号化後 ${formatBytes(packedSize)} ` +
    `(オーバーヘッド ${formatBytes(packedSize - originalSize)})`;
  downloadBtn.disabled = false;
  uploadBtn.disabled = false;
  copyUrlBtn.textContent = COPY_LABEL;
}

function renderUploaded(id: string, expireAtISO: string): void {
  uploadResultPanel.style.display = 'block';
  // 共有 URL: dist/upload.html と同じディレクトリの download.html に ?id= を付ける
  const shareUrl = new URL('download.html', window.location.href);
  shareUrl.searchParams.set('id', id);
  shareUrlEl.textContent = shareUrl.toString();

  const expireDate = new Date(expireAtISO);
  expireAtEl.textContent = Number.isNaN(expireDate.getTime())
    ? expireAtISO
    : formatDateTime(expireDate);
}

// =============================================================================
// アクションハンドラ
// =============================================================================

async function handlePubkeyLoad(file: File): Promise<void> {
  clearError();
  let text: string;
  try {
    text = await file.text();
  } catch (e) {
    showError('ファイルの読み取りに失敗しました');
    console.error(e);
    return;
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    showError('JSON のパースに失敗しました。有効な JSON ファイルを選択してください。');
    return;
  }

  try {
    const state = validateAndParsePubkey(json);
    pubKeyState = state;
    renderPubkeyLoaded(state);
  } catch (e) {
    if (e instanceof PubKeyValidationError) {
      showError(`公開鍵 JSON が不正です [${e.field}]: ${e.message}`);
    } else {
      console.error(e);
      showError(`予期しないエラー: ${(e as Error).message ?? String(e)}`);
    }
  }
}

function handleFileSelect(file: File): void {
  clearError();
  // 新しいファイル選択時は前回の暗号化結果を破棄 (鮮度のために)
  lastPacked = null;
  encryptResultPanel.style.display = 'none';
  uploadResultPanel.style.display = 'none';

  if (file.size > MAX_FILE_SIZE) {
    showError(
      `100 MB を超えるファイルは現バージョンでは対応していません ` +
        `(選択ファイル: ${formatBytes(file.size)})`,
    );
    selectedFile = null;
    fileInput.value = '';
    fileInfoEl.style.display = 'none';
    encryptBtn.disabled = true;
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;
  fileSizeEl.textContent = formatBytes(file.size);
  fileMimeEl.textContent = file.type || '(unknown)';
  fileInfoEl.style.display = 'block';
  encryptBtn.disabled = false;
}

async function handleEncrypt(): Promise<void> {
  if (!pubKeyState || !selectedFile) {
    showError('内部状態エラー: 公開鍵またはファイルが選択されていません');
    return;
  }
  clearError();
  encryptBtn.disabled = true;
  encryptBtn.textContent = '暗号化中...';

  try {
    const file = selectedFile;
    const buf = await file.arrayBuffer();
    const plaintext = new Uint8Array(buf);

    const metadata: FileMetadata = {
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: plaintext.length,
      sentAt: new Date().toISOString(),
    };

    const packed = encryptForRecipient(pubKeyState.pub, plaintext, metadata);
    lastPacked = packed;
    renderEncrypted(plaintext.length, packed.length);
  } catch (e) {
    console.error(e);
    if (e instanceof CryptoError) {
      showError(`暗号化失敗 (${e.code}): ${e.message}`);
    } else {
      showError(`予期しないエラー: ${(e as Error).message ?? String(e)}`);
    }
  } finally {
    encryptBtn.disabled = false;
    encryptBtn.textContent = ENCRYPT_LABEL;
  }
}

function handleDownload(): void {
  if (!lastPacked) {
    showError('先に暗号化してください');
    return;
  }
  clearError();
  // Uint8Array<ArrayBuffer> アサーションは TypeScript 5.7+ の Blob 型整合のため
  const blob = new Blob([lastPacked as Uint8Array<ArrayBuffer>], {
    type: 'application/octet-stream',
  });
  const url = URL.createObjectURL(blob);
  const filename =
    `${OUTPUT_FILENAME_PREFIX}${randomAlphanumeric(RANDOM_NAME_LEN)}${OUTPUT_FILENAME_SUFFIX}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function handleUpload(): Promise<void> {
  if (!lastPacked) {
    showError('先に暗号化してください');
    return;
  }
  clearError();
  uploadBtn.disabled = true;
  uploadBtn.textContent = 'アップロード中...';

  try {
    const formData = new FormData();
    const blob = new Blob([lastPacked as Uint8Array<ArrayBuffer>], {
      type: 'application/octet-stream',
    });
    formData.append('file', blob, 'upload.ppqd');

    const response = await fetch(`${BACKEND_BASE}/upload.php`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      // エラー JSON を読み取って詳細を表示。読み取り失敗時は status のみ
      const errPayload = await response.json().catch(() => null) as
        | { error?: string; message?: string }
        | null;
      const msg = errPayload?.message ?? response.statusText;
      const code = errPayload?.error ?? `HTTP_${response.status}`;
      showError(`アップロード失敗 (${code}): ${msg}`);
      return;
    }

    const result = (await response.json()) as {
      id: string;
      expireAt: string;
      downloadUrl: string;
    };
    renderUploaded(result.id, result.expireAt);
  } catch (e) {
    console.error(e);
    showError(`アップロード失敗: ネットワーク経由でサーバーに到達できませんでした`);
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = UPLOAD_LABEL;
  }
}

async function handleCopyUrl(): Promise<void> {
  const text = shareUrlEl.textContent ?? '';
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    copyUrlBtn.textContent = 'コピーしました';
    window.setTimeout(() => {
      copyUrlBtn.textContent = COPY_LABEL;
    }, 2000);
  } catch (e) {
    console.error(e);
    showError('クリップボードへのコピーに失敗しました。URL を選択して手動でコピーしてください。');
  }
}

// =============================================================================
// イベント配線
// =============================================================================

loadPubkeyBtn.addEventListener('click', () => pubkeyInput.click());
pubkeyInput.addEventListener('change', () => {
  const f = pubkeyInput.files?.[0];
  if (f) void handlePubkeyLoad(f);
});
reloadPubkeyLink.addEventListener('click', (e) => {
  e.preventDefault();
  clearError();
  renderPubkeyEmpty();
});

selectFileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  const f = fileInput.files?.[0];
  if (f) handleFileSelect(f);
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
  if (f) handleFileSelect(f);
});

window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

encryptBtn.addEventListener('click', () => void handleEncrypt());
downloadBtn.addEventListener('click', handleDownload);
uploadBtn.addEventListener('click', () => void handleUpload());
copyUrlBtn.addEventListener('click', () => void handleCopyUrl());

// 初期状態
renderPubkeyEmpty();
