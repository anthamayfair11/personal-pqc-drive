/**
 * upload.ts - 送信者画面: 受信者公開鍵で D&D ファイルを暗号化
 *
 * UI フロー:
 *   ステップA: 公開鍵 JSON ファイルを選択 → 厳密にバリデート → メモリへ保持
 *   ステップB: ファイルを D&D or 選択 → encryptForRecipient → .ppqd でダウンロード
 *
 * 状態は upload.ts のモジュールスコープ変数のみで管理 (リロードで消失する)。
 * これは「送信時のエフェメラル性」と整合する: 鍵もファイルもサーバーには渡らず、
 * 送信完了後は破棄される (設計メモ エフェメラル鍵設計)。
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

// =============================================================================
// 状態 (モジュールスコープ、リロードで消失)
// =============================================================================

interface PubKeyState {
  pub: ReceiverPublicKeys;
  /** JSON 内の createdAt 文字列 (ISO 8601 形式を想定) */
  createdAt: string;
  /** UI に表示する短い識別子 (x_pk_b64 の先頭 16 文字) */
  identifier: string;
}

let pubKeyState: PubKeyState | null = null;
let selectedFile: File | null = null;

// =============================================================================
// DOM 取得
// =============================================================================

const errorEl           = document.getElementById('error')             as HTMLDivElement;
const stepA             = document.getElementById('step-a')            as HTMLElement;
const pubkeyInfo        = document.getElementById('pubkey-info')       as HTMLElement;
const stepB             = document.getElementById('step-b')            as HTMLElement;
const loadPubkeyBtn     = document.getElementById('load-pubkey-btn')   as HTMLButtonElement;
const pubkeyInput       = document.getElementById('pubkey-input')      as HTMLInputElement;
const pubkeyCreatedAtEl = document.getElementById('pubkey-created-at') as HTMLParagraphElement;
const pubkeyIdEl        = document.getElementById('pubkey-id')         as HTMLElement;
const reloadPubkeyLink  = document.getElementById('reload-pubkey-link') as HTMLAnchorElement;
const dropzone          = document.getElementById('dropzone')          as HTMLElement;
const fileInput         = document.getElementById('file-input')        as HTMLInputElement;
const selectFileBtn     = document.getElementById('select-file-btn')   as HTMLButtonElement;
const fileInfoEl        = document.getElementById('file-info')         as HTMLElement;
const fileNameEl        = document.getElementById('file-name')         as HTMLElement;
const fileSizeEl        = document.getElementById('file-size')         as HTMLElement;
const fileMimeEl        = document.getElementById('file-mime')         as HTMLElement;
const encryptBtn        = document.getElementById('encrypt-btn')       as HTMLButtonElement;

const ENCRYPT_LABEL = '暗号化してダウンロード';

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

/** Base64 → Uint8Array (atob ベース)。不正な Base64 では例外が投げられる */
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

/**
 * 暗号論的乱数で生成する英数字文字列。
 * 36 文字集合 × 8 文字 ≒ 41 bit のエントロピーで衝突確率は実用上十分に低い。
 */
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
// 公開鍵 JSON のバリデーション
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

/**
 * 受け取った未検証の JSON を型と長さの両面で検証して PubKeyState に変換する。
 * 不正な箇所があれば PubKeyValidationError を field 名付きで投げる
 * (UI 側はどこが不正かを利用者に表示できる)。
 */
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
  pubKeyState = null;
  // フォーム要素を初期化
  pubkeyInput.value = '';
  fileInput.value = '';
  selectedFile = null;
  fileInfoEl.style.display = 'none';
  encryptBtn.disabled = true;
}

// =============================================================================
// 公開鍵読み込み
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

// =============================================================================
// ファイル選択
// =============================================================================

function handleFileSelect(file: File): void {
  clearError();
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

// =============================================================================
// 暗号化 + ダウンロード
// =============================================================================

async function handleEncrypt(): Promise<void> {
  if (!pubKeyState || !selectedFile) {
    showError('内部状態エラー: 公開鍵またはファイルが選択されていません');
    return;
  }
  clearError();
  encryptBtn.disabled = true;
  encryptBtn.textContent = '暗号化中...';

  // 暗号化処理の本体。try/finally で UI を必ず復元。
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

    // Blob 経由でダウンロード。
    // 型アサーションの理由: TypeScript 5.7+ で Uint8Array にジェネリック引数が
    // 追加され、デフォルトは Uint8Array<ArrayBufferLike> となる。Blob constructor
    // は Uint8Array<ArrayBuffer> のみ受け付けるため明示する。crypto.ts が返す
    // バッファは実体として ArrayBuffer 上にあるのでランタイムでは無問題、
    // メモリコピーも発生しない。
    const blob = new Blob([packed as Uint8Array<ArrayBuffer>], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const filename = `${OUTPUT_FILENAME_PREFIX}${randomAlphanumeric(RANDOM_NAME_LEN)}${OUTPUT_FILENAME_SUFFIX}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    // 参照を切って GC を促す (100MB のファイルバッファを引きずらない)
    selectedFile = null;
    fileInput.value = '';
    fileInfoEl.style.display = 'none';
  } catch (e) {
    console.error(e);
    if (e instanceof CryptoError) {
      showError(`暗号化失敗 (${e.code}): ${e.message}`);
    } else {
      showError(`予期しないエラー: ${(e as Error).message ?? String(e)}`);
    }
  } finally {
    encryptBtn.disabled = selectedFile === null;
    encryptBtn.textContent = ENCRYPT_LABEL;
  }
}

// =============================================================================
// イベント配線
// =============================================================================

// 公開鍵読み込み
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

// ファイル選択 (ボタン経由)
selectFileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  const f = fileInput.files?.[0];
  if (f) handleFileSelect(f);
});

// D&D
dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('dragover');
});
dropzone.addEventListener('dragleave', (e) => {
  // dropzone から完全に離れた時だけ class 削除
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

// ページ全体での誤ドロップ防止 (ブラウザが画像をプレビューしてしまうのを抑制)
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

// 暗号化
encryptBtn.addEventListener('click', () => {
  void handleEncrypt();
});

// 初期状態
renderPubkeyEmpty();
