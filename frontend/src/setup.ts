/**
 * setup.ts - 受信者初期セットアップ画面のロジック
 *
 * UI フロー:
 *   ページロード → hasKeyPair() で分岐
 *     - 未生成 (false): 「鍵ペアを生成して保管」ボタンを表示
 *     - 生成済み (true): 生成日時 + エクスポート + リセットボタンを表示
 *
 * 依存:
 *   crypto.ts (generateReceiverKeyPair のみ) + keystore.ts
 *   types.ts の KeystoreError を code で分岐して UI 向けメッセージを表示
 */

import { generateReceiverKeyPair } from './crypto.ts';
import {
  deleteKeyPair,
  exportPublicKeys,
  getKeyPairCreatedAt,
  hasKeyPair,
  saveKeyPair,
} from './keystore.ts';
import { KeystoreError } from './types.ts';

// =============================================================================
// DOM 取得
// =============================================================================

const errorEl      = document.getElementById('error')         as HTMLDivElement;
const emptyPanel   = document.getElementById('empty-panel')   as HTMLElement;
const presentPanel = document.getElementById('present-panel') as HTMLElement;
const createdAtEl  = document.getElementById('created-at')    as HTMLParagraphElement;
const generateBtn  = document.getElementById('generate-btn')  as HTMLButtonElement;
const exportBtn    = document.getElementById('export-btn')    as HTMLButtonElement;
const resetBtn     = document.getElementById('reset-btn')     as HTMLButtonElement;

const GENERATE_LABEL = '鍵ペアを生成して保管';

// =============================================================================
// 表示制御
// =============================================================================

function renderEmpty(): void {
  emptyPanel.style.display = 'block';
  presentPanel.style.display = 'none';
}

function renderPresent(createdAt: Date | null): void {
  emptyPanel.style.display = 'none';
  presentPanel.style.display = 'block';
  createdAtEl.textContent = createdAt
    ? `${formatDateTime(createdAt)} 生成`
    : '生成日時不明';
}

function hidePanels(): void {
  emptyPanel.style.display = 'none';
  presentPanel.style.display = 'none';
}

function showError(message: string): void {
  errorEl.textContent = message;
  errorEl.style.display = 'block';
}

function clearError(): void {
  errorEl.textContent = '';
  errorEl.style.display = 'none';
}

// =============================================================================
// フォーマッタ
// =============================================================================

function pad2(n: number): string {
  return n.toString().padStart(2, '0');
}

/** "YYYY-MM-DD HH:mm" 形式 (ローカルタイムゾーン)。表示用 */
function formatDateTime(d: Date): string {
  return (
    `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}`
  );
}

/** "YYYYMMDD" 形式 (ファイル名用) */
function formatDateYYYYMMDD(d: Date): string {
  return `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}`;
}

// =============================================================================
// エラー処理
// =============================================================================

/**
 * KeystoreError の code に応じたユーザー向けメッセージを出す。
 * 他種のエラーは原文を出して隠さない (デバッグ可能性優先)。
 */
function handleError(e: unknown): void {
  console.error(e);
  if (e instanceof KeystoreError) {
    switch (e.code) {
      case 'STORAGE_UNAVAILABLE':
        showError('シークレットウィンドウや古いブラウザでは利用できません');
        return;
      case 'STORAGE_FAILED':
        showError('ストレージへの保存に失敗しました');
        return;
      case 'SCHEMA_MISMATCH':
        showError('保存形式が古いか壊れています。リセットしてやり直してください');
        return;
      case 'EXPORT_INVALID':
        showError('公開鍵のエクスポートに失敗しました');
        return;
      case 'NOT_FOUND':
        showError('鍵が見つかりません');
        return;
      default: {
        // 網羅性チェック: 新しい code が増えたら TS がここでエラーになる
        const _exhaustive: never = e.code;
        showError(`エラー: ${(_exhaustive as string) ?? e.message}`);
        return;
      }
    }
  }
  showError(`予期しないエラー: ${(e as Error)?.message ?? String(e)}`);
}

// =============================================================================
// アクションハンドラ
// =============================================================================

async function handleGenerate(): Promise<void> {
  clearError();
  generateBtn.disabled = true;
  generateBtn.textContent = '生成中...';
  try {
    const kp = generateReceiverKeyPair();
    await saveKeyPair(kp);
    const createdAt = await getKeyPairCreatedAt();
    renderPresent(createdAt);
  } catch (e) {
    handleError(e);
  } finally {
    generateBtn.disabled = false;
    generateBtn.textContent = GENERATE_LABEL;
  }
}

async function handleExport(): Promise<void> {
  clearError();
  exportBtn.disabled = true;
  try {
    const exported = await exportPublicKeys();
    if (!exported) {
      showError('エクスポート対象の鍵が存在しません');
      return;
    }
    const createdAt = (await getKeyPairCreatedAt()) ?? new Date();

    const json = {
      type: 'personal-pqc-drive-recipient-pubkey',
      version: 1,
      x_pk_b64: exported.x_pk_b64,
      m_pk_b64: exported.m_pk_b64,
      createdAt: createdAt.toISOString(),
    };
    const blob = new Blob([JSON.stringify(json, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const filename = `personal-pqc-drive-pubkey-${formatDateYYYYMMDD(createdAt)}.json`;
    // クリック専用の一時 <a> でダウンロードを発火
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    handleError(e);
  } finally {
    exportBtn.disabled = false;
  }
}

async function handleReset(): Promise<void> {
  clearError();
  const msg =
    '鍵をリセットすると、この鍵で暗号化された過去のすべてのファイルが復号できなくなります。' +
    '\n\nフェーズ2では秘密鍵のバックアップ機能がまだ未実装のため、リセットすると完全に失われます。' +
    '\n\n本当にリセットしますか?';
  if (!confirm(msg)) return;

  resetBtn.disabled = true;
  try {
    await deleteKeyPair();
    renderEmpty();
  } catch (e) {
    handleError(e);
  } finally {
    resetBtn.disabled = false;
  }
}

// =============================================================================
// 初期化
// =============================================================================

async function init(): Promise<void> {
  try {
    const present = await hasKeyPair();
    if (present) {
      const createdAt = await getKeyPairCreatedAt();
      renderPresent(createdAt);
    } else {
      renderEmpty();
    }
  } catch (e) {
    // 初期化失敗時は両パネルを隠してエラーのみ表示
    // (SCHEMA_MISMATCH 等で hasKeyPair 自体が成功しても loadKeyPair で失敗する可能性は
    //  本フローには無いが、ストレージ自体が使えない場合に到達する)
    hidePanels();
    handleError(e);
  }
}

generateBtn.addEventListener('click', () => {
  void handleGenerate();
});
exportBtn.addEventListener('click', () => {
  void handleExport();
});
resetBtn.addEventListener('click', () => {
  void handleReset();
});

window.addEventListener('DOMContentLoaded', () => {
  void init();
});
