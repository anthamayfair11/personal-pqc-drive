/**
 * main.ts - フェーズ2 ステップ3: crypto.ts の動作確認用エントリ
 *
 * バンドラ (Vite) 経由で crypto.ts が prototype.html と等価に動作することを確認する。
 * 確認項目:
 *   - 正常往復 (本体・メタデータがバイト単位で一致)
 *   - 改ざん検出 (CryptoError がスローされ code が正しい)
 *   - 不正鍵での復号失敗 (CryptoError の code 識別)
 *
 * このファイルはフェーズ2の検証用一時エントリ。
 * 本実装の upload.ts / download.ts / setup.ts が揃った時点で置き換える。
 */

import {
  CRYPTO_CONSTANTS,
  decryptAsRecipient,
  encryptForRecipient,
  generateReceiverKeyPair,
} from './crypto.ts';
import { CryptoError, type FileMetadata } from './types.ts';

const utf8Encoder = new TextEncoder();

const logEl = document.getElementById('log') as HTMLDivElement;
const runBtn = document.getElementById('run-btn') as HTMLButtonElement;

type LogLevel = 'info' | 'muted' | 'step' | 'ok' | 'err';
function log(text: string, level: LogLevel = 'info'): void {
  const div = document.createElement('div');
  div.className = `log-${level}`;
  div.textContent = text;
  logEl.appendChild(div);
  if (level === 'err') console.error(text);
  else console.log(text);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function buildMetadata(name: string, mime: string, size: number): FileMetadata {
  return { name, mime, size, sentAt: new Date().toISOString() };
}

async function runTests(): Promise<void> {
  logEl.innerHTML = '';
  log(
    `crypto.ts: ALG_ID=0x${CRYPTO_CONSTANTS.ALG_ID.toString(16).padStart(2, '0')}` +
      ` / MIN_PACKED_LEN=${CRYPTO_CONSTANTS.MIN_PACKED_LEN}`,
    'muted',
  );

  // ===========================================================================
  // テスト 1: 正常往復
  // ===========================================================================
  log('テスト1: 正常往復', 'step');
  try {
    const plaintext = utf8Encoder.encode(
      'Hello from Vite + crypto.ts! バンドラ経由で動作するか確認中…',
    );
    const metadata = buildMetadata('greeting.txt', 'text/plain; charset=utf-8', plaintext.length);

    const t0 = performance.now();
    const recipient = generateReceiverKeyPair();
    const t1 = performance.now();
    log(`鍵生成: ${(t1 - t0).toFixed(1)} ms`, 'muted');

    const packed = encryptForRecipient(recipient.pub, plaintext, metadata);
    const t2 = performance.now();
    log(`暗号化: ${(t2 - t1).toFixed(1)} ms / packed=${packed.length} bytes`, 'muted');

    const result = decryptAsRecipient(packed, recipient.sec);
    const t3 = performance.now();
    log(`復号: ${(t3 - t2).toFixed(1)} ms`, 'muted');

    const bodyMatch = bytesEqual(plaintext, result.plaintext);
    const metaMatch = JSON.stringify(metadata) === JSON.stringify(result.metadata);

    if (bodyMatch && metaMatch) {
      log(`✓ 期待通り成功した (本体・メタデータ完全一致)`, 'ok');
    } else {
      log(`✗ 不一致 body=${bodyMatch} meta=${metaMatch}`, 'err');
    }
  } catch (e) {
    log(`✗ 想定外の例外: ${(e as Error).message}`, 'err');
    console.error(e);
  }

  // ===========================================================================
  // テスト 2: 改ざん検出 (ファイル本体の末尾近く1バイトを反転)
  // ===========================================================================
  log('テスト2: 改ざん検出', 'step');
  try {
    const plaintext = utf8Encoder.encode('tamper detection test payload');
    const metadata = buildMetadata('tamper.txt', 'text/plain', plaintext.length);
    const recipient = generateReceiverKeyPair();
    const packed = encryptForRecipient(recipient.pub, plaintext, metadata);

    const tampered = new Uint8Array(packed);
    const idx = tampered.length - 5; // Poly1305 タグの少し手前
    const orig = tampered[idx];
    tampered[idx] = orig ^ 0xff;
    log(`本体 offset=${idx}: 0x${orig.toString(16).padStart(2, '0')} → 0x${tampered[idx].toString(16).padStart(2, '0')}`, 'muted');

    try {
      decryptAsRecipient(tampered, recipient.sec);
      log('✗ 想定外: 改ざんが検出されなかった', 'err');
    } catch (e) {
      if (e instanceof CryptoError) {
        log(`✓ 期待通り失敗した: code=${e.code}, message="${e.message}"`, 'ok');
      } else {
        log(`✗ 想定外の例外型: ${e}`, 'err');
      }
    }
  } catch (e) {
    log(`✗ セットアップで例外: ${(e as Error).message}`, 'err');
    console.error(e);
  }

  // ===========================================================================
  // テスト 3: 不正鍵での復号失敗
  // ===========================================================================
  log('テスト3: 不正鍵での復号失敗', 'step');
  try {
    const plaintext = utf8Encoder.encode('wrong key test payload');
    const metadata = buildMetadata('wrong.txt', 'text/plain', plaintext.length);
    const r1 = generateReceiverKeyPair();
    const r2 = generateReceiverKeyPair();
    const packed = encryptForRecipient(r1.pub, plaintext, metadata);

    try {
      decryptAsRecipient(packed, r2.sec);
      log('✗ 想定外: 別人の鍵で復号できてしまった', 'err');
    } catch (e) {
      if (e instanceof CryptoError) {
        log(`✓ 期待通り失敗した: code=${e.code}`, 'ok');
      } else {
        log(`✗ 想定外の例外型: ${e}`, 'err');
      }
    }
  } catch (e) {
    log(`✗ セットアップで例外: ${(e as Error).message}`, 'err');
    console.error(e);
  }

  // ===========================================================================
  // テスト 4: ヘッダー検証 (マジックバイトを破壊)
  // ===========================================================================
  log('テスト4: マジックバイト検証', 'step');
  try {
    const plaintext = utf8Encoder.encode('magic byte test');
    const metadata = buildMetadata('magic.txt', 'text/plain', plaintext.length);
    const recipient = generateReceiverKeyPair();
    const packed = encryptForRecipient(recipient.pub, plaintext, metadata);

    const tampered = new Uint8Array(packed);
    tampered[0] = 0x00; // 'P' を破壊

    try {
      decryptAsRecipient(tampered, recipient.sec);
      log('✗ 想定外: 不正なマジックバイトを受け入れてしまった', 'err');
    } catch (e) {
      if (e instanceof CryptoError && e.code === 'INVALID_MAGIC') {
        log(`✓ 期待通り失敗した: code=${e.code}`, 'ok');
      } else if (e instanceof CryptoError) {
        log(`△ CryptoError だが code が想定と違う: ${e.code} (期待: INVALID_MAGIC)`, 'err');
      } else {
        log(`✗ 想定外の例外型: ${e}`, 'err');
      }
    }
  } catch (e) {
    log(`✗ セットアップで例外: ${(e as Error).message}`, 'err');
    console.error(e);
  }

  log('全テスト完了', 'step');
}

runBtn.addEventListener('click', () => {
  runBtn.disabled = true;
  runTests().finally(() => {
    runBtn.disabled = false;
  });
});

// 自動初回実行
window.addEventListener('DOMContentLoaded', () => {
  void runTests();
});
