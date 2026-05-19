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
import {
  deleteKeyPair,
  exportPublicKeys,
  getKeyPairCreatedAt,
  hasKeyPair,
  loadKeyPair,
  saveKeyPair,
} from './keystore.ts';
import { CryptoError, KeystoreError, type FileMetadata } from './types.ts';

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

  // ===========================================================================
  // テスト5+: keystore (IndexedDB 永続化、crypto.ts 統合)
  // ===========================================================================
  log('テスト5+: keystore (IndexedDB 永続化)', 'step');
  try {
    // 5.1: 前段クリア (前回のテスト残骸を消す)
    log('5.1: deleteKeyPair() で開始前にクリーンスレートに', 'muted');
    await deleteKeyPair();

    // 5.2: hasKeyPair が false
    const initiallyEmpty = await hasKeyPair();
    if (initiallyEmpty === false) {
      log('✓ 5.2: hasKeyPair() === false (削除直後)', 'ok');
    } else {
      log(`✗ 5.2: 想定外、hasKeyPair=${initiallyEmpty}`, 'err');
    }

    // 5.3: 鍵生成 + saveKeyPair
    const kp = generateReceiverKeyPair();
    await saveKeyPair(kp);
    log('✓ 5.3: generateReceiverKeyPair() → saveKeyPair() 完了', 'ok');

    // 5.4: hasKeyPair が true
    const present = await hasKeyPair();
    if (present === true) {
      log('✓ 5.4: hasKeyPair() === true (保存後)', 'ok');
    } else {
      log(`✗ 5.4: 想定外、保存後も hasKeyPair=${present}`, 'err');
    }

    // 5.5: getKeyPairCreatedAt が Date
    const createdAt = await getKeyPairCreatedAt();
    if (createdAt instanceof Date) {
      log(`✓ 5.5: getKeyPairCreatedAt() = ${createdAt.toISOString()}`, 'ok');
    } else {
      log(`✗ 5.5: 想定外、createdAt が Date でない (${createdAt})`, 'err');
    }

    // 5.6: loadKeyPair でバイト一致
    const loaded = await loadKeyPair();
    if (loaded === null) {
      log('✗ 5.6: 想定外、loadKeyPair() が null', 'err');
    } else {
      const allMatch =
        bytesEqual(kp.pub.x_pk, loaded.pub.x_pk) &&
        bytesEqual(kp.pub.m_pk, loaded.pub.m_pk) &&
        bytesEqual(kp.sec.x_sk, loaded.sec.x_sk) &&
        bytesEqual(kp.sec.m_sk, loaded.sec.m_sk);
      if (allMatch) {
        log('✓ 5.6: loadKeyPair() で 4 つのバイト列すべて一致', 'ok');
      } else {
        log('✗ 5.6: ロード後のバイト列に不一致あり', 'err');
      }

      // 5.7: 統合テスト - ロードした鍵で crypto.ts 暗号往復
      try {
        const pt = utf8Encoder.encode('keystore-loaded key roundtrip integration test');
        const meta = buildMetadata('integration.txt', 'text/plain', pt.length);
        const packed = encryptForRecipient(loaded.pub, pt, meta);
        const result = decryptAsRecipient(packed, loaded.sec);
        if (bytesEqual(pt, result.plaintext)) {
          log(`✓ 5.7: ロード鍵で crypto.ts 暗号往復成功 (packed=${packed.length}B)`, 'ok');
        } else {
          log('✗ 5.7: ロード鍵での往復で本体不一致', 'err');
        }
      } catch (e) {
        if (e instanceof CryptoError) {
          log(`✗ 5.7: CryptoError code=${e.code}: ${e.message}`, 'err');
        } else {
          log(`✗ 5.7: 想定外の例外: ${(e as Error).message}`, 'err');
        }
      }
    }

    // 5.8: exportPublicKeys の Base64 出力
    const exported = await exportPublicKeys();
    if (exported === null) {
      log('✗ 5.8: 想定外、exportPublicKeys() が null', 'err');
    } else {
      const xLen = atob(exported.x_pk_b64).length;
      const mLen = atob(exported.m_pk_b64).length;
      if (xLen === 32 && mLen === 1184) {
        log(`✓ 5.8: Base64 復号後 x_pk=${xLen}B / m_pk=${mLen}B`, 'ok');
        log(`x_pk_b64 先頭16: ${exported.x_pk_b64.slice(0, 16)}... (全${exported.x_pk_b64.length} chars)`, 'muted');
        log(`m_pk_b64 先頭16: ${exported.m_pk_b64.slice(0, 16)}... (全${exported.m_pk_b64.length} chars)`, 'muted');
      } else {
        log(`✗ 5.8: 復号後の長さが想定外 x=${xLen} m=${mLen}`, 'err');
      }
    }

    // 5.9: deleteKeyPair → hasKeyPair が false に戻る
    await deleteKeyPair();
    const afterDelete = await hasKeyPair();
    if (afterDelete === false) {
      log('✓ 5.9: deleteKeyPair() 後に hasKeyPair() === false', 'ok');
    } else {
      log(`✗ 5.9: 想定外、削除後も hasKeyPair=${afterDelete}`, 'err');
    }
  } catch (e) {
    if (e instanceof KeystoreError) {
      log(`✗ KeystoreError: code=${e.code}, message="${e.message}"`, 'err');
    } else {
      log(`✗ 想定外の例外: ${(e as Error).message}`, 'err');
    }
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
