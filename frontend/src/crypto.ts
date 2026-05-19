/**
 * crypto.ts - Personal PQC Drive のコア暗号モジュール
 *
 * 「暗号化処理は crypto.ts に集約し、他のファイルからは関数として呼び出すのみ」
 * (プロジェクトのコード規約) に従い、全ての暗号操作をこのモジュールに閉じ込める。
 *
 * 仕様の詳細とアルゴリズム選定の根拠は docs/crypto-spec.md を参照。
 * フェーズ1の prototype.html で動作検証済みの実装を TypeScript 化して切り出したもの。
 *
 * 公開 API:
 *   - generateReceiverKeyPair(): 受信者の永続鍵ペアを生成
 *   - encryptForRecipient():     受信者公開鍵でファイルを暗号化
 *   - decryptAsRecipient():      受信者秘密鍵でパック済みバイナリを復号
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { x25519 } from '@noble/curves/ed25519';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  CryptoError,
  type DecryptResult,
  type FileMetadata,
  type ReceiverKeyPair,
  type ReceiverPublicKeys,
  type ReceiverSecretKeys,
} from './types.ts';

// =============================================================================
// 定数 (docs/crypto-spec.md §5 のバイナリフォーマット仕様に準拠)
// =============================================================================

/** ファイル先頭マジックバイト "PPQD" (Personal PQC Drive の頭文字) */
const MAGIC = new Uint8Array([0x50, 0x50, 0x51, 0x44]);

/** フォーマットバージョン。プロトコル変更時にインクリメント */
const VERSION = 0x01;

/**
 * 暗号スイート識別子。
 * 0x01 = X25519+ML-KEM-768 / ChaCha20-Poly1305 / HKDF-SHA256
 * 将来 ML-KEM のアップグレードや AEAD 変更時に新 ID を割り当てる。
 */
const ALG_ID = 0x01;

/** ヘッダー全体サイズ (Magic 4 + Version 1 + AlgId 1 + Reserved 42) */
const HEADER_LEN = 48;

/** X25519 公開鍵の長さ (RFC 7748) */
const X25519_PK_LEN = 32;

/** ML-KEM-768 暗号文の長さ (NIST FIPS 203 Table 2) */
const MLKEM_CT_LEN = 1088;

/**
 * ChaCha20-Poly1305 の nonce 長 (RFC 8439)。
 * 96bit ランダム生成。同一鍵での衝突は構造上発生しない
 * (file_key はファイルごとにエフェメラル鍵から導出されユニークになる)。
 */
const NONCE_LEN = 12;

/** 対称鍵長 (ChaCha20: 256bit / HKDF 出力長) */
const KEY_LEN = 32;

/** Poly1305 認証タグ長 (RFC 8439) */
const POLY1305_TAG_LEN = 16;

/**
 * HKDF info パラメータ。
 *
 * 必ずプロジェクト名前空間 + 用途 + バージョン番号を含む形で命名し、
 * 将来鍵階層を再設計する際は /v2 等で世代を分ける (docs/crypto-spec.md §3.1)。
 */
const HKDF_INFO_HYBRID = 'personal-pqc-drive/hybrid-kex/v1';
const HKDF_INFO_FILE = 'file-key/v1';
const HKDF_INFO_METADATA = 'metadata-key/v1';

// 派生定数
const KEX_BLOCK_LEN = X25519_PK_LEN + MLKEM_CT_LEN; // 1120
const META_LEN_FIELD_LEN = 4;
const MIN_PACKED_LEN =
  HEADER_LEN + KEX_BLOCK_LEN + META_LEN_FIELD_LEN +
  NONCE_LEN + POLY1305_TAG_LEN +  // 空メタデータ最小ケース
  NONCE_LEN + POLY1305_TAG_LEN;   // 空本体最小ケース

// =============================================================================
// 内部ユーティリティ
// =============================================================================

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

/** 複数の Uint8Array を 1 つに結合する */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/**
 * 定数時間で 2 つの Uint8Array を比較する。
 * マジックバイト等の公開値比較ではタイミング攻撃の心配は本来不要だが、
 * 暗号モジュールの慣習として定数時間比較を採用する (防御的プログラミング)。
 */
function bytesEqualConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** バイト列を hex 文字列に変換 (エラーメッセージ用) */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** HKDF-SHA256 のラッパ。info を UTF-8 でエンコードして呼び出す */
function deriveKey(ikm: Uint8Array, info: string, length: number): Uint8Array {
  return hkdf(sha256, ikm, undefined, utf8Encoder.encode(info), length);
}

// =============================================================================
// 公開 API
// =============================================================================

/**
 * 受信者の永続鍵ペアを生成する。
 *
 * 「永続」とは初回セットアップ時に一度生成し、その後 IndexedDB 等に保管して
 * 長期間使い続けることを意味する。送信者はこの公開鍵で暗号化するため、
 * 受信者は同じ鍵ペアを保持し続ける必要がある。
 *
 * X25519 と ML-KEM-768 の両方を生成するのは、片方の鍵交換が将来破られた場合でも
 * もう片方で守られる「ハイブリッド KEM」を実現するため。詳細: docs/crypto-spec.md §2.1
 *
 * @returns 公開鍵と秘密鍵をそれぞれ `pub`/`sec` にまとめた構造体
 */
export function generateReceiverKeyPair(): ReceiverKeyPair {
  const x_sk = x25519.utils.randomPrivateKey();
  const x_pk = x25519.getPublicKey(x_sk);
  const { publicKey: m_pk, secretKey: m_sk } = ml_kem768.keygen();
  return {
    pub: { x_pk, m_pk },
    sec: { x_sk, m_sk },
  };
}

/**
 * 受信者の公開鍵を使ってファイルを暗号化する。
 *
 * 内部処理 (docs/crypto-spec.md §4.2):
 *   1. エフェメラル X25519 鍵ペアを生成 (毎回新規 → Forward Secrecy)
 *   2. 古典側 ECDH と ML-KEM カプセル化
 *   3. HKDF-SHA256 でハイブリッド共有秘密を導出
 *   4. ファイル鍵 / メタデータ鍵を派生 (ドメイン分離)
 *   5. メタデータと本体をそれぞれ ChaCha20-Poly1305 で暗号化
 *   6. バイナリフォーマット (docs/crypto-spec.md §5) にパック
 *
 * エフェメラル秘密鍵と派生鍵は関数終了時にスコープから外れるが、
 * JavaScript の GC タイミングは保証されない点に注意。
 *
 * @param pub - 受信者の公開鍵 (別経路で受け取ったもの)
 * @param plaintext - 暗号化対象のバイナリ
 * @param metadata - ファイル属性 (元ファイル名、MIME、サイズ、送信時刻)
 * @returns パック済みバイナリ
 */
export function encryptForRecipient(
  pub: ReceiverPublicKeys,
  plaintext: Uint8Array,
  metadata: FileMetadata,
): Uint8Array {
  // 1. エフェメラル X25519 鍵ペア生成
  const eph_sk = x25519.utils.randomPrivateKey();
  const eph_pk = x25519.getPublicKey(eph_sk);

  // 2. 古典側 ECDH と ML-KEM-768 カプセル化
  const ss_classical = x25519.getSharedSecret(eph_sk, pub.x_pk);
  const { cipherText: mkem_ct, sharedSecret: ss_pqc } = ml_kem768.encapsulate(pub.m_pk);

  // 3. ハイブリッド共有秘密の導出
  const ikm = concat(ss_classical, ss_pqc);
  const shared = deriveKey(ikm, HKDF_INFO_HYBRID, KEY_LEN);

  // 4. データ鍵を派生 (ドメイン分離)
  const file_key = deriveKey(shared, HKDF_INFO_FILE, KEY_LEN);
  const metadata_key = deriveKey(shared, HKDF_INFO_METADATA, KEY_LEN);

  // 5. メタデータ暗号化 (ChaCha20-Poly1305)
  const meta_json = utf8Encoder.encode(JSON.stringify(metadata));
  const meta_nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const meta_ct = chacha20poly1305(metadata_key, meta_nonce).encrypt(meta_json);

  // 6. ファイル本体暗号化 (ChaCha20-Poly1305)
  const body_nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const body_ct = chacha20poly1305(file_key, body_nonce).encrypt(plaintext);

  // 7. バイナリフォーマットへパック
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = ALG_ID;
  // header[6..47] は Reserved (0 埋め、将来のフォーマット拡張に使う)

  const meta_block_len = NONCE_LEN + meta_ct.length;
  const meta_len_buf = new Uint8Array(META_LEN_FIELD_LEN);
  new DataView(meta_len_buf.buffer).setUint32(0, meta_block_len, false); // big-endian

  return concat(
    header,
    eph_pk, mkem_ct,
    meta_len_buf, meta_nonce, meta_ct,
    body_nonce, body_ct,
  );
}

/**
 * 受信者の秘密鍵を使ってパック済みバイナリを復号する。
 *
 * 検証経路:
 *   - ヘッダーのマジックバイト / バージョン / アルゴリズム ID
 *   - メタデータブロックの長さフィールドの妥当性
 *   - 2 つの ChaCha20-Poly1305 タグ (メタデータと本体)
 *
 * ML-KEM-768 は不正な暗号文に対しても implicit rejection で例外を出さず
 * 疑似ランダムな共有秘密を返すため (FIPS 203 §6.3)、ML-KEM 部分の改ざんは
 * 最終的に AEAD タグ検証段階で検出される (docs/crypto-spec.md §4.4)。
 *
 * @param packed - パック済みバイナリ
 * @param sec - 受信者の秘密鍵
 * @returns 復号された平文とメタデータ
 * @throws {CryptoError} 不正なフォーマット、または改ざん検出時
 */
export function decryptAsRecipient(
  packed: Uint8Array,
  sec: ReceiverSecretKeys,
): DecryptResult {
  // パッケージ最小長の事前チェック
  if (packed.length < MIN_PACKED_LEN) {
    throw new CryptoError(
      `パッケージが短すぎます (${packed.length} < ${MIN_PACKED_LEN} bytes)`,
      'PACKAGE_TOO_SHORT',
    );
  }

  let off = 0;

  // (1) ヘッダー検証
  const magicBytes = packed.subarray(off, off + 4);
  if (!bytesEqualConstantTime(magicBytes, MAGIC)) {
    throw new CryptoError(
      `不正なマジックバイト: ${bytesToHex(magicBytes)}`,
      'INVALID_MAGIC',
    );
  }
  off += 4;

  const version = packed[off++];
  const algorithmId = packed[off++];
  off += 42; // Reserved 領域はスキップ (受信側は内容を検証しない)

  if (version !== VERSION) {
    throw new CryptoError(
      `未対応バージョン: 0x${version.toString(16).padStart(2, '0')} ` +
        `(このビルドは 0x${VERSION.toString(16).padStart(2, '0')} のみ対応)`,
      'UNSUPPORTED_VERSION',
    );
  }
  if (algorithmId !== ALG_ID) {
    throw new CryptoError(
      `未対応アルゴリズムID: 0x${algorithmId.toString(16).padStart(2, '0')}`,
      'UNSUPPORTED_ALGORITHM',
    );
  }

  // (2) 鍵交換ブロックを抽出
  const eph_pk = packed.subarray(off, off + X25519_PK_LEN);
  off += X25519_PK_LEN;
  const mkem_ct = packed.subarray(off, off + MLKEM_CT_LEN);
  off += MLKEM_CT_LEN;

  // (3) 共有秘密を復元
  const ss_classical = x25519.getSharedSecret(sec.x_sk, eph_pk);
  const ss_pqc = ml_kem768.decapsulate(mkem_ct, sec.m_sk);
  const ikm = concat(ss_classical, ss_pqc);
  const shared = deriveKey(ikm, HKDF_INFO_HYBRID, KEY_LEN);
  const file_key = deriveKey(shared, HKDF_INFO_FILE, KEY_LEN);
  const metadata_key = deriveKey(shared, HKDF_INFO_METADATA, KEY_LEN);

  // (4) メタデータブロックを抽出
  const meta_block_len = new DataView(
    packed.buffer,
    packed.byteOffset + off,
    META_LEN_FIELD_LEN,
  ).getUint32(0, false);
  off += META_LEN_FIELD_LEN;

  // メタデータブロック長の妥当性チェック
  // (nonce 12B + 最低でも認証タグ 16B が含まれるため 28B 未満は不正)
  const meta_ct_len = meta_block_len - NONCE_LEN;
  if (meta_block_len < NONCE_LEN + POLY1305_TAG_LEN ||
      off + meta_block_len + NONCE_LEN + POLY1305_TAG_LEN > packed.length) {
    throw new CryptoError(
      `メタデータブロック長が不正: ${meta_block_len}`,
      'INVALID_METADATA_BLOCK_LENGTH',
    );
  }

  const meta_nonce = packed.subarray(off, off + NONCE_LEN);
  off += NONCE_LEN;
  const meta_ct = packed.subarray(off, off + meta_ct_len);
  off += meta_ct_len;

  // (5) メタデータ復号 (Poly1305 タグ検証含む)
  let meta_pt: Uint8Array;
  try {
    meta_pt = chacha20poly1305(metadata_key, meta_nonce).decrypt(meta_ct);
  } catch (e) {
    throw new CryptoError(
      'メタデータ復号失敗 (鍵不一致または改ざんの可能性)',
      'METADATA_DECRYPT_FAILED',
      { cause: e },
    );
  }

  let metadata: FileMetadata;
  try {
    metadata = JSON.parse(utf8Decoder.decode(meta_pt)) as FileMetadata;
  } catch (e) {
    throw new CryptoError(
      'メタデータ JSON のパース失敗',
      'INVALID_METADATA_JSON',
      { cause: e },
    );
  }

  // (6) ファイル本体復号
  const body_nonce = packed.subarray(off, off + NONCE_LEN);
  off += NONCE_LEN;
  const body_ct = packed.subarray(off);

  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(file_key, body_nonce).decrypt(body_ct);
  } catch (e) {
    throw new CryptoError(
      'ファイル本体の復号失敗 (鍵不一致または改ざんの可能性)',
      'BODY_DECRYPT_FAILED',
      { cause: e },
    );
  }

  return { metadata, plaintext };
}

// =============================================================================
// 定数の再公開 (UI 側でフォーマット情報が必要なケース用)
// =============================================================================

/**
 * 暗号フォーマットの定数群。読み取り専用。
 * UI 側でヘッダー検査やプログレス表示の閾値計算に使う想定。
 */
export const CRYPTO_CONSTANTS = Object.freeze({
  MAGIC,
  VERSION,
  ALG_ID,
  HEADER_LEN,
  X25519_PK_LEN,
  MLKEM_CT_LEN,
  KEX_BLOCK_LEN,
  NONCE_LEN,
  KEY_LEN,
  POLY1305_TAG_LEN,
  MIN_PACKED_LEN,
  HKDF_INFO_HYBRID,
  HKDF_INFO_FILE,
  HKDF_INFO_METADATA,
} as const);
