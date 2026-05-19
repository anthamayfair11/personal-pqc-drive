/**
 * keystore.ts - 受信者の永続鍵ペアを IndexedDB に保管する
 *
 * 関心分離: このモジュールは「鍵の箱」だけを扱い、暗号アルゴリズムには触れない。
 * crypto.ts (鍵の使い方) との依存は ReceiverKeyPair 型を介する一方向のみ。
 *
 * 設計判断:
 *   - 単一受信者前提で固定キー 'default' に 1 鍵ペアのみ保管
 *     (マルチアカウントは本プロジェクトのスコープ外)
 *   - Uint8Array は構造化クローン経由でそのまま保存 (Base64 変換は export 時のみ)
 *   - パスワード保護は本フェーズではスコープ外
 *     (脅威モデル: IndexedDB へのアクセスは明示的に防御対象外)
 *   - 書き込みは tx.oncomplete (= 確定済み) で resolve することで、
 *     await 後の後続操作が確実に新しい状態を見るようにする
 *
 * IndexedDB スキーマ:
 *   DB:     'personal-pqc-drive' (version 1)
 *   Store:  'receiver-keys' (keyPath: 'id')
 *   Record: 固定キー 'default' に StoredKeyPair
 */

import { KeystoreError, type ReceiverKeyPair } from './types.ts';

const DB_NAME = 'personal-pqc-drive';
const DB_VERSION = 1;
const STORE_NAME = 'receiver-keys';
const FIXED_KEY = 'default';
const CURRENT_SCHEMA_VERSION = 1;

/**
 * IndexedDB に永続化するレコード形式 (モジュール内部型)。
 *
 * 外部 export しない理由: 将来 schemaVersion: 2 へ移行する際に、
 * 旧フィールドの互換性維持を keystore.ts 内に閉じ込めるため。
 */
interface StoredKeyPair {
  id: typeof FIXED_KEY;
  x_pk: Uint8Array;
  x_sk: Uint8Array;
  m_pk: Uint8Array;
  m_sk: Uint8Array;
  createdAt: Date;
  schemaVersion: typeof CURRENT_SCHEMA_VERSION;
}

// =============================================================================
// IndexedDB ヘルパ
// =============================================================================

function ensureIndexedDB(): IDBFactory {
  // typeof で safe-guard (Worker / 古いブラウザ / IDB が無効化された環境)
  if (typeof indexedDB === 'undefined') {
    throw new KeystoreError(
      'IndexedDB が利用できない環境です (プライベートウィンドウや古いブラウザの可能性)',
      'STORAGE_UNAVAILABLE',
    );
  }
  return indexedDB;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const factory = ensureIndexedDB();
    const req = factory.open(DB_NAME, DB_VERSION);
    req.onerror = () =>
      reject(
        new KeystoreError(
          `IndexedDB を開けません: ${req.error?.message ?? 'unknown'}`,
          'STORAGE_FAILED',
          req.error ? { cause: req.error } : undefined,
        ),
      );
    req.onblocked = () =>
      reject(
        new KeystoreError(
          'IndexedDB のアップグレードが他タブによりブロックされています',
          'STORAGE_FAILED',
        ),
      );
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

/**
 * 単一の IDBRequest を実行する Promise ラッパ。
 *
 * tx.oncomplete で resolve することで、書き込みトランザクションが確定した
 * 時点で次の操作へ進めるようにする。読み出しでも同じ振る舞い (await 完了 =
 * トランザクション終了) で挙動が一貫する。
 */
function txRequest<T>(
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDB().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, mode);
        const store = tx.objectStore(STORE_NAME);
        const req = fn(store);
        req.onerror = () =>
          reject(
            new KeystoreError(
              `IndexedDB 操作失敗: ${req.error?.message ?? 'unknown'}`,
              'STORAGE_FAILED',
              req.error ? { cause: req.error } : undefined,
            ),
          );
        tx.onerror = () =>
          reject(
            new KeystoreError(
              `IndexedDB トランザクション失敗: ${tx.error?.message ?? 'unknown'}`,
              'STORAGE_FAILED',
              tx.error ? { cause: tx.error } : undefined,
            ),
          );
        tx.oncomplete = () => {
          db.close();
          // req.result は onsuccess 時点で確定し、oncomplete までは IDBRequest が保持する
          resolve(req.result);
        };
        tx.onabort = () => db.close();
      }),
  );
}

/** 内部用: 保存レコードを取得する共通処理 */
function fetchStored(): Promise<StoredKeyPair | undefined> {
  return txRequest<StoredKeyPair | undefined>(
    'readonly',
    (s) => s.get(FIXED_KEY) as IDBRequest<StoredKeyPair | undefined>,
  );
}

// =============================================================================
// Base64 エンコーディング (exportPublicKeys 用)
// =============================================================================

function bytesToBase64(bytes: Uint8Array): string {
  // String.fromCharCode のスタック制限 (引数最大個数) を回避するため 32KB ずつ分割。
  // ML-KEM-768 公開鍵は 1184 B で 1 chunk 内に収まるが、汎用ヘルパとして安全側に倒す。
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// =============================================================================
// 公開 API
// =============================================================================

/**
 * 鍵ペアが保管されているかを判定する。
 * 初回セットアップ画面で「鍵を生成するか / 既存の鍵を使うか」を分岐するのに使う。
 */
export async function hasKeyPair(): Promise<boolean> {
  const count = await txRequest<number>('readonly', (s) => s.count(FIXED_KEY));
  return count > 0;
}

/**
 * 保管されている鍵ペアを読み出す。
 *
 * @returns 存在しなければ null
 * @throws {KeystoreError} schemaVersion が現実装と非互換 (SCHEMA_MISMATCH)
 */
export async function loadKeyPair(): Promise<ReceiverKeyPair | null> {
  const stored = await fetchStored();
  if (!stored) return null;
  if (stored.schemaVersion !== CURRENT_SCHEMA_VERSION) {
    throw new KeystoreError(
      `保存データのスキーマバージョン不整合: ` +
        `${stored.schemaVersion} (期待: ${CURRENT_SCHEMA_VERSION})`,
      'SCHEMA_MISMATCH',
    );
  }
  return {
    pub: { x_pk: stored.x_pk, m_pk: stored.m_pk },
    sec: { x_sk: stored.x_sk, m_sk: stored.m_sk },
  };
}

/**
 * 鍵ペアを保管する。
 *
 * 既存データは上書きされる (put セマンティクス)。createdAt は保存時に自動付与。
 * 鍵の「リセット → 新規生成 → 保存」のフローでもそのまま使える。
 */
export async function saveKeyPair(kp: ReceiverKeyPair): Promise<void> {
  const entry: StoredKeyPair = {
    id: FIXED_KEY,
    x_pk: kp.pub.x_pk,
    m_pk: kp.pub.m_pk,
    x_sk: kp.sec.x_sk,
    m_sk: kp.sec.m_sk,
    createdAt: new Date(),
    schemaVersion: CURRENT_SCHEMA_VERSION,
  };
  await txRequest('readwrite', (s) => s.put(entry));
}

/**
 * 鍵ペアを削除する。
 * 存在しないケースでも no-op で成功する (IndexedDB の delete 仕様に従う)。
 */
export async function deleteKeyPair(): Promise<void> {
  await txRequest('readwrite', (s) => s.delete(FIXED_KEY));
}

/**
 * 鍵ペアの生成時刻を取得する。
 * UI で「いつ生成された鍵か」を表示する用途を想定。
 *
 * @returns 存在しなければ null
 */
export async function getKeyPairCreatedAt(): Promise<Date | null> {
  const stored = await fetchStored();
  return stored?.createdAt ?? null;
}

/**
 * 受信者の公開鍵を Base64 文字列として書き出す。
 *
 * 送信者に共有するための表現形式 (URL、QR、JSON、メッセージへの貼り付け等)。
 * 秘密鍵は決して export しない (関数名どおり PublicKeys のみ)。
 *
 * @returns 鍵が無ければ null
 * @throws {KeystoreError} Base64 エンコード失敗 (EXPORT_INVALID)
 */
export async function exportPublicKeys(): Promise<{
  x_pk_b64: string;
  m_pk_b64: string;
} | null> {
  const stored = await fetchStored();
  if (!stored) return null;
  try {
    return {
      x_pk_b64: bytesToBase64(stored.x_pk),
      m_pk_b64: bytesToBase64(stored.m_pk),
    };
  } catch (e) {
    throw new KeystoreError(
      '公開鍵の Base64 エンコードに失敗',
      'EXPORT_INVALID',
      { cause: e },
    );
  }
}
