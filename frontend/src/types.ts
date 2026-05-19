/**
 * types.ts - Personal PQC Drive フロントエンドの共有型定義
 *
 * 暗号モジュール (crypto.ts) と UI モジュール (upload.ts / download.ts / setup.ts) が
 * 境界をまたいで受け渡す構造をここに集約する。
 */

// =============================================================================
// 受信者の鍵ペア
// =============================================================================

/**
 * 受信者の永続公開鍵 (送信者と別経路で共有するもの)。
 *
 * - `x_pk`: X25519 公開鍵 (32 bytes, RFC 7748)
 * - `m_pk`: ML-KEM-768 公開鍵 (1184 bytes, NIST FIPS 203)
 *
 * 両者を組み合わせることで「古典暗号 OR ポスト量子暗号の片方が破られても
 * もう片方で守られる」ハイブリッド安全性を実現する (docs/crypto-spec.md §2.1)。
 */
export interface ReceiverPublicKeys {
  x_pk: Uint8Array;
  m_pk: Uint8Array;
}

/**
 * 受信者の永続秘密鍵 (IndexedDB に保管するもの)。
 *
 * - `x_sk`: X25519 秘密鍵 (32 bytes)
 * - `m_sk`: ML-KEM-768 秘密鍵 (2400 bytes)
 *
 * ファイルとしてエクスポートする際はユーザーパスフレーズで暗号化することを
 * 推奨するが、その仕組みは別フェーズで実装する。
 */
export interface ReceiverSecretKeys {
  x_sk: Uint8Array;
  m_sk: Uint8Array;
}

/** 公開鍵と秘密鍵をまとめた構造 */
export interface ReceiverKeyPair {
  pub: ReceiverPublicKeys;
  sec: ReceiverSecretKeys;
}

// =============================================================================
// ファイルメタデータ
// =============================================================================

/**
 * 暗号化メタデータブロックに格納されるファイル属性。
 *
 * - 受信側で復号後、プレビュー方法の決定 (`mime`) や保存ファイル名 (`name`) に使用
 * - AEAD タグで完全性が保証されるため、内容は受信者にとって信頼できる
 * - サーバー側からは暗号化されているため見えない
 */
export interface FileMetadata {
  /** 元ファイル名 (UTF-8、表示およびダウンロード保存名に使用) */
  name: string;
  /** MIME type (例: "image/png" / "text/plain; charset=utf-8") */
  mime: string;
  /** 平文サイズ (bytes) */
  size: number;
  /** 送信時刻 (ISO 8601 形式の文字列) */
  sentAt: string;
}

// =============================================================================
// 復号結果
// =============================================================================

/** decryptAsRecipient の戻り値 */
export interface DecryptResult {
  metadata: FileMetadata;
  plaintext: Uint8Array;
}

// =============================================================================
// エラー型
// =============================================================================

/**
 * 暗号モジュールが throw するエラーの分類コード。
 * UI 側はこの `code` を見てユーザーに表示するメッセージを切り替える。
 *
 * 注: ML-KEM-768 は implicit rejection の性質を持つため、暗号文側の改ざんは
 * `MLKEM_DECAP_FAILED` ではなく `METADATA_DECRYPT_FAILED` (または BODY_…)
 * として現れる (docs/crypto-spec.md §4.4)。
 */
export type CryptoErrorCode =
  | 'INVALID_MAGIC'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_ALGORITHM'
  | 'PACKAGE_TOO_SHORT'
  | 'INVALID_METADATA_BLOCK_LENGTH'
  | 'METADATA_DECRYPT_FAILED'
  | 'INVALID_METADATA_JSON'
  | 'BODY_DECRYPT_FAILED';

/**
 * 暗号モジュール固有のエラー。
 *
 * 元の例外 (Noble ライブラリの "invalid tag" 等) は `cause` プロパティで保持する
 * (ES2022 Error.cause)。これにより UI 側は分類された `code` を使いつつ、
 * デバッグ時は cause チェーンで詳細を辿れる。
 */
export class CryptoError extends Error {
  override readonly name = 'CryptoError';

  constructor(
    message: string,
    public readonly code: CryptoErrorCode,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

// =============================================================================
// 鍵保管 (keystore) のエラー型
// =============================================================================

/**
 * keystore モジュールが throw するエラーの分類コード。
 *
 *  - `NOT_FOUND`:           取得対象の鍵が存在しない (将来の strictGet API 用、現状未使用)
 *  - `STORAGE_FAILED`:      IndexedDB の I/O 失敗 (詳細は cause 参照)
 *  - `STORAGE_UNAVAILABLE`: IndexedDB が使えない (シークレットウィンドウや古いブラウザ等)
 *  - `SCHEMA_MISMATCH`:     保存データの schemaVersion が現実装と非互換
 *  - `EXPORT_INVALID`:      公開鍵の Base64 エクスポート失敗
 */
export type KeystoreErrorCode =
  | 'NOT_FOUND'
  | 'STORAGE_FAILED'
  | 'STORAGE_UNAVAILABLE'
  | 'SCHEMA_MISMATCH'
  | 'EXPORT_INVALID';

/**
 * keystore モジュール固有のエラー。
 *
 * 原因 (IndexedDB の DOMException 等) は ES2022 の Error.cause で保持する。
 * 設計は CryptoError と対称 (UI 側は code で分岐、デバッグ時は cause を辿る)。
 */
export class KeystoreError extends Error {
  override readonly name = 'KeystoreError';

  constructor(
    message: string,
    public readonly code: KeystoreErrorCode,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}
