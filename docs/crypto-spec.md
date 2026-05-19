# 暗号化仕様 (Crypto Specification)

Personal PQC Drive におけるエンドツーエンド暗号化の詳細仕様。
フェーズ1のプロトタイプ (`prototype.html`) で実証された内容に基づく。

## 1. スコープと目的

本ドキュメントは、Personal PQC Drive がファイル転送時に使用する暗号アルゴリズム、鍵階層、バイナリフォーマット、および各設計判断の根拠を定義する。

- **対象**: ブラウザ内で完結する暗号化処理 (受信者の鍵生成、送信者の暗号化、受信者の復号)
- **対象外**: 鍵の永続化方式 (IndexedDB スキーマ等) は `architecture.md` を参照。脅威モデルは `threat-model.md` を参照
- **アルゴリズム識別子**: 本仕様は `Algorithm ID = 0x01` に対応する。将来別スイートを追加する場合は新たな ID を割り当てる

## 2. 暗号スイート

| 用途 | アルゴリズム | パラメータ |
|---|---|---|
| 古典 KEM | X25519 ECDH | RFC 7748 |
| ポスト量子 KEM | ML-KEM-768 | NIST FIPS 203, セキュリティ Level 3 |
| KDF | HKDF | RFC 5869, ハッシュ SHA-256 |
| AEAD | ChaCha20-Poly1305 | RFC 8439, 鍵 256bit / nonce 96bit / タグ 128bit |

### 2.1 ハイブリッド KEM を採用する理由

ML-KEM 単独ではなく X25519 と組み合わせる。

- **PQC 単独運用の危険**: ML-KEM は標準化されて日が浅く、将来未発見の暗号解析が出る可能性を排除できない
- **古典 KEM 単独の危険**: 量子コンピュータによる Shor のアルゴリズムで X25519 は破られる。記録された通信は将来復号される可能性がある (HNDL: Harvest Now, Decrypt Later)
- **ハイブリッドの安全性**: 共有秘密を `HKDF(ss_classical || ss_pqc)` で導出するため、**両方の KEM が同時に破られない限り** 鍵は安全。これは TLS 1.3 ハイブリッドモードや Google/Cloudflare/Apple が採用する業界標準アプローチと同じ

### 2.2 ML-KEM-768 を選ぶ理由 (Level 1/5 ではなく)

| スイート | セキュリティ | 公開鍵 | 暗号文 | 速度 |
|---|---|---|---|---|
| ML-KEM-512 (Level 1) | AES-128 相当 | 800B | 768B | 最速 |
| **ML-KEM-768 (Level 3)** | **AES-192 相当** | **1184B** | **1088B** | **中** |
| ML-KEM-1024 (Level 5) | AES-256 相当 | 1568B | 1568B | 最遅 |

Level 3 を選択する根拠:

- **NIST 推奨水準**: NIST は Level 3 を「将来 30 年程度の用途で十分」と評価
- **業界標準との整合**: Cloudflare の `X25519MLKEM768`, Chrome の TLS PQ デプロイも Level 3 を採用
- **オーバーヘッドが許容範囲**: 1088B の暗号文は数百MBのファイルに対して無視できる比率 (フェーズ1検証で 100MB に対し 0.001%)
- **Level 5 を選ばない理由**: ChaCha20 の鍵が 256bit なので、KEM だけ Level 5 にしても全体強度は AEAD で頭打ち。サイズと速度の純粋なロスになる

### 2.3 ChaCha20-Poly1305 を選ぶ理由

AES-256-GCM ではなく ChaCha20-Poly1305 を採用。

- **ソフトウェア性能**: AES-NI が使えない環境 (古いCPU、wasm 等) でも一定の速度。ブラウザ JS 実装でも `@noble/ciphers` で 100 MB/s 超を確認 (フェーズ1)
- **nonce 衝突耐性が高い**: GCM は同一鍵+同一 nonce で破滅的に壊れる (機密性喪失+認証鍵漏洩) が、ChaCha20-Poly1305 は同様に壊れるものの、Poly1305 の構造上 GCM ほどカタストロフィックではない (とはいえ衝突は避ける設計が前提)
- **量子耐性**: 対称鍵 256bit に対して Grover アルゴリズムでの実効強度は 128bit。AES-256 と同等
- **将来の WebCrypto 標準化**: ChaCha20-Poly1305 は WebCrypto への組み込みが議論されており、純JS実装からネイティブに置換しやすい

### 2.4 HKDF-SHA256 を選ぶ理由

- **RFC 5869 の標準 KDF**: 「extract-then-expand」モデルが理論的にも実装的にも枯れている
- **ドメイン分離**: `info` パラメータで同じ shared_secret から複数の独立した鍵を派生可。本仕様では `file-key/v1` と `metadata-key/v1` を分離
- **SHA-256 で十分**: 32B 出力を最大3つ程度しか派生しないため、SHA-512 の余裕は不要。SHA-256 のほうがブラウザ実装が速い

## 3. 鍵階層

```
受信者の永続鍵ペア (IndexedDB に保管)
├── X25519 鍵ペア: (x_pk, x_sk)
└── ML-KEM-768 鍵ペア: (m_pk, m_sk)

送信ごとに新規生成 (ファイル送信後は破棄)
└── エフェメラル X25519 鍵ペア: (eph_pk, eph_sk)

ハイブリッド共有秘密の導出 (32 bytes)
shared_secret = HKDF-SHA256(
    IKM  = ss_classical || ss_pqc,
    salt = (省略 = 全 0)
    info = "personal-pqc-drive/hybrid-kex/v1",
    L    = 32
)
    ss_classical = X25519(eph_sk, x_pk)     // 送信側
                 = X25519(x_sk, eph_pk)     // 受信側
    ss_pqc       = ML-KEM-768.Encap(m_pk).sharedSecret      // 送信側
                 = ML-KEM-768.Decap(ct, m_sk)               // 受信側

データ暗号化鍵 (各 32 bytes)
file_key     = HKDF-SHA256(IKM=shared_secret, info="file-key/v1",     L=32)
metadata_key = HKDF-SHA256(IKM=shared_secret, info="metadata-key/v1", L=32)
```

### 3.1 HKDF info の設計方針

`info` 文字列は **必ずプロジェクト名前空間 + 用途 + バージョン番号** を含む:

| info 文字列 | 用途 |
|---|---|
| `personal-pqc-drive/hybrid-kex/v1` | ハイブリッド共有秘密の導出 |
| `file-key/v1` | ファイル本体の暗号化鍵 |
| `metadata-key/v1` | メタデータ JSON の暗号化鍵 |

将来 KDF を変更したり鍵階層を再設計する際は `/v2` 等で世代を分け、`Algorithm ID` の更新と同期させる。

### 3.2 なぜ file_key と metadata_key を分離するか

機能的には 1 つの鍵で足りるが、分離することで以下を達成する:

- **ドメイン分離の徹底**: メタデータと本体の暗号文を取り違える実装ミスを「鍵が違うのでタグ検証失敗する」として早期に発見できる
- **将来の機能拡張余地**: 例えば「メタデータだけ別経路で再暗号化して保管する」「メタデータだけサーバー側で検索インデックス化する (仮)」といった拡張で鍵を分けたくなる可能性がある

## 4. プロトコル仕様

### 4.1 受信者の初期セットアップ (鍵ペア生成)

```
受信者:
    (x_sk, x_pk) ← X25519.GenerateKeyPair()
    (m_pk, m_sk) ← ML-KEM-768.KeyGen()
    IndexedDB に (x_sk, x_pk, m_pk, m_sk) を保存
    (x_pk, m_pk) を別経路で送信者に共有
```

公開鍵の表現は `architecture.md` で別途規定 (JSON エクスポート形式)。

### 4.2 送信者の暗号化

入力: 受信者公開鍵 `(x_pk, m_pk)`、平文 `plaintext`、メタデータ `metadata` (JSON シリアライズ可能なオブジェクト)

```
送信者:
  1. エフェメラル鍵ペア生成
     (eph_sk, eph_pk) ← X25519.GenerateKeyPair()

  2. 古典側 ECDH
     ss_classical ← X25519(eph_sk, x_pk)

  3. ML-KEM カプセル化
     (ss_pqc, mkem_ct) ← ML-KEM-768.Encap(m_pk)

  4. ハイブリッド共有秘密
     shared ← HKDF-SHA256(ss_classical || ss_pqc, info="personal-pqc-drive/hybrid-kex/v1", 32)

  5. データ暗号化鍵を派生
     file_key     ← HKDF-SHA256(shared, info="file-key/v1",     32)
     metadata_key ← HKDF-SHA256(shared, info="metadata-key/v1", 32)

  6. メタデータ暗号化 (Encrypted Metadata Block 用)
     meta_nonce ← RANDOM(12)
     meta_ct    ← ChaCha20-Poly1305(metadata_key, meta_nonce, UTF8(JSON(metadata)))

  7. ファイル本体暗号化 (Encrypted File Body 用)
     body_nonce ← RANDOM(12)
     body_ct    ← ChaCha20-Poly1305(file_key, body_nonce, plaintext)

  8. バイナリフォーマットへパック (§5 参照)

  9. eph_sk, ss_classical, ss_pqc, shared, file_key, metadata_key をメモリ上で破棄
```

エフェメラル鍵が毎回新規生成されることで Forward Secrecy が確保される (将来送信者環境が侵害されても過去送信は復号できない)。

### 4.3 受信者の復号

入力: パックされたバイナリ `packed`、受信者秘密鍵 `(x_sk, m_sk)`

```
受信者:
  1. ヘッダー検証
     Magic == "PPQD" を確認 (違えば即エラー)
     Version == 0x01 を確認
     Algorithm ID == 0x01 を確認

  2. 鍵交換ブロックを抽出
     eph_pk  ← packed[48 .. 80]    // 32 bytes
     mkem_ct ← packed[80 .. 1168]  // 1088 bytes

  3. 共有秘密の復元
     ss_classical ← X25519(x_sk, eph_pk)
     ss_pqc       ← ML-KEM-768.Decap(mkem_ct, m_sk)
     shared       ← HKDF-SHA256(ss_classical || ss_pqc, info="personal-pqc-drive/hybrid-kex/v1", 32)
     file_key     ← HKDF-SHA256(shared, info="file-key/v1",     32)
     metadata_key ← HKDF-SHA256(shared, info="metadata-key/v1", 32)

  4. メタデータ復号
     meta_len   ← read_uint32_be(packed[1168 .. 1172])
     meta_nonce ← packed[1172 .. 1184]
     meta_ct    ← packed[1184 .. 1184 + (meta_len - 12)]
     meta_pt    ← ChaCha20-Poly1305.Decrypt(metadata_key, meta_nonce, meta_ct)
                  // Poly1305 タグ検証失敗時はここで例外
     metadata   ← JSON.parse(UTF8.decode(meta_pt))

  5. ファイル本体復号
     body_nonce ← packed[meta_end .. meta_end+12]
     body_ct    ← packed[meta_end+12 .. end]
     plaintext  ← ChaCha20-Poly1305.Decrypt(file_key, body_nonce, body_ct)
                  // Poly1305 タグ検証失敗時はここで例外
```

### 4.4 ML-KEM の Implicit Rejection に関する注意

ML-KEM-768 の `Decap` は**不正な暗号文に対しても例外を throw せず**、決定的に派生される疑似ランダムな共有秘密を返す (FIPS 203 §6.3, "implicit rejection")。

このため改ざんされた `mkem_ct` を受信した場合:

1. `Decap` は壊れた `ss_pqc` を返す (例外なし)
2. HKDF で誤った `file_key` / `metadata_key` が派生される
3. **AEAD タグ検証で失敗する**

つまり ML-KEM 部分の改ざんは「AEAD 段階で検出される」点が、X25519 部分や本体改ざんと同じ経路で表面化する。フェーズ1の検証ではこれが実際に確認できた (すべて `invalid tag` で失敗)。

## 5. バイナリフォーマット

暗号化ファイルは以下の連結バイト列。**全フィールド ネットワークバイトオーダ (big-endian)**。

```
┌─────────────────────────────────────────────────────────────────┐
│                          Header (48 bytes)                       │
├──────────┬─────────┬───────────────┬─────────────────────────────┤
│ Magic    │ Version │ Algorithm ID  │ Reserved (42 bytes, all 0)  │
│ 4 bytes  │ 1 byte  │ 1 byte        │                             │
│ "PPQD"   │ 0x01    │ 0x01          │ 00 00 ... 00                │
└──────────┴─────────┴───────────────┴─────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                    Key Exchange Block (1120 bytes)               │
├─────────────────────────────┬───────────────────────────────────┤
│ Ephemeral X25519 PublicKey  │ ML-KEM-768 Ciphertext             │
│ 32 bytes                    │ 1088 bytes                        │
└─────────────────────────────┴───────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│              Encrypted Metadata Block (16 + N bytes)             │
├──────────────┬───────────────┬──────────────────────────────────┤
│ MetaLen      │ Meta Nonce    │ Meta Ciphertext + Poly1305 Tag   │
│ 4 bytes (BE) │ 12 bytes      │ N bytes (= MetaLen - 12)         │
│ = 12 + N     │               │                                  │
└──────────────┴───────────────┴──────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│              Encrypted File Body (12 + M bytes)                  │
├───────────────┬─────────────────────────────────────────────────┤
│ Body Nonce    │ Body Ciphertext + Poly1305 Tag                  │
│ 12 bytes      │ M bytes (= 平文長 + 16)                          │
└───────────────┴─────────────────────────────────────────────────┘
```

### 5.1 フィールド詳細

| フィールド | サイズ | 値 | 説明 |
|---|---|---|---|
| Magic | 4B | `0x50 0x50 0x51 0x44` | ASCII "PPQD"、ファイル種別の自己記述 |
| Version | 1B | `0x01` | フォーマットバージョン。プロトコル変更時にインクリメント |
| Algorithm ID | 1B | `0x01` | スイート識別子。`0x01` = X25519+ML-KEM-768 / ChaCha20-Poly1305 / HKDF-SHA256 |
| Reserved | 42B | `0x00` × 42 | 将来拡張用。受信側は内容を検証しない |
| Eph X25519 PK | 32B | random | エフェメラル X25519 公開鍵 (RFC 7748 形式) |
| ML-KEM Ciphertext | 1088B | random | ML-KEM-768.Encap の出力暗号文 |
| MetaLen | 4B BE | uint32 | Meta Nonce + Meta Ct+Tag の合計長 (= 12 + N) |
| Meta Nonce | 12B | random | メタデータ用 ChaCha20-Poly1305 nonce |
| Meta Ct+Tag | NB | - | 暗号化メタデータ + 末尾 16B の Poly1305 タグ |
| Body Nonce | 12B | random | 本体用 ChaCha20-Poly1305 nonce |
| Body Ct+Tag | MB | - | 暗号化本体 + 末尾 16B の Poly1305 タグ |

### 5.2 サイズ計算

固定オーバーヘッド = `48 (header) + 32 (eph_pk) + 1088 (mkem_ct) + 4 (meta_len) + 12 (meta_nonce) + 16 (meta_tag) + 12 (body_nonce) + 16 (body_tag) = 1228 bytes` + メタデータ JSON のサイズ。

フェーズ1検証では 391,943B の PNG に対し packed が 393,257B、オーバーヘッドは 1,314B (うちメタデータJSONが約86B)。

### 5.3 ヘッダーにバージョンとアルゴリズム ID を持たせる理由

将来の暗号アジリティのため。例えば:

- ML-KEM-768 に重大な脆弱性が出た場合 → `Algorithm ID = 0x02` で ML-KEM-1024 や HQC に切替
- AEAD 仕様を AES-256-GCM-SIV に変える場合 → 別の Algorithm ID を割当

受信側は `Algorithm ID` を見て対応スイートで復号処理を分岐する。Reserved 領域 42B は今後のフォーマット拡張用 (例: チャンク分割のヒント、有効期限の埋め込み等)。

## 6. nonce 管理

- **12 byte ランダム生成** (`crypto.getRandomValues`)
- **ファイルごとに新規生成**、メタデータ用と本体用で独立した nonce
- **同一鍵での nonce 衝突を許容しない**: 同じ `file_key` は同じ shared_secret から派生し、shared_secret はエフェメラル鍵+受信者公開鍵で決まるため、ファイルごとに必ず異なる。よって nonce 衝突のリスクは構造的に存在しない (鍵そのものが毎回ユニーク)
- **96bit ランダムの安全性**: 同一鍵で 2^48 メッセージ送るまで衝突確率 2^-32 (RFC 8439 §4 の議論)。本仕様では同一鍵を1回しか使わないので問題にならない

### 6.1 巨大ファイルのチャンク分割について (将来検討)

ChaCha20-Poly1305 の 1 nonce あたりの暗号化上限は 256GiB (2^32 × 64B ブロック)。これを超える場合や、ストリーミング復号が必要な場合はチャンク分割を導入する。

その際は:

- 各チャンクに連番カウンタを nonce に組み込む (`nonce[8..12] = counter_be`)
- 最終チャンクに「これが最後」フラグを AAD に入れて末尾削除攻撃を防ぐ
- 別の Algorithm ID を割当

現フェーズでは単一 nonce / 一括暗号化に留め、上限は本体長 256GiB。実用上 (数百MB想定) は何の制約にもならない。

## 7. 検証済みのセキュリティ性質

フェーズ1のプロトタイプ (`prototype.html`) で以下を実証済み:

1. **正常往復**: 受信者鍵で暗号化→復号がバイト単位で完全一致 (テキスト・PNG・最大100MBランダム)
2. **改ざん検出 (5領域)**: ヘッダー / eph_pk / mkem_ct / メタデータ暗号文 / 本体暗号文 のいずれを 1 byte でも書き換えると復号失敗
   - ヘッダー改ざんはマジックバイト検証で即時失敗
   - 他はすべて ChaCha20-Poly1305 の `invalid tag` で失敗
3. **不正鍵での復号失敗 (3パターン)**: X25519 のみ別人 / ML-KEM のみ別人 / 両方別人 — どのケースも復号不可。**ハイブリッドの両側が一致して初めて復号できる**ことを実証 (これがハイブリッド KEM の設計意図そのもの)

## 8. 性能特性 (フェーズ1実測値)

純JS実装 (`@noble/*` 系) によるブラウザ性能。Chrome 最新版 + デスクトップ環境。

| サイズ | 暗号化 (ms) | 復号 (ms) | 暗号化スループット | 復号スループット |
|---|---|---|---|---|
| 1MB | 34.6 | 13.2 | 28.9 MB/s | 75.8 MB/s |
| 10MB | 100.8 | 98.0 | 99.2 MB/s | 102.0 MB/s |
| 50MB | 488.8 | 472.9 | 102.3 MB/s | 105.7 MB/s |
| 100MB | 983.7 | 929.0 | 101.7 MB/s | 107.6 MB/s |

観察:

- 定常状態で約 100 MB/s。これは純JS ChaCha20-Poly1305 の典型値
- 1MB のみスループットが低いのは JIT ウォームアップ
- 暗号化が復号より僅かに遅いのは、送信側で packed バッファを構築する `concat` のメモリコピーコスト。受信側は subarray ビューで参照するためコピー不要
- 将来 WebCrypto が ChaCha20-Poly1305 を標準化すればネイティブ実装で 5-10 倍速くなる見込み

## 9. 範囲外 (この仕様で扱わないもの)

`threat-model.md` で詳細を扱うが、暗号仕様としては以下を保証しない:

- **メタデータの可視性**: 平文ファイル名や MIME type はメタデータブロック内で暗号化されるが、暗号文の**長さ**は推測可能 (ファイルサイズの目安が漏れる)。これを隠すにはパディング層が必要 (現フェーズでは未実装)
- **アップロード/ダウンロードのタイミング相関**: サーバーが見える時刻・IPアドレス等から送受信者を推定する攻撃
- **エンドポイント侵害**: ブラウザや OS が侵害された場合の保護は不可
- **量子コンピュータが現実に存在する世界での古典 KEM 部分の安全性**: その時は ML-KEM だけが頼り。ハイブリッドの設計上、ML-KEM が破られない限り通信は守られる

## 10. 参考文献

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
  <https://csrc.nist.gov/pubs/fips/203/final>
- RFC 7748: Elliptic Curves for Security (Curve25519, Curve448)
  <https://datatracker.ietf.org/doc/html/rfc7748>
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
  <https://datatracker.ietf.org/doc/html/rfc8439>
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
  <https://datatracker.ietf.org/doc/html/rfc5869>
- Cloudflare: NIST's first post-quantum standards
  <https://blog.cloudflare.com/nists-first-post-quantum-standards/>
- Google: Hybrid X25519MLKEM768 in Chrome TLS
  <https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html>
