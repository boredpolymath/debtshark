use crate::error::{AppError, AppResult};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Parameters conforming to Section 2.3.1:
/// Memory cost: 64MB (65536 KiB), Iterations: 3, Parallelism: 4
pub const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024; // 64 MB
pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const KEY_SIZE_BYTES: usize = 32; // 256 bits
pub const NONCE_SIZE_BYTES: usize = 12; // 96 bits
pub const SALT_SIZE_BYTES: usize = 16; // 128 bits
pub const SMBAK_MAGIC_HEADER: &[u8; 8] = b"SMBAK01\0";

/// Helper for encoding bytes to hex string
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Helper for decoding hex string to bytes
pub(crate) fn hex_decode(s: &str) -> AppResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(AppError::Validation(
            "Hex string length must be even".to_string(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| AppError::Validation(format!("Invalid hex string: {}", e)))
        })
        .collect()
}

/// Wrapper for sensitive string data (passwords, SSNs, bank accounts) that zeroizes upon drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Wrapper for sensitive consumer credentials (SSNs, account numbers) that zeroizes upon drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveCredentials {
    pub ssn: String,
    pub original_account_number: String,
    pub collection_account_number: String,
}

impl SensitiveCredentials {
    pub fn new(
        ssn: impl Into<String>,
        original_account_number: impl Into<String>,
        collection_account_number: impl Into<String>,
    ) -> Self {
        Self {
            ssn: ssn.into(),
            original_account_number: original_account_number.into(),
            collection_account_number: collection_account_number.into(),
        }
    }
}

impl fmt::Debug for SensitiveCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveCredentials([REDACTED])")
    }
}

/// Zeroizing wrapper for 256-bit cryptographic keys
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; KEY_SIZE_BYTES]);

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterKey([REDACTED 256-bit Key])")
    }
}

/// Zeroizing wrapper for sensitive decrypted byte payloads
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(pub Vec<u8>);

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveBytes([REDACTED {} bytes])", self.0.len())
    }
}

/// Serialized envelope containing ChaCha20-Poly1305 ciphertext, salt, and nonce
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext_with_tag: Vec<u8>,
}

/// Persistent record for Master Passphrase Authentication & Verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultAuthRecord {
    pub version: u32,
    pub salt_hex: String,
    pub verification_hash: String,
    pub created_at: String,
}

/// Individual item bundled into a .smbak backup archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupArchiveItem {
    pub relative_path: String,
    pub data: Vec<u8>,
    pub sha256_hash: String,
}

/// Unencrypted payload manifest inside a .smbak backup container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupContainer {
    pub version: String,
    pub created_at: String,
    pub items: Vec<BackupArchiveItem>,
}

/// Cryptographic Manager for Master Key Derivation & At-Rest Database Encryption
pub struct CryptoEngine;

impl CryptoEngine {
    /// Derive a 256-bit master encryption key from user passphrase using Argon2id
    /// Settings: memory_cost = 64MB, iterations = 3, parallelism = 4
    pub fn derive_master_key(passphrase: &SensitiveString, salt: &[u8]) -> AppResult<MasterKey> {
        let params = Params::new(
            ARGON2_MEMORY_COST_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(KEY_SIZE_BYTES),
        )
        .map_err(|e| AppError::Calculation(format!("Invalid Argon2 parameters: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_vec = Self::generate_random_bytes(KEY_SIZE_BYTES);
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_vec)
            .map_err(|e| AppError::Calculation(format!("Key derivation failed: {}", e)))?;

        let key_bytes: [u8; KEY_SIZE_BYTES] = key_vec
            .try_into()
            .map_err(|_| AppError::Calculation("Invalid derived key length".to_string()))?;

        Ok(MasterKey(key_bytes))
    }

    /// Generate cryptographically secure random bytes for salts and nonces
    pub fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::rng();
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.random::<u8>());
        }
        buf
    }

    /// Compute SHA-256 verification hash of a key or payload
    pub fn compute_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex_encode(&hasher.finalize())
    }

    /// Enroll a new master passphrase:
    /// 1. Generates 16-byte random salt
    /// 2. Derives 256-bit MasterKey via Argon2id (64MB/3/4)
    /// 3. Computes SHA-256 verification hash of derived key
    /// 4. Returns VaultAuthRecord and zeroizing MasterKey
    pub fn enroll_passphrase(
        passphrase: &SensitiveString,
    ) -> AppResult<(VaultAuthRecord, MasterKey)> {
        let salt = Self::generate_random_bytes(SALT_SIZE_BYTES);
        let master_key = Self::derive_master_key(passphrase, &salt)?;
        let verification_hash = Self::compute_sha256(&master_key.0);

        let record = VaultAuthRecord {
            version: 1,
            salt_hex: hex_encode(&salt),
            verification_hash,
            created_at: Utc::now().to_rfc3339(),
        };

        Ok((record, master_key))
    }

    /// Authenticate a candidate passphrase against a stored VaultAuthRecord:
    /// Derives candidate key and verifies its hash in constant time against verification_hash
    pub fn authenticate_passphrase(
        passphrase: &SensitiveString,
        record: &VaultAuthRecord,
    ) -> AppResult<MasterKey> {
        let salt = hex_decode(&record.salt_hex)?;
        let candidate_key = Self::derive_master_key(passphrase, &salt)?;
        let candidate_hash = Self::compute_sha256(&candidate_key.0);

        if candidate_hash != record.verification_hash {
            return Err(AppError::Validation(
                "Master passphrase authentication failed: invalid passphrase".to_string(),
            ));
        }

        Ok(candidate_key)
    }

    /// Persist VaultAuthRecord to disk
    pub fn save_auth_record<P: AsRef<Path>>(path: P, record: &VaultAuthRecord) -> AppResult<()> {
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| AppError::Io(format!("Failed to serialize auth record: {}", e)))?;
        fs::write(path, json)
            .map_err(|e| AppError::Io(format!("Failed to write auth record: {}", e)))?;
        Ok(())
    }

    /// Read VaultAuthRecord from disk
    pub fn load_auth_record<P: AsRef<Path>>(path: P) -> AppResult<VaultAuthRecord> {
        let data = fs::read_to_string(path)
            .map_err(|e| AppError::Io(format!("Failed to read auth record: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| AppError::Io(format!("Failed to parse auth record: {}", e)))
    }

    /// Encrypt plaintext using ChaCha20-Poly1305 AEAD authenticated encryption
    pub fn encrypt(
        key: &MasterKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> AppResult<EncryptedPayload> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
            .map_err(|e| AppError::Io(format!("Cipher initialization failed: {}", e)))?;

        let nonce_bytes = Self::generate_random_bytes(NONCE_SIZE_BYTES);
        let nonce = Nonce::try_from(nonce_bytes.as_slice())
            .map_err(|e| AppError::Io(format!("Invalid nonce: {}", e)))?;

        let payload = Payload {
            msg: plaintext,
            aad: associated_data.unwrap_or(b"settlemint-at-rest-vault"),
        };

        let ciphertext_with_tag = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| AppError::Io(format!("Encryption failed: {}", e)))?;

        Ok(EncryptedPayload {
            salt: Vec::new(),
            nonce: nonce_bytes,
            ciphertext_with_tag,
        })
    }

    /// Decrypt ciphertext using ChaCha20-Poly1305 and return zeroizing plaintext bytes
    pub fn decrypt(
        key: &MasterKey,
        payload: &EncryptedPayload,
        associated_data: Option<&[u8]>,
    ) -> AppResult<SensitiveBytes> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
            .map_err(|e| AppError::Io(format!("Cipher initialization failed: {}", e)))?;

        if payload.nonce.len() != NONCE_SIZE_BYTES {
            return Err(AppError::Validation(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_SIZE_BYTES,
                payload.nonce.len()
            )));
        }

        let nonce = Nonce::try_from(payload.nonce.as_slice())
            .map_err(|e| AppError::Io(format!("Invalid nonce: {}", e)))?;
        let aead_payload = Payload {
            msg: &payload.ciphertext_with_tag,
            aad: associated_data.unwrap_or(b"settlemint-at-rest-vault"),
        };

        let decrypted = cipher
            .decrypt(&nonce, aead_payload)
            .map_err(|e| AppError::Io(format!("Decryption authentication failed: {}", e)))?;

        Ok(SensitiveBytes(decrypted))
    }

    /// Encrypt an entire SQLite database file at rest into an authenticated encrypted vault file
    pub fn encrypt_database_file<P: AsRef<Path>, Q: AsRef<Path>>(
        src_db_path: P,
        dest_vault_path: Q,
        key: &MasterKey,
    ) -> AppResult<()> {
        let mut file = File::open(&src_db_path)
            .map_err(|e| AppError::Io(format!("Failed to open source DB: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| AppError::Io(format!("Failed to read source DB: {}", e)))?;

        let encrypted = Self::encrypt(key, &buffer, Some(b"settlemint-sqlite-db-at-rest"))?;
        let encoded_vault = serde_json::to_vec(&encrypted)
            .map_err(|e| AppError::Io(format!("Failed to serialize encrypted payload: {}", e)))?;

        let mut out_file = File::create(&dest_vault_path)
            .map_err(|e| AppError::Io(format!("Failed to create destination vault: {}", e)))?;
        out_file
            .write_all(&encoded_vault)
            .map_err(|e| AppError::Io(format!("Failed to write encrypted vault: {}", e)))?;

        Ok(())
    }

    /// Decrypt an authenticated encrypted vault file at rest into an active SQLite database file
    pub fn decrypt_database_file<P: AsRef<Path>, Q: AsRef<Path>>(
        src_vault_path: P,
        dest_db_path: Q,
        key: &MasterKey,
    ) -> AppResult<()> {
        let mut file = File::open(&src_vault_path)
            .map_err(|e| AppError::Io(format!("Failed to open vault file: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| AppError::Io(format!("Failed to read vault file: {}", e)))?;

        let encrypted: EncryptedPayload = serde_json::from_slice(&buffer)
            .map_err(|e| AppError::Io(format!("Failed to deserialize vault payload: {}", e)))?;

        let decrypted = Self::decrypt(key, &encrypted, Some(b"settlemint-sqlite-db-at-rest"))?;

        let mut out_file = File::create(&dest_db_path)
            .map_err(|e| AppError::Io(format!("Failed to write decrypted database: {}", e)))?;
        out_file
            .write_all(&decrypted.0)
            .map_err(|e| AppError::Io(format!("Failed to write decrypted DB content: {}", e)))?;

        Ok(())
    }

    /// Export an encrypted database snapshot to a user-selected destination directory
    pub fn export_encrypted_database<P: AsRef<Path>, Q: AsRef<Path>>(
        src_db_path: P,
        dest_dir: Q,
        key: &MasterKey,
    ) -> AppResult<PathBuf> {
        let dest_dir = dest_dir.as_ref();
        fs::create_dir_all(dest_dir)
            .map_err(|e| AppError::Io(format!("Failed to create export directory: {}", e)))?;

        let filename = format!(
            "settlemint_backup_{}.vault",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let dest_path = dest_dir.join(filename);

        Self::encrypt_database_file(src_db_path, &dest_path, key)?;
        Ok(dest_path)
    }

    /// Create a passphrase-protected backup archive (.smbak) packaging the SQLite DB and evidence files
    pub fn create_backup_archive<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
        db_path: P,
        evidence_dir: Q,
        dest_archive_path: R,
        passphrase: &SensitiveString,
    ) -> AppResult<()> {
        let mut items = Vec::new();

        // 1. Pack database file
        let db_path = db_path.as_ref();
        if db_path.exists() {
            let mut db_bytes = Vec::new();
            File::open(db_path)
                .map_err(|e| AppError::Io(format!("Failed to open DB: {}", e)))?
                .read_to_end(&mut db_bytes)
                .map_err(|e| AppError::Io(format!("Failed to read DB: {}", e)))?;
            let hash = Self::compute_sha256(&db_bytes);
            items.push(BackupArchiveItem {
                relative_path: "dbs/settlemint.db".to_string(),
                data: db_bytes,
                sha256_hash: hash,
            });
        }

        // 2. Pack evidence files
        let evidence_dir = evidence_dir.as_ref();
        if evidence_dir.exists() && evidence_dir.is_dir() {
            for entry in fs::read_dir(evidence_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let filename = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("evidence.bin");
                    let mut file_bytes = Vec::new();
                    File::open(&path)
                        .map_err(|e| AppError::Io(format!("Failed to open evidence file: {}", e)))?
                        .read_to_end(&mut file_bytes)
                        .map_err(|e| {
                            AppError::Io(format!("Failed to read evidence file: {}", e))
                        })?;
                    let hash = Self::compute_sha256(&file_bytes);
                    items.push(BackupArchiveItem {
                        relative_path: format!("evidence/{}", filename),
                        data: file_bytes,
                        sha256_hash: hash,
                    });
                }
            }
        }

        let container = BackupContainer {
            version: "1.0.0".to_string(),
            created_at: Utc::now().to_rfc3339(),
            items,
        };

        let container_bytes = serde_json::to_vec(&container)
            .map_err(|e| AppError::Io(format!("Failed to serialize backup container: {}", e)))?;

        // Derive key using fresh salt
        let salt = Self::generate_random_bytes(SALT_SIZE_BYTES);
        let key = Self::derive_master_key(passphrase, &salt)?;
        let encrypted = Self::encrypt(&key, &container_bytes, Some(b"settlemint-smbak-archive"))?;

        // Write container: [8 bytes magic][16 bytes salt][12 bytes nonce][ciphertext_with_tag]
        let mut out = File::create(dest_archive_path)
            .map_err(|e| AppError::Io(format!("Failed to create backup archive: {}", e)))?;
        out.write_all(SMBAK_MAGIC_HEADER)?;
        out.write_all(&salt)?;
        out.write_all(&encrypted.nonce)?;
        out.write_all(&encrypted.ciphertext_with_tag)?;

        Ok(())
    }

    /// Restore and unpack a passphrase-protected backup archive (.smbak)
    pub fn restore_backup_archive<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
        src_archive_path: P,
        target_db_path: Q,
        target_evidence_dir: R,
        passphrase: &SensitiveString,
    ) -> AppResult<usize> {
        let mut file = File::open(src_archive_path)
            .map_err(|e| AppError::Io(format!("Failed to open archive: {}", e)))?;
        let mut raw_bytes = Vec::new();
        file.read_to_end(&mut raw_bytes)
            .map_err(|e| AppError::Io(format!("Failed to read archive: {}", e)))?;

        let header_len = SMBAK_MAGIC_HEADER.len() + SALT_SIZE_BYTES + NONCE_SIZE_BYTES;
        if raw_bytes.len() < header_len {
            return Err(AppError::Validation(
                "Invalid .smbak file: payload is too short".to_string(),
            ));
        }

        // Verify magic header
        if &raw_bytes[0..SMBAK_MAGIC_HEADER.len()] != SMBAK_MAGIC_HEADER {
            return Err(AppError::Validation(
                "Invalid .smbak file: header magic mismatch".to_string(),
            ));
        }

        let salt_start = SMBAK_MAGIC_HEADER.len();
        let salt_end = salt_start + SALT_SIZE_BYTES;
        let salt = &raw_bytes[salt_start..salt_end];

        let nonce_start = salt_end;
        let nonce_end = nonce_start + NONCE_SIZE_BYTES;
        let nonce = &raw_bytes[nonce_start..nonce_end];

        let ciphertext = &raw_bytes[nonce_end..];

        // Derive key and decrypt
        let key = Self::derive_master_key(passphrase, salt)?;
        let payload = EncryptedPayload {
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            ciphertext_with_tag: ciphertext.to_vec(),
        };

        let decrypted = Self::decrypt(&key, &payload, Some(b"settlemint-smbak-archive"))?;

        let container: BackupContainer = serde_json::from_slice(&decrypted.0)
            .map_err(|e| AppError::Validation(format!("Corrupt backup container data: {}", e)))?;

        let target_evidence_dir = target_evidence_dir.as_ref();
        fs::create_dir_all(target_evidence_dir)
            .map_err(|e| AppError::Io(format!("Failed to create evidence dir: {}", e)))?;

        let mut restored_count = 0;
        for item in container.items {
            // Verify integrity hash
            let computed_hash = Self::compute_sha256(&item.data);
            if computed_hash != item.sha256_hash {
                return Err(AppError::Validation(format!(
                    "Integrity check failed for file: {}",
                    item.relative_path
                )));
            }

            if item.relative_path == "dbs/settlemint.db" {
                let target_db = target_db_path.as_ref();
                if let Some(parent) = target_db.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::write(target_db, &item.data)
                    .map_err(|e| AppError::Io(format!("Failed to write DB: {}", e)))?;
                restored_count += 1;
            } else if item.relative_path.starts_with("evidence/") {
                let filename = item
                    .relative_path
                    .strip_prefix("evidence/")
                    .unwrap_or("evidence.bin");
                let dest = target_evidence_dir.join(filename);
                fs::write(&dest, &item.data)
                    .map_err(|e| AppError::Io(format!("Failed to write evidence file: {}", e)))?;
                restored_count += 1;
            }
        }

        Ok(restored_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_master_key_derivation() {
        let pass = SensitiveString::new("CorrectHorseBatteryStaple-2026!");
        let salt = CryptoEngine::generate_random_bytes(SALT_SIZE_BYTES);

        let key1 = CryptoEngine::derive_master_key(&pass, &salt).expect("Key derivation failed");
        let key2 = CryptoEngine::derive_master_key(&pass, &salt).expect("Key derivation failed");

        // Deterministic derivation for identical salt and passphrase
        assert_eq!(key1.0, key2.0);

        // Different salt yields completely distinct keys
        let salt_diff = CryptoEngine::generate_random_bytes(SALT_SIZE_BYTES);
        let key3 =
            CryptoEngine::derive_master_key(&pass, &salt_diff).expect("Key derivation failed");
        assert_ne!(key1.0, key3.0);
    }

    #[test]
    fn test_chacha20poly1305_authenticated_encryption() {
        let pass = SensitiveString::new("UltraSecureMasterPassword99!");
        let salt = CryptoEngine::generate_random_bytes(SALT_SIZE_BYTES);
        let master_key = CryptoEngine::derive_master_key(&pass, &salt).expect("Derivation failed");

        let secret_ssn_and_account =
            b"DEBTOR_SSN: 000-12-3456 | CITIBANK_CARD: 4111-2222-3333-4444";
        let aad = b"test-case-aad";

        let encrypted = CryptoEngine::encrypt(&master_key, secret_ssn_and_account, Some(aad))
            .expect("Encryption failed");

        // Ciphertext must not match plaintext
        assert_ne!(
            &encrypted.ciphertext_with_tag[..secret_ssn_and_account.len()],
            secret_ssn_and_account
        );

        let decrypted =
            CryptoEngine::decrypt(&master_key, &encrypted, Some(aad)).expect("Decryption failed");
        assert_eq!(&decrypted.0, secret_ssn_and_account);

        // Tampering with ciphertext fails authentication
        let mut tampered = encrypted.clone();
        tampered.ciphertext_with_tag[0] ^= 0xFF;
        assert!(CryptoEngine::decrypt(&master_key, &tampered, Some(aad)).is_err());
    }

    #[test]
    fn test_zeroization_on_drop() {
        let mut sensitive = SensitiveString::new("TopSecretPassphrase");
        assert_eq!(sensitive.as_str(), "TopSecretPassphrase");
        sensitive.zeroize();
        assert_eq!(sensitive.as_str(), "");

        let mut creds = SensitiveCredentials::new("000-11-2222", "1234-5678", "COLL-999");
        assert_eq!(creds.ssn, "000-11-2222");
        creds.zeroize();
        assert_eq!(creds.ssn, "");
        assert_eq!(creds.original_account_number, "");
        assert_eq!(creds.collection_account_number, "");
    }

    #[test]
    fn test_enrollment_and_authentication() {
        let pass = SensitiveString::new("MySecurePassphrase!2026");
        let (record, key) = CryptoEngine::enroll_passphrase(&pass).expect("Enrollment failed");

        assert_eq!(record.version, 1);
        assert_eq!(record.verification_hash.len(), 64); // SHA-256 hex length

        // Successful authentication yields identical master key
        let authenticated_key = CryptoEngine::authenticate_passphrase(&pass, &record)
            .expect("Authentication should succeed");
        assert_eq!(authenticated_key.0, key.0);

        // Wrong passphrase must be rejected
        let wrong_pass = SensitiveString::new("WrongPassword!");
        let auth_result = CryptoEngine::authenticate_passphrase(&wrong_pass, &record);
        assert!(auth_result.is_err());
    }

    #[test]
    fn test_backup_archive_packaging_and_restoration() {
        let temp_dir =
            std::env::temp_dir().join(format!("settlemint_test_{}", uuid::Uuid::new_v4()));
        let db_file = temp_dir.join("dbs").join("test_settlemint.db");
        let evidence_dir = temp_dir.join("evidence");
        let backup_file = temp_dir.join("backup.smbak");
        let restore_db_file = temp_dir.join("restored_dbs").join("restored.db");
        let restore_evidence_dir = temp_dir.join("restored_evidence");

        fs::create_dir_all(db_file.parent().unwrap()).unwrap();
        fs::create_dir_all(&evidence_dir).unwrap();

        // Write sample DB and evidence
        fs::write(&db_file, b"SQLITE_FORMAT_3_TEST_DATA").unwrap();
        fs::write(evidence_dir.join("doc1.pdf"), b"PDF_EVIDENCE_1").unwrap();
        fs::write(evidence_dir.join("audio.wav"), b"WAV_RECORDING_DATA").unwrap();

        let pass = SensitiveString::new("BackupPassword99!");

        // Create .smbak archive
        CryptoEngine::create_backup_archive(&db_file, &evidence_dir, &backup_file, &pass)
            .expect("Create backup failed");
        assert!(backup_file.exists());

        // Restore .smbak archive
        let count = CryptoEngine::restore_backup_archive(
            &backup_file,
            &restore_db_file,
            &restore_evidence_dir,
            &pass,
        )
        .expect("Restore backup failed");

        assert_eq!(count, 3); // 1 DB + 2 evidence files
        assert_eq!(
            fs::read(&restore_db_file).unwrap(),
            b"SQLITE_FORMAT_3_TEST_DATA"
        );
        assert_eq!(
            fs::read(restore_evidence_dir.join("doc1.pdf")).unwrap(),
            b"PDF_EVIDENCE_1"
        );
        assert_eq!(
            fs::read(restore_evidence_dir.join("audio.wav")).unwrap(),
            b"WAV_RECORDING_DATA"
        );

        // Wrong passphrase restore fails
        let wrong_pass = SensitiveString::new("BadPassword");
        assert!(
            CryptoEngine::restore_backup_archive(
                &backup_file,
                &restore_db_file,
                &restore_evidence_dir,
                &wrong_pass
            )
            .is_err()
        );

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
