use crate::crypto::hex_encode;
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Standard application directory hierarchy (Section 2.3.2)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxPaths {
    pub base_dir: PathBuf,
    pub database_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub letters_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub temp_dir: PathBuf,
}

impl SandboxPaths {
    /// Initialize and ensure all isolated directory branches exist with secure permissions
    pub fn create_all(&self) -> AppResult<()> {
        fs::create_dir_all(&self.base_dir)
            .map_err(|e| AppError::Io(format!("Failed to create base dir: {}", e)))?;
        fs::create_dir_all(&self.database_dir)
            .map_err(|e| AppError::Io(format!("Failed to create database dir: {}", e)))?;
        fs::create_dir_all(&self.evidence_dir)
            .map_err(|e| AppError::Io(format!("Failed to create evidence dir: {}", e)))?;
        fs::create_dir_all(&self.letters_dir)
            .map_err(|e| AppError::Io(format!("Failed to create letters dir: {}", e)))?;
        fs::create_dir_all(&self.backups_dir)
            .map_err(|e| AppError::Io(format!("Failed to create backups dir: {}", e)))?;
        fs::create_dir_all(&self.temp_dir)
            .map_err(|e| AppError::Io(format!("Failed to create temp dir: {}", e)))?;
        Ok(())
    }

    /// Clean up transient scratch files from the temp directory
    pub fn cleanup_temp(&self) -> AppResult<()> {
        if self.temp_dir.exists() {
            for entry in fs::read_dir(&self.temp_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }

    /// Validates and securely resolves a relative subpath within the sandbox.
    /// Strictly rejects:
    /// - Null byte injection (`\0`)
    /// - Path traversal sequences (`../`, `..\\`)
    /// - Leading directory separators / absolute path escapes
    /// - Symlinks escaping sandbox root
    pub fn resolve_safe_subpath(&self, subpath: &str) -> AppResult<PathBuf> {
        if Path::new(subpath).is_absolute() {
            return Err(AppError::Validation(
                "Sandbox escape violation: absolute path cannot be used as a sandbox subpath"
                    .to_string(),
            ));
        }
        EvidenceVault::validate_sandbox_containment(&self.base_dir, subpath)
    }
}

/// Metadata record for ingested and sandboxed evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestedEvidence {
    pub doc_id: Uuid,
    pub original_filename: String,
    pub vault_filename: String,
    pub relative_vault_path: String,
    pub absolute_path: PathBuf,
    pub sha256_hash: String,
    pub file_size_bytes: u64,
}

/// Integrity audit result representing evidentiary file verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceIntegrityReport {
    pub is_valid: bool,
    pub is_tampered: bool,
    pub expected_hash: String,
    pub actual_hash: String,
    pub file_path: PathBuf,
}

/// Supported evidentiary file types and formats (Section 4.5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupportedFileType {
    Pdf,
    Png,
    Jpeg,
    Wav,
    Mp3,
}

impl SupportedFileType {
    pub fn mime_type(&self) -> &'static str {
        match self {
            SupportedFileType::Pdf => "application/pdf",
            SupportedFileType::Png => "image/png",
            SupportedFileType::Jpeg => "image/jpeg",
            SupportedFileType::Wav => "audio/wav",
            SupportedFileType::Mp3 => "audio/mpeg",
        }
    }

    pub fn default_extension(&self) -> &'static str {
        match self {
            SupportedFileType::Pdf => "pdf",
            SupportedFileType::Png => "png",
            SupportedFileType::Jpeg => "jpg",
            SupportedFileType::Wav => "wav",
            SupportedFileType::Mp3 => "mp3",
        }
    }
}

/// Evidentiary validation descriptor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceValidationInfo {
    pub file_type: SupportedFileType,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256_hash: String,
}

/// Strict validator for evidentiary file MIME types, magic bytes, and sizes
pub struct FileTypeValidator;

impl FileTypeValidator {
    pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50 MB

    /// Rejects executable binary formats (PE, ELF, Mach-O, scripts)
    pub fn is_executable_binary(bytes: &[u8]) -> bool {
        if bytes.len() >= 2 {
            // Windows PE executable ("MZ")
            if bytes[0..2] == [0x4D, 0x5A] {
                return true;
            }
            // Shell script shebang ("#!")
            if &bytes[0..2] == b"#!" {
                return true;
            }
        }
        if bytes.len() >= 4 {
            // Linux ELF ("\x7fELF")
            if bytes[0..4] == [0x7F, 0x45, 0x4C, 0x46] {
                return true;
            }
            // macOS Mach-O headers (32-bit, 64-bit, big-endian, little-endian, Universal Fat)
            let magic4 = &bytes[0..4];
            if magic4 == [0xFE, 0xED, 0xFA, 0xCE]
                || magic4 == [0xFE, 0xED, 0xFA, 0xCF]
                || magic4 == [0xCE, 0xFA, 0xED, 0xFE]
                || magic4 == [0xCF, 0xFA, 0xED, 0xFE]
                || magic4 == [0xCA, 0xFE, 0xBA, 0xBE]
            {
                return true;
            }
        }
        false
    }

    /// Detects file type from magic bytes and cross-checks against file extension
    pub fn detect_and_validate(
        header_bytes: &[u8],
        extension: &str,
    ) -> AppResult<SupportedFileType> {
        // Strict executable check
        if Self::is_executable_binary(header_bytes) {
            return Err(AppError::Validation(
                "Security violation: executable binary detected".to_string(),
            ));
        }

        let clean_ext = extension.trim_start_matches('.').to_lowercase();
        let dangerous_exts = [
            "exe", "dll", "so", "dylib", "bat", "cmd", "ps1", "sh", "vbs", "com", "bin",
        ];
        if dangerous_exts.contains(&clean_ext.as_str()) {
            return Err(AppError::Validation(format!(
                "Security violation: dangerous file extension '.{}' is strictly prohibited",
                clean_ext
            )));
        }

        if header_bytes.len() < 3 {
            return Err(AppError::Validation(
                "File too small to identify valid MIME magic header".to_string(),
            ));
        }

        // PDF magic bytes: "%PDF"
        if header_bytes.len() >= 4 && &header_bytes[0..4] == b"%PDF" {
            if clean_ext == "pdf" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Pdf);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: PDF header detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        // PNG magic bytes: "\x89PNG\r\n\x1a\n"
        if header_bytes.len() >= 8 && &header_bytes[0..8] == b"\x89PNG\r\n\x1a\n" {
            if clean_ext == "png" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Png);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: PNG header detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        // JPEG magic bytes: "\xFF\xD8\xFF"
        if header_bytes.len() >= 3 && header_bytes[0..3] == [0xFF, 0xD8, 0xFF] {
            if clean_ext == "jpg" || clean_ext == "jpeg" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Jpeg);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: JPEG header detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        // WAV magic bytes: "RIFF....WAVE"
        if header_bytes.len() >= 12
            && &header_bytes[0..4] == b"RIFF"
            && &header_bytes[8..12] == b"WAVE"
        {
            if clean_ext == "wav" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Wav);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: WAV header detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        // MP3 with ID3v2 tag: "ID3"
        if header_bytes.len() >= 3 && &header_bytes[0..3] == b"ID3" {
            if clean_ext == "mp3" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Mp3);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: MP3 (ID3) header detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        // MP3 raw frame sync: 11 consecutive 1s (0xFF followed by 0xEx)
        if header_bytes.len() >= 2 && header_bytes[0] == 0xFF && (header_bytes[1] & 0xE0) == 0xE0 {
            if clean_ext == "mp3" || clean_ext.is_empty() {
                return Ok(SupportedFileType::Mp3);
            } else {
                return Err(AppError::Validation(format!(
                    "MIME mismatch: MP3 audio sync frame detected but extension is '.{}'",
                    clean_ext
                )));
            }
        }

        Err(AppError::Validation(format!(
            "Unsupported or unrecognized file type for extension '.{}'. Permitted types: PDF, PNG, JPG, WAV, MP3",
            clean_ext
        )))
    }

    /// Validates file size against maximum permissible bytes
    pub fn validate_file_size(size_bytes: u64, max_bytes: Option<u64>) -> AppResult<()> {
        let limit = max_bytes.unwrap_or(Self::DEFAULT_MAX_FILE_SIZE_BYTES);
        if size_bytes == 0 {
            return Err(AppError::Validation(
                "Evidence file is empty (0 bytes)".to_string(),
            ));
        }
        if size_bytes > limit {
            return Err(AppError::Validation(format!(
                "Evidence file size exceeds limit: {} bytes exceeds maximum allowed {} bytes ({:.1} MB)",
                size_bytes,
                limit,
                (limit as f64) / (1024.0 * 1024.0)
            )));
        }
        Ok(())
    }
}

/// Evidence Vault Cryptographic Hashing and Sandboxing (Section 4.5)
pub struct EvidenceVault;

impl EvidenceVault {
    /// Resolve default application data directory conforming to OS standards:
    /// - macOS: ~/Library/Application Support/DebtShark (with CounterFin and SettleMint fallbacks)
    /// - Windows: %APPDATA%/DebtShark
    /// - Linux: ~/.config/DebtShark (or $XDG_CONFIG_HOME/DebtShark)
    pub fn resolve_os_sandbox_dir() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                let base = PathBuf::from(home)
                    .join("Library")
                    .join("Application Support");
                if base.join("DebtShark").exists() {
                    base.join("DebtShark")
                } else if base.join("CounterFin").exists() {
                    base.join("CounterFin")
                } else if base.join("SettleMint").exists() {
                    base.join("SettleMint")
                } else {
                    base.join("DebtShark")
                }
            } else {
                PathBuf::from("./debtshark_sandbox")
            }
        }

        #[cfg(target_os = "windows")]
        {
            let base = if let Ok(app_data) = std::env::var("APPDATA") {
                PathBuf::from(app_data)
            } else if let Ok(user_profile) = std::env::var("USERPROFILE") {
                PathBuf::from(user_profile).join("AppData").join("Roaming")
            } else {
                PathBuf::from(".")
            };
            if base.join("DebtShark").exists() {
                base.join("DebtShark")
            } else if base.join("CounterFin").exists() {
                base.join("CounterFin")
            } else if base.join("SettleMint").exists() {
                base.join("SettleMint")
            } else {
                base.join("DebtShark")
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let base = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
                PathBuf::from(xdg_config)
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home).join(".config")
            } else {
                PathBuf::from(".")
            };
            if base.join("CounterFin").exists() || !base.join("SettleMint").exists() {
                base.join("CounterFin")
            } else {
                base.join("SettleMint")
            }
        }
    }

    /// Build strongly typed sandbox hierarchy for given base directory
    pub fn build_sandbox_paths<P: AsRef<Path>>(base_dir: P) -> SandboxPaths {
        let base = base_dir.as_ref().to_path_buf();
        SandboxPaths {
            database_dir: base.join("dbs"),
            evidence_dir: base.join("evidence"),
            letters_dir: base.join("letters"),
            backups_dir: base.join("backups"),
            temp_dir: base.join("temp"),
            base_dir: base,
        }
    }

    /// Calculate SHA-256 hash of a byte slice for cryptographic chain of custody
    pub fn compute_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex_encode(&hasher.finalize())
    }

    /// Calculate SHA-256 hash streaming directly from a file path
    pub fn compute_file_sha256<P: AsRef<Path>>(path: P) -> AppResult<String> {
        let mut file = File::open(path)
            .map_err(|e| AppError::Io(format!("Failed to open file for hashing: {}", e)))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024]; // 64 KB buffer

        loop {
            let bytes_read = file
                .read(&mut buffer)
                .map_err(|e| AppError::Io(format!("Failed to read file for hashing: {}", e)))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex_encode(&hasher.finalize()))
    }

    /// Verify file integrity against an expected SHA-256 hash.
    /// Returns true if the file exists on disk and matches the expected hash.
    pub fn verify_file_integrity<P: AsRef<Path>>(expected_hash: &str, path: P) -> AppResult<bool> {
        let computed = Self::compute_file_sha256(path)?;
        Ok(computed.eq_ignore_ascii_case(expected_hash.trim()))
    }

    /// Audit file integrity and generate a structured tamper report.
    pub fn audit_file_integrity<P: AsRef<Path>>(
        expected_hash: &str,
        path: P,
    ) -> AppResult<EvidenceIntegrityReport> {
        let p = path.as_ref().to_path_buf();
        let actual_hash = Self::compute_file_sha256(&p)?;
        let is_valid = actual_hash.eq_ignore_ascii_case(expected_hash.trim());
        Ok(EvidenceIntegrityReport {
            is_valid,
            is_tampered: !is_valid,
            expected_hash: expected_hash.trim().to_string(),
            actual_hash,
            file_path: p,
        })
    }

    /// Assert file integrity, returning AppError::Validation if the file has been tampered with or modified.
    pub fn assert_file_integrity<P: AsRef<Path>>(expected_hash: &str, path: P) -> AppResult<()> {
        let report = Self::audit_file_integrity(expected_hash, &path)?;
        if report.is_tampered {
            return Err(AppError::Validation(format!(
                "Evidence file tamper detected for path {:?}: expected SHA-256 '{}', actual disk SHA-256 '{}'",
                report.file_path, report.expected_hash, report.actual_hash
            )));
        }
        Ok(())
    }

    /// Sanitizes an input filename, stripping directory traversal separators,
    /// null bytes, and malicious tokens.
    pub fn sanitize_filename(name: &str) -> AppResult<String> {
        if name.contains('\0') {
            return Err(AppError::Validation(
                "Filename contains forbidden null byte".to_string(),
            ));
        }
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(AppError::Validation(format!(
                "Filename contains directory traversal separators: '{}'",
                name
            )));
        }
        let clean = name.trim();
        if clean.is_empty() || clean == "." || clean == ".." {
            return Err(AppError::Validation(format!(
                "Invalid empty or dot filename: '{}'",
                name
            )));
        }

        let filtered: String = clean
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '_' || *c == '-' || *c == ' ')
            .collect();

        if filtered.is_empty() || filtered == "." || filtered == ".." {
            return Err(AppError::Validation(format!(
                "Filename has no valid characters after sanitization: '{}'",
                name
            )));
        }

        Ok(filtered)
    }

    /// Normalizes path by resolving '.' and '..' components without filesystem lookups
    pub fn normalize_path(path: &Path) -> PathBuf {
        use std::path::Component;
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Prefix(p) => out.push(p.as_os_str()),
                Component::RootDir => out.push(Component::RootDir.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(c) => out.push(c),
            }
        }
        out
    }

    /// Validates that a requested target path or subpath remains strictly confined
    /// within the sandbox base directory.
    /// Strictly rejects:
    /// 1. Null bytes (`\0`)
    /// 2. Explicit traversal tokens (`..`)
    /// 3. Absolute path escapes outside sandbox
    /// 4. Symlinks pointing outside the sandbox boundary
    pub fn validate_sandbox_containment<B: AsRef<Path>, P: AsRef<Path>>(
        sandbox_base: B,
        target: P,
    ) -> AppResult<PathBuf> {
        let base_path = sandbox_base.as_ref();
        let target_path = target.as_ref();

        // 1. Check for null bytes
        let target_str = target_path.to_string_lossy();
        if target_str.contains('\0') {
            return Err(AppError::Validation(
                "Path traversal rejected: null byte detected in path payload".to_string(),
            ));
        }

        // 2. Reject directory traversal sequences in string (cross-platform for / and \)
        if target_str.contains("../")
            || target_str.contains("..\\")
            || target_str.ends_with("/..")
            || target_str.ends_with("\\..")
            || target_str == ".."
        {
            return Err(AppError::Validation(
                "Path traversal rejected: parent directory token ('..') detected".to_string(),
            ));
        }

        // Reject explicit parent traversal tokens in components
        for component in target_path.components() {
            if let std::path::Component::ParentDir = component {
                return Err(AppError::Validation(
                    "Path traversal rejected: parent directory token ('..') detected".to_string(),
                ));
            }
        }

        // Canonicalize base directory
        let canonical_base = base_path
            .canonicalize()
            .unwrap_or_else(|_| base_path.to_path_buf());

        // Resolve candidate path
        let candidate = if target_path.is_absolute() {
            // Find existing ancestor and canonicalize to resolve system symlinks (e.g. /var -> /private/var on macOS)
            let mut ancestor = target_path.to_path_buf();
            let mut remaining_tail = Vec::new();
            while !ancestor.exists() {
                if let Some(parent) = ancestor.parent() {
                    if let Some(file_name) = ancestor.file_name() {
                        remaining_tail.push(file_name.to_os_string());
                    }
                    ancestor = parent.to_path_buf();
                } else {
                    break;
                }
            }

            if ancestor.exists() {
                let canonical_ancestor = ancestor.canonicalize().map_err(|e| {
                    AppError::Io(format!("Failed to canonicalize path ancestor: {}", e))
                })?;
                let mut full_path = canonical_ancestor;
                for part in remaining_tail.into_iter().rev() {
                    full_path.push(part);
                }
                full_path
            } else {
                target_path.to_path_buf()
            }
        } else {
            canonical_base.join(target_path)
        };

        // If candidate already exists, canonicalize directly (resolves symlinks)
        if candidate.exists() {
            let canonical_target = candidate
                .canonicalize()
                .map_err(|e| AppError::Io(format!("Failed to canonicalize target path: {}", e)))?;
            if !canonical_target.starts_with(&canonical_base) {
                return Err(AppError::Validation(format!(
                    "Sandbox escape violation: target {:?} canonicalizes outside sandbox {:?}",
                    target_path, canonical_base
                )));
            }
            Ok(canonical_target)
        } else {
            // For not-yet-existing paths, check closest existing ancestor for symlinks / escapes
            let mut ancestor = candidate.clone();
            while !ancestor.exists() {
                if let Some(parent) = ancestor.parent() {
                    ancestor = parent.to_path_buf();
                } else {
                    break;
                }
            }

            if ancestor.exists() {
                let canonical_ancestor = ancestor.canonicalize().map_err(|e| {
                    AppError::Io(format!("Failed to canonicalize path ancestor: {}", e))
                })?;
                if !canonical_ancestor.starts_with(&canonical_base) {
                    return Err(AppError::Validation(
                        "Sandbox escape violation: path ancestor canonicalizes outside sandbox"
                            .to_string(),
                    ));
                }
            }

            // Normalization check
            let normalized = Self::normalize_path(&candidate);
            if !normalized.starts_with(&canonical_base) {
                return Err(AppError::Validation(format!(
                    "Sandbox escape violation: normalized candidate {:?} is outside sandbox {:?}",
                    normalized, canonical_base
                )));
            }

            Ok(candidate)
        }
    }

    /// Generate an anonymized sandboxed storage filename using internal UUID
    /// Obscures debtor/creditor names and medical billing details from OS desktop search indexers
    pub fn generate_vault_filename(doc_id: &Uuid, original_extension: &str) -> String {
        let ext = original_extension.trim_start_matches('.');
        if ext.is_empty() {
            doc_id.to_string()
        } else {
            format!("{}.{}", doc_id, ext)
        }
    }

    /// Validates an evidentiary payload's MIME type, magic bytes, and size
    pub fn validate_evidence_payload(
        bytes: &[u8],
        extension: &str,
        max_bytes: Option<u64>,
    ) -> AppResult<EvidenceValidationInfo> {
        FileTypeValidator::validate_file_size(bytes.len() as u64, max_bytes)?;
        let file_type = FileTypeValidator::detect_and_validate(bytes, extension)?;
        let sha256_hash = Self::compute_sha256(bytes);
        Ok(EvidenceValidationInfo {
            file_type,
            mime_type: file_type.mime_type().to_string(),
            size_bytes: bytes.len() as u64,
            sha256_hash,
        })
    }

    /// Ingest a document or audio recording into the sandboxed evidence directory using streaming I/O:
    /// 1. Reads header bytes and validates MIME type and magic bytes without loading whole file into RAM
    /// 2. Validates overall file size against configured limit
    /// 3. Computes SHA-256 checksum in 64 KB chunks for cryptographic chain of custody
    /// 4. Generates UUID-anonymized vault filename
    /// 5. Validates sandbox containment
    /// 6. Streams payload directly to sandboxed destination file
    /// 7. Returns IngestedEvidence metadata record
    pub fn ingest_evidence_streaming(
        sandbox: &SandboxPaths,
        source_path: &Path,
        doc_id: &Uuid,
        max_bytes: Option<u64>,
    ) -> AppResult<IngestedEvidence> {
        let original_filename = source_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("document.bin")
            .to_string();

        let ext = source_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");

        let metadata = fs::metadata(source_path)
            .map_err(|e| AppError::Io(format!("Failed to read source file metadata: {}", e)))?;
        let file_size_bytes = metadata.len();
        FileTypeValidator::validate_file_size(file_size_bytes, max_bytes)?;

        let vault_filename = Self::generate_vault_filename(doc_id, ext);
        let destination_path = sandbox.evidence_dir.join(&vault_filename);
        Self::validate_sandbox_containment(&sandbox.base_dir, &destination_path)?;

        let mut file = File::open(source_path)
            .map_err(|e| AppError::Io(format!("Failed to open source evidence: {}", e)))?;

        // Read initial header chunk for MIME magic validation
        let mut header = [0u8; 512];
        let header_read = file
            .read(&mut header)
            .map_err(|e| AppError::Io(format!("Failed to read source header: {}", e)))?;
        if header_read == 0 {
            return Err(AppError::Validation(
                "Evidence file is empty (0 bytes)".to_string(),
            ));
        }

        FileTypeValidator::detect_and_validate(&header[..header_read], ext)?;

        // Rewind to start of file for streaming copy and hash computation
        file.seek(SeekFrom::Start(0))
            .map_err(|e| AppError::Io(format!("Failed to seek source file: {}", e)))?;

        let mut dest_file = File::create(&destination_path)
            .map_err(|e| AppError::Io(format!("Failed to create vault file: {}", e)))?;

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024]; // 64 KB streaming buffer
        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| {
                AppError::Io(format!(
                    "Failed to read chunk during streaming ingest: {}",
                    e
                ))
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            dest_file
                .write_all(&buffer[..bytes_read])
                .map_err(|e| AppError::Io(format!("Failed to write chunk to vault file: {}", e)))?;
        }

        let sha256_hash = hex_encode(&hasher.finalize());

        Ok(IngestedEvidence {
            doc_id: *doc_id,
            original_filename,
            vault_filename: vault_filename.clone(),
            relative_vault_path: format!("evidence/{}", vault_filename),
            absolute_path: destination_path,
            sha256_hash,
            file_size_bytes,
        })
    }

    /// Ingest a document or audio recording with default file size limit (50 MB)
    pub fn ingest_evidence(
        sandbox: &SandboxPaths,
        source_path: &Path,
        doc_id: &Uuid,
    ) -> AppResult<IngestedEvidence> {
        Self::ingest_evidence_streaming(sandbox, source_path, doc_id, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sandbox_hierarchy_creation() {
        let temp_dir = std::env::temp_dir().join(format!("settlemint_test_{}", Uuid::new_v4()));
        let sandbox = EvidenceVault::build_sandbox_paths(&temp_dir);

        assert!(sandbox.create_all().is_ok());
        assert!(sandbox.base_dir.exists());
        assert!(sandbox.database_dir.exists());
        assert!(sandbox.evidence_dir.exists());
        assert!(sandbox.letters_dir.exists());
        assert!(sandbox.backups_dir.exists());
        assert!(sandbox.temp_dir.exists());

        // Test cleanup
        let dummy_temp_file = sandbox.temp_dir.join("scratch.tmp");
        let mut f = File::create(&dummy_temp_file).unwrap();
        f.write_all(b"temporary scratch bytes").unwrap();
        assert!(dummy_temp_file.exists());

        assert!(sandbox.cleanup_temp().is_ok());
        assert!(!dummy_temp_file.exists());

        // Clean up root test directory
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_evidence_ingestion_and_hashing() {
        let temp_dir =
            std::env::temp_dir().join(format!("settlemint_vault_test_{}", Uuid::new_v4()));
        let sandbox = EvidenceVault::build_sandbox_paths(&temp_dir);
        sandbox.create_all().expect("Failed to create sandbox");

        // Create mock source evidence
        let mock_source = temp_dir.join("Hospital_Emergency_Bill_Sensitive.pdf");
        let mock_content = b"%PDF-1.4 Mock Itemized Medical Bill with CPT 99285 $4,200.00";
        let mut f = File::create(&mock_source).unwrap();
        f.write_all(mock_content).unwrap();

        let doc_id = Uuid::new_v4();
        let ingested = EvidenceVault::ingest_evidence(&sandbox, &mock_source, &doc_id)
            .expect("Ingestion failed");

        assert_eq!(ingested.doc_id, doc_id);
        assert_eq!(
            ingested.original_filename,
            "Hospital_Emergency_Bill_Sensitive.pdf"
        );
        assert_eq!(ingested.vault_filename, format!("{}.pdf", doc_id));
        assert!(ingested.absolute_path.exists());
        assert_eq!(ingested.file_size_bytes, mock_content.len() as u64);

        // Verify SHA-256 match
        let expected_hash = EvidenceVault::compute_sha256(mock_content);
        assert_eq!(ingested.sha256_hash, expected_hash);

        // Verify streaming file hash matches byte slice hash
        let streamed_hash = EvidenceVault::compute_file_sha256(&ingested.absolute_path)
            .expect("Streaming hash failed");
        assert_eq!(streamed_hash, expected_hash);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_os_sandbox_path_resolution() {
        let path = EvidenceVault::resolve_os_sandbox_dir();
        assert!(
            path.to_string_lossy().contains("CounterFin")
                || path.to_string_lossy().contains("SettleMint")
        );
    }

    #[test]
    fn test_nist_sha256_vectors() {
        // NIST FIPS 180-2 Test Vector 1: Empty string
        assert_eq!(
            EvidenceVault::compute_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // NIST FIPS 180-2 Test Vector 2: "abc"
        assert_eq!(
            EvidenceVault::compute_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // NIST FIPS 180-2 Test Vector 3: 448-bit string
        assert_eq!(
            EvidenceVault::compute_sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            ),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_evidence_file_tamper_and_hash_mismatch_detection() {
        let temp_dir =
            std::env::temp_dir().join(format!("settlemint_tamper_test_{}", Uuid::new_v4()));
        let sandbox = EvidenceVault::build_sandbox_paths(&temp_dir);
        sandbox.create_all().expect("Failed to create sandbox");

        // 1. Create original authentic evidence file (e.g. collection notice or itemized bill)
        let source_path = temp_dir.join("original_validation_letter.pdf");
        let initial_bytes = b"%PDF-1.4 AUTHENTIC RECORD: Debt validation notice issued by Acme Recovery LLC. Balance: $1,250.00";
        fs::write(&source_path, initial_bytes).expect("Failed to write initial source file");

        let doc_id = Uuid::new_v4();
        let ingested = EvidenceVault::ingest_evidence(&sandbox, &source_path, &doc_id)
            .expect("Ingestion failed");

        let canonical_hash = ingested.sha256_hash.clone();
        assert_eq!(canonical_hash, EvidenceVault::compute_sha256(initial_bytes));

        // 2. Validate clean integrity state
        assert!(
            EvidenceVault::verify_file_integrity(&canonical_hash, &ingested.absolute_path).unwrap()
        );
        assert!(
            EvidenceVault::assert_file_integrity(&canonical_hash, &ingested.absolute_path).is_ok()
        );

        let clean_report =
            EvidenceVault::audit_file_integrity(&canonical_hash, &ingested.absolute_path).unwrap();
        assert!(clean_report.is_valid);
        assert!(!clean_report.is_tampered);
        assert_eq!(clean_report.expected_hash, canonical_hash);
        assert_eq!(clean_report.actual_hash, canonical_hash);

        // 3. Single-byte modification on disk (flip bit 0 of byte 10)
        let mut disk_bytes =
            fs::read(&ingested.absolute_path).expect("Failed to read ingested file");
        let original_byte = disk_bytes[10];
        disk_bytes[10] ^= 0x01; // flip single bit
        assert_ne!(disk_bytes[10], original_byte);
        fs::write(&ingested.absolute_path, &disk_bytes).expect("Failed to overwrite file on disk");

        // 4. Assert tamper detection and hash mismatch
        let tampered_hash = EvidenceVault::compute_file_sha256(&ingested.absolute_path).unwrap();
        assert_ne!(
            tampered_hash, canonical_hash,
            "Avalanche effect must alter SHA-256 digest"
        );

        let is_valid =
            EvidenceVault::verify_file_integrity(&canonical_hash, &ingested.absolute_path).unwrap();
        assert!(
            !is_valid,
            "verify_file_integrity must report false when tampered"
        );

        let assert_res =
            EvidenceVault::assert_file_integrity(&canonical_hash, &ingested.absolute_path);
        match assert_res {
            Err(AppError::Validation(msg)) => {
                assert!(msg.contains("Evidence file tamper detected"));
                assert!(msg.contains(&canonical_hash));
                assert!(msg.contains(&tampered_hash));
            }
            other => panic!("Expected AppError::Validation, got {:?}", other),
        }

        let tamper_report =
            EvidenceVault::audit_file_integrity(&canonical_hash, &ingested.absolute_path).unwrap();
        assert!(!tamper_report.is_valid);
        assert!(tamper_report.is_tampered);
        assert_eq!(tamper_report.expected_hash, canonical_hash);
        assert_eq!(tamper_report.actual_hash, tampered_hash);

        // 5. Truncation tamper (delete last byte)
        disk_bytes.pop();
        fs::write(&ingested.absolute_path, &disk_bytes).expect("Failed to write truncated file");
        assert!(
            !EvidenceVault::verify_file_integrity(&canonical_hash, &ingested.absolute_path)
                .unwrap()
        );
        assert!(
            EvidenceVault::assert_file_integrity(&canonical_hash, &ingested.absolute_path).is_err()
        );

        // 6. Byte appended tamper (append trailing bytes)
        disk_bytes.push(0x00);
        disk_bytes.push(0xFF);
        fs::write(&ingested.absolute_path, &disk_bytes).expect("Failed to write appended file");
        assert!(
            !EvidenceVault::verify_file_integrity(&canonical_hash, &ingested.absolute_path)
                .unwrap()
        );
        assert!(
            EvidenceVault::assert_file_integrity(&canonical_hash, &ingested.absolute_path).is_err()
        );

        // 7. Non-existent file error handling
        let missing_path = temp_dir.join("non_existent_file.pdf");
        assert!(EvidenceVault::verify_file_integrity(&canonical_hash, &missing_path).is_err());
        assert!(EvidenceVault::assert_file_integrity(&canonical_hash, &missing_path).is_err());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_traversal_and_sandbox_escape_prevention() {
        let temp_dir =
            std::env::temp_dir().join(format!("settlemint_escape_test_{}", Uuid::new_v4()));
        let sandbox = EvidenceVault::build_sandbox_paths(&temp_dir);
        sandbox
            .create_all()
            .expect("Failed to create sandbox hierarchy");

        // 1. Parent directory traversal payloads
        let traversal_payloads = [
            "../outside.txt",
            "../../etc/passwd",
            "../../../var/log/system.log",
            "evidence/../../escaped.dat",
            "letters/../../../root_secret",
            "..\\..\\windows\\system32\\cmd.exe",
        ];

        for payload in traversal_payloads {
            let res = sandbox.resolve_safe_subpath(payload);
            assert!(
                res.is_err(),
                "Traversal payload '{}' should have been rejected, got {:?}",
                payload,
                res
            );
            match res {
                Err(AppError::Validation(msg)) => {
                    assert!(
                        msg.contains("Path traversal rejected")
                            || msg.contains("Sandbox escape violation"),
                        "Expected path traversal rejection message, got: {}",
                        msg
                    );
                }
                other => panic!("Expected AppError::Validation, got {:?}", other),
            }
        }

        // 2. Null byte injection payloads
        let null_byte_payloads = [
            "evidence/document.pdf\0.exe",
            "letters/docket\0_injection.txt",
            "\0",
            "normal_name.pdf\0",
        ];

        for payload in null_byte_payloads {
            let res = sandbox.resolve_safe_subpath(payload);
            assert!(
                res.is_err(),
                "Null byte payload should have been rejected, got {:?}",
                res
            );
            match res {
                Err(AppError::Validation(msg)) => {
                    assert!(
                        msg.contains("null byte"),
                        "Expected null byte alert, got: {}",
                        msg
                    );
                }
                other => panic!("Expected AppError::Validation, got {:?}", other),
            }

            // Also test filename sanitization with null byte
            assert!(EvidenceVault::sanitize_filename(payload).is_err());
        }

        // 3. Absolute paths outside sandbox
        #[cfg(unix)]
        let outside_paths = ["/etc/passwd", "/var/log", "/tmp"];
        #[cfg(windows)]
        let outside_paths = ["C:\\Windows\\System32", "C:\\Windows\\notepad.exe"];

        for path in outside_paths {
            let subpath_res = sandbox.resolve_safe_subpath(path);
            assert!(
                subpath_res.is_err(),
                "Absolute path '{}' as subpath must be rejected",
                path
            );

            let containment_res =
                EvidenceVault::validate_sandbox_containment(&sandbox.base_dir, path);
            assert!(
                containment_res.is_err(),
                "Absolute path '{}' outside sandbox base must be rejected",
                path
            );
        }

        // 4. Symlink escape prevention (Unix platforms)
        #[cfg(unix)]
        {
            let external_dir =
                std::env::temp_dir().join(format!("external_secret_{}", Uuid::new_v4()));
            fs::create_dir_all(&external_dir).expect("Failed to create external test dir");
            let external_file = external_dir.join("secret_records.pdf");
            fs::write(&external_file, b"CLASSIFIED DEBTOR MEDICAL RECORD")
                .expect("Failed to write external file");

            // Create symlink inside sandbox pointing outside
            let symlink_in_sandbox = sandbox.evidence_dir.join("symlink_to_external_file");
            std::os::unix::fs::symlink(&external_file, &symlink_in_sandbox)
                .expect("Failed to create symlink");

            // Validating containment on symlink must detect external target and reject
            let escape_res =
                EvidenceVault::validate_sandbox_containment(&sandbox.base_dir, &symlink_in_sandbox);
            assert!(
                escape_res.is_err(),
                "Symlink pointing outside sandbox must be rejected"
            );
            match escape_res {
                Err(AppError::Validation(msg)) => {
                    assert!(
                        msg.contains("Sandbox escape violation"),
                        "Expected sandbox escape violation, got: {}",
                        msg
                    );
                }
                other => panic!("Expected AppError::Validation, got {:?}", other),
            }

            // Create symlink directory pointing outside
            let symlink_dir = sandbox.evidence_dir.join("symlink_to_external_dir");
            std::os::unix::fs::symlink(&external_dir, &symlink_dir)
                .expect("Failed to create symlink dir");
            let file_in_symlink_dir = symlink_dir.join("non_existent_yet.pdf");
            let dir_escape_res = EvidenceVault::validate_sandbox_containment(
                &sandbox.base_dir,
                &file_in_symlink_dir,
            );
            assert!(
                dir_escape_res.is_err(),
                "Path inside symlinked external dir must be rejected"
            );

            let _ = fs::remove_dir_all(&external_dir);
        }

        // 5. Filename sanitization
        assert!(EvidenceVault::sanitize_filename("").is_err());
        assert!(EvidenceVault::sanitize_filename(".").is_err());
        assert!(EvidenceVault::sanitize_filename("..").is_err());
        assert!(EvidenceVault::sanitize_filename("../../etc/passwd").is_err());
        assert!(EvidenceVault::sanitize_filename("evil/file.pdf").is_err());
        assert!(EvidenceVault::sanitize_filename("evil\\file.pdf").is_err());

        let clean_filename =
            EvidenceVault::sanitize_filename("BATES-000001 Medical Notice 2026.pdf").unwrap();
        assert_eq!(clean_filename, "BATES-000001 Medical Notice 2026.pdf");

        // 6. Legitimate subpaths inside sandbox
        let canonical_sandbox_base = sandbox.base_dir.canonicalize().unwrap();
        let legit_1 = sandbox.resolve_safe_subpath("evidence/doc1.pdf").unwrap();
        assert!(legit_1.starts_with(&canonical_sandbox_base));

        let legit_2 = sandbox.resolve_safe_subpath("letters/dispute.txt").unwrap();
        assert!(legit_2.starts_with(&canonical_sandbox_base));

        let legit_3 = sandbox
            .resolve_safe_subpath("backups/snapshot.aes")
            .unwrap();
        assert!(legit_3.starts_with(&canonical_sandbox_base));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mime_type_and_size_limit_enforcement() {
        // 1. Permitted file types with valid magic bytes
        // PDF: %PDF-1.7
        let pdf_bytes = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF";
        let pdf_info = EvidenceVault::validate_evidence_payload(pdf_bytes, "pdf", None).unwrap();
        assert_eq!(pdf_info.file_type, SupportedFileType::Pdf);
        assert_eq!(pdf_info.mime_type, "application/pdf");

        // PNG: \x89PNG\r\n\x1a\n
        let mut png_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png_bytes.extend_from_slice(b"IHDR_mock_chunk_content");
        let png_info = EvidenceVault::validate_evidence_payload(&png_bytes, "png", None).unwrap();
        assert_eq!(png_info.file_type, SupportedFileType::Png);
        assert_eq!(png_info.mime_type, "image/png");

        // JPEG: \xFF\xD8\xFF\xE0
        let jpg_bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        let jpg_info = EvidenceVault::validate_evidence_payload(&jpg_bytes, "jpg", None).unwrap();
        assert_eq!(jpg_info.file_type, SupportedFileType::Jpeg);
        assert_eq!(jpg_info.mime_type, "image/jpeg");

        // WAV: RIFF....WAVE
        let mut wav_bytes = Vec::new();
        wav_bytes.extend_from_slice(b"RIFF");
        wav_bytes.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]); // file size - 8
        wav_bytes.extend_from_slice(b"WAVEfmt ");
        let wav_info = EvidenceVault::validate_evidence_payload(&wav_bytes, "wav", None).unwrap();
        assert_eq!(wav_info.file_type, SupportedFileType::Wav);
        assert_eq!(wav_info.mime_type, "audio/wav");

        // MP3 with ID3 tag
        let mut mp3_id3 = Vec::new();
        mp3_id3.extend_from_slice(b"ID3\x03\x00\x00\x00\x00\x00\x00mock_id3_tag_audio");
        let mp3_info = EvidenceVault::validate_evidence_payload(&mp3_id3, "mp3", None).unwrap();
        assert_eq!(mp3_info.file_type, SupportedFileType::Mp3);
        assert_eq!(mp3_info.mime_type, "audio/mpeg");

        // MP3 raw frame sync (0xFF 0xFB)
        let mp3_sync = [0xFF, 0xFB, 0x90, 0x44, 0x00, 0x00];
        let mp3_sync_info =
            EvidenceVault::validate_evidence_payload(&mp3_sync, "mp3", None).unwrap();
        assert_eq!(mp3_sync_info.file_type, SupportedFileType::Mp3);

        // 2. Executable binary rejection
        // Windows PE ("MZ")
        let win_exe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let exe_res = EvidenceVault::validate_evidence_payload(&win_exe, "exe", None);
        assert!(exe_res.is_err(), "Windows PE executable must be rejected");

        // Windows PE disguised as PDF (spoofed extension)
        let win_exe_disguised = EvidenceVault::validate_evidence_payload(&win_exe, "pdf", None);
        assert!(
            win_exe_disguised.is_err(),
            "Spoofed Windows PE as .pdf must be rejected"
        );

        // Linux ELF ("\x7fELF")
        let linux_elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let elf_res = EvidenceVault::validate_evidence_payload(&linux_elf, "bin", None);
        assert!(elf_res.is_err(), "Linux ELF binary must be rejected");

        // Linux ELF disguised as PNG
        let elf_png = EvidenceVault::validate_evidence_payload(&linux_elf, "png", None);
        assert!(
            elf_png.is_err(),
            "Spoofed Linux ELF as .png must be rejected"
        );

        // macOS Mach-O 64-bit
        let macho = [0xFE, 0xED, 0xFA, 0xCF, 0x00, 0x00, 0x00, 0x01];
        let macho_res = EvidenceVault::validate_evidence_payload(&macho, "pdf", None);
        assert!(macho_res.is_err(), "Mach-O binary must be rejected");

        // Shell script shebang
        let shell_script = b"#!/bin/bash\nrm -rf /";
        let sh_res = EvidenceVault::validate_evidence_payload(shell_script, "sh", None);
        assert!(sh_res.is_err(), "Shell script must be rejected");

        // Prohibited extensions
        for bad_ext in &[
            "exe", "dll", "so", "dylib", "bat", "cmd", "ps1", "sh", "vbs",
        ] {
            let res = EvidenceVault::validate_evidence_payload(pdf_bytes, bad_ext, None);
            assert!(res.is_err(), "Extension .{} must be rejected", bad_ext);
        }

        // 3. MIME / Extension mismatch
        // PNG header with .pdf extension
        let png_as_pdf = EvidenceVault::validate_evidence_payload(&png_bytes, "pdf", None);
        assert!(
            png_as_pdf.is_err(),
            "MIME mismatch (PNG with .pdf) must be rejected"
        );

        // PDF header with .mp3 extension
        let pdf_as_mp3 = EvidenceVault::validate_evidence_payload(pdf_bytes, "mp3", None);
        assert!(
            pdf_as_mp3.is_err(),
            "MIME mismatch (PDF with .mp3) must be rejected"
        );

        // 4. Empty file rejection (0 bytes)
        let empty_res = EvidenceVault::validate_evidence_payload(b"", "pdf", None);
        assert!(empty_res.is_err(), "0-byte empty file must be rejected");

        // 5. File size limit enforcement
        let max_test_limit = 500u64; // 500 bytes limit
        let small_content = b"%PDF-1.4 Mock document under 500 bytes limit";
        assert!(
            EvidenceVault::validate_evidence_payload(small_content, "pdf", Some(max_test_limit))
                .is_ok()
        );

        let mut large_content = Vec::new();
        large_content.extend_from_slice(b"%PDF-1.4 ");
        large_content.resize(600, b'A'); // 600 bytes exceeds 500 byte limit
        let oversize_res =
            EvidenceVault::validate_evidence_payload(&large_content, "pdf", Some(max_test_limit));
        assert!(
            oversize_res.is_err(),
            "Payload exceeding limit must be rejected"
        );
        match oversize_res {
            Err(AppError::Validation(msg)) => {
                assert!(
                    msg.contains("Evidence file size exceeds limit"),
                    "Got: {}",
                    msg
                );
            }
            other => panic!("Expected AppError::Validation, got {:?}", other),
        }

        // 6. Ingest evidence integration: rejection of malware disguised as evidence
        let temp_dir =
            std::env::temp_dir().join(format!("settlemint_mime_test_{}", Uuid::new_v4()));
        let sandbox = EvidenceVault::build_sandbox_paths(&temp_dir);
        sandbox
            .create_all()
            .expect("Failed to create sandbox hierarchy");

        let malicious_file = temp_dir.join("ransomware_trojan.pdf");
        fs::write(&malicious_file, win_exe).expect("Failed to write mock malicious file");

        let doc_id = Uuid::new_v4();
        let ingest_res = EvidenceVault::ingest_evidence(&sandbox, &malicious_file, &doc_id);
        assert!(ingest_res.is_err(), "Ingesting executable binary must fail");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
