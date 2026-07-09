//! Tesseract OCR provider.
//!
//! Implements the OCR portion of [`MediaProvider`] by invoking the
//! Tesseract CLI (`tesseract`) as a subprocess. Tesseract must be
//! installed on the system (`brew install tesseract` on macOS,
//! `apt install tesseract-ocr` on Debian/Ubuntu).
//!
//! Transcription is **not** supported by this provider — use a
//! Whisper-based provider for that.

use async_trait::async_trait;
use tokio::process::Command;

use crate::capabilities::media::{
    MediaProvider, OcrRequest, OcrResponse, TextBlock, TranscribeRequest, TranscribeResponse,
};
use crate::PerceptionError;

/// Configuration for the Tesseract OCR provider.
#[derive(Clone, Debug)]
pub struct TesseractConfig {
    /// Path to the `tesseract` binary.
    pub binary: String,
    /// Default language pack (e.g. `"eng"`).
    pub language: String,
    /// Timeout in milliseconds for the subprocess.
    pub timeout_ms: u64,
}

impl Default for TesseractConfig {
    fn default() -> Self {
        Self {
            binary: "tesseract".to_string(),
            language: "eng".to_string(),
            timeout_ms: 60_000,
        }
    }
}

/// A [`MediaProvider`] that performs OCR via the Tesseract CLI.
///
/// Transcription always returns an error — this provider only handles OCR.
pub struct TesseractOcrProvider {
    config: TesseractConfig,
}

impl Default for TesseractOcrProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TesseractOcrProvider {
    /// Create a new provider with default configuration.
    pub fn new() -> Self {
        Self::with_config(TesseractConfig::default())
    }

    /// Create a new provider with custom configuration.
    pub fn with_config(config: TesseractConfig) -> Self {
        Self { config }
    }

    /// Write image bytes to a temp file with the appropriate extension.
    async fn write_temp_image(
        &self,
        image_data: &[u8],
        format: &crate::capabilities::media::ImageFormat,
    ) -> Result<std::path::PathBuf, PerceptionError> {
        let ext = match format {
            crate::capabilities::media::ImageFormat::Png => "png",
            crate::capabilities::media::ImageFormat::Jpeg => "jpg",
            crate::capabilities::media::ImageFormat::Webp => "webp",
            crate::capabilities::media::ImageFormat::Tiff => "tif",
        };
        let dir = std::env::temp_dir();
        let filename = format!("aafp_ocr_{}.{}", std::process::id(), ext);
        let path = dir.join(filename);
        tokio::fs::write(&path, image_data)
            .await
            .map_err(|e| PerceptionError::Provider(format!("write temp image: {e}")))?;
        Ok(path)
    }
}

#[async_trait]
impl MediaProvider for TesseractOcrProvider {
    async fn transcribe(
        &self,
        _req: &TranscribeRequest,
    ) -> Result<TranscribeResponse, PerceptionError> {
        Err(PerceptionError::Provider(
            "TesseractOcrProvider does not support transcription".into(),
        ))
    }

    async fn ocr(&self, req: &OcrRequest) -> Result<OcrResponse, PerceptionError> {
        let image_path = self.write_temp_image(&req.image_data, &req.format).await?;
        let lang = req
            .language_hint
            .as_deref()
            .unwrap_or(&self.config.language);

        // Run: tesseract <image> stdout -l <lang>
        let output = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            Command::new(&self.config.binary)
                .arg(&image_path)
                .arg("stdout")
                .arg("-l")
                .arg(lang)
                .output(),
        )
        .await
        .map_err(|_| PerceptionError::Timeout)?
        .map_err(|e| PerceptionError::Provider(format!("tesseract spawn: {e}")))?;

        // Clean up temp file (best-effort).
        let _ = tokio::fs::remove_file(&image_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PerceptionError::Provider(format!(
                "tesseract failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }

        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Tesseract CLI doesn't provide bounding boxes in this mode,
        // so we return a single block covering the whole image.
        let blocks = if text.is_empty() {
            Vec::new()
        } else {
            vec![TextBlock::new(text.clone(), 0, 0, 0, 0, 0.9)]
        };

        Ok(OcrResponse {
            text,
            blocks,
            confidence: 0.85,
            page_count: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::media::ImageFormat;

    #[tokio::test]
    async fn test_transcribe_unsupported() {
        let provider = TesseractOcrProvider::new();
        let req = TranscribeRequest::new(vec![], crate::capabilities::media::AudioFormat::Wav);
        let err = provider.transcribe(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    #[tokio::test]
    async fn test_ocr_empty_image_returns_error() {
        let provider = TesseractOcrProvider::new();
        let req = OcrRequest::new(vec![], ImageFormat::Png);
        // This will fail because tesseract can't process an empty image,
        // but we just verify the error is a Provider error, not a panic.
        let result = provider.ocr(&req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::Provider(_) | PerceptionError::Timeout
        ));
    }
}
