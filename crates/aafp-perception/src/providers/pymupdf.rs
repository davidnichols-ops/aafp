//! PyMuPDF document-read provider.
//!
//! Implements [`DocumentReadProvider`] for PDF files by invoking a
//! Python subprocess with the `pymupdf` (a.k.a. `fitz`) library.
//! PyMuPDF must be installed in the Python environment:
//!
//! ```bash
//! pip install pymupdf
//! ```
//!
//! The provider writes a small Python script to a temp file, passes
//! the PDF path and page range as arguments, and parses the JSON
//! output into [`DocumentContent`].

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;

use crate::capabilities::document_read::{
    DocumentFormat, DocumentReadProvider, DocumentReadRequest, PageRange,
};
use crate::schema::{ContentHash, ContentSection, DocumentContent, DocumentPage, PageMetadata};
use crate::PerceptionError;

/// Configuration for the PyMuPDF provider.
#[derive(Clone, Debug)]
pub struct PyMuPdfConfig {
    /// Path to the Python interpreter.
    pub python: String,
    /// Subprocess timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for PyMuPdfConfig {
    fn default() -> Self {
        Self {
            python: "python3".to_string(),
            timeout_ms: 120_000,
        }
    }
}

/// A [`DocumentReadProvider`] backed by PyMuPDF (via Python subprocess).
pub struct PyMuPdfProvider {
    config: PyMuPdfConfig,
}

impl Default for PyMuPdfProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PyMuPdfProvider {
    /// Create a new provider with default configuration.
    pub fn new() -> Self {
        Self::with_config(PyMuPdfConfig::default())
    }

    /// Create a new provider with custom configuration.
    pub fn with_config(config: PyMuPdfConfig) -> Self {
        Self { config }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Generate the Python extraction script.
    fn extraction_script() -> &'static str {
        r#"
import sys, json
try:
    import fitz  # PyMuPDF
except ImportError:
    print(json.dumps({"error": "pymupdf not installed"}))
    sys.exit(1)

path = sys.argv[1]
start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
end = int(sys.argv[3]) if len(sys.argv) > 3 else 0

try:
    doc = fitz.open(path)
except Exception as e:
    print(json.dumps({"error": f"open failed: {e}"}))
    sys.exit(1)

meta = doc.metadata or {}
total = doc.page_count

if start > 0 and end > 0:
    page_indices = range(start - 1, min(end, total))
else:
    page_indices = range(total)

pages = []
for i in page_indices:
    page = doc[i]
    text = page.get_text("text") or ""
    # Split into sections by lines that look like headings (short, no trailing period).
    sections = []
    current_title = "Content"
    current_lines = []
    sid = 0
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped and len(stripped) < 80 and not stripped.endswith(".") and not stripped.endswith(","):
            if current_lines:
                sections.append({
                    "id": f"s{sid}",
                    "title": current_title,
                    "content": "\n".join(current_lines),
                    "level": 2,
                    "children": []
                })
                sid += 1
                current_lines = []
            current_title = stripped
        else:
            if stripped:
                current_lines.append(stripped)
    if current_lines or sid == 0:
        sections.append({
            "id": f"s{sid}",
            "title": current_title,
            "content": "\n".join(current_lines),
            "level": 2,
            "children": []
        })

    pages.append({
        "page_num": i + 1,
        "text": text,
        "sections": sections
    })

result = {
    "title": meta.get("title", ""),
    "language": meta.get("language", ""),
    "page_count": total,
    "pages": pages
}
print(json.dumps(result))
doc.close()
"#
    }
}

/// JSON output from the Python script.
#[derive(Deserialize)]
struct PyMuPdfOutput {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    page_count: u32,
    #[serde(default)]
    pages: Vec<PyMuPdfPage>,
}

#[derive(Deserialize)]
struct PyMuPdfPage {
    page_num: u32,
    text: String,
    #[serde(default)]
    sections: Vec<PyMuPdfSection>,
}

#[derive(Deserialize)]
struct PyMuPdfSection {
    id: String,
    title: String,
    content: String,
    level: u8,
    #[serde(default)]
    children: Vec<String>,
}

#[async_trait]
impl DocumentReadProvider for PyMuPdfProvider {
    async fn read(
        &self,
        request: &DocumentReadRequest,
    ) -> Result<DocumentContent, PerceptionError> {
        // Only handle PDF format.
        let format = request.format.unwrap_or_else(|| {
            crate::capabilities::document_read::detect_format(&request.source)
                .unwrap_or(DocumentFormat::Pdf)
        });
        if format != DocumentFormat::Pdf {
            return Err(PerceptionError::Provider(format!(
                "PyMuPdfProvider only supports PDF, got {:?}",
                format
            )));
        }

        let source = &request.source;
        // If it's a URL, we'd need to download it first. For now, only
        // local file paths are supported.
        if source.starts_with("http://") || source.starts_with("https://") {
            return Err(PerceptionError::Provider(
                "PyMuPdfProvider does not support URLs yet — download the file first".into(),
            ));
        }

        if !std::path::Path::new(source).exists() {
            return Err(PerceptionError::NotFound(source.clone()));
        }

        // Write the extraction script to a temp file.
        let script_path =
            std::env::temp_dir().join(format!("aafp_pymupdf_{}.py", std::process::id()));
        tokio::fs::write(&script_path, Self::extraction_script())
            .await
            .map_err(|e| PerceptionError::Provider(format!("write script: {e}")))?;

        // Determine page range arguments.
        let (start, end) = match &request.page_range {
            Some(PageRange { start, end }) => (start.to_string(), end.to_string()),
            None => ("0".to_string(), "0".to_string()),
        };

        let output = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            Command::new(&self.config.python)
                .arg(&script_path)
                .arg(source)
                .arg(&start)
                .arg(&end)
                .output(),
        )
        .await
        .map_err(|_| PerceptionError::Timeout)?
        .map_err(|e| PerceptionError::Provider(format!("python spawn: {e}")))?;

        // Clean up script (best-effort).
        let _ = tokio::fs::remove_file(&script_path).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PerceptionError::Provider(format!(
                "python failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: PyMuPdfOutput = serde_json::from_str(stdout.trim())
            .map_err(|e| PerceptionError::Provider(format!("parse python output: {e}")))?;

        if let Some(err) = parsed.error {
            return Err(PerceptionError::Provider(err));
        }

        let fetched_at = Self::now_ms();

        // Convert pages.
        let pages: Vec<DocumentPage> = parsed
            .pages
            .into_iter()
            .map(|p| DocumentPage {
                page_num: p.page_num,
                text: p.text,
                sections: p
                    .sections
                    .into_iter()
                    .map(|s| ContentSection {
                        id: s.id,
                        title: s.title,
                        content: s.content,
                        level: s.level,
                        children: s.children,
                    })
                    .collect(),
            })
            .collect();

        // Compute hash from all page text concatenated.
        let all_text: String = pages
            .iter()
            .map(|p| p.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let hash = ContentHash::compute(all_text.as_bytes());

        Ok(DocumentContent {
            source: source.clone(),
            doc_type: "pdf".into(),
            title: parsed.title.filter(|t| !t.is_empty()),
            pages,
            tables: Vec::new(),
            metadata: PageMetadata {
                status_code: 200,
                content_type: "application/pdf".into(),
                charset: None,
                language: parsed.language.filter(|l| !l.is_empty()),
                title: None,
                description: None,
                fetched_at,
            },
            language: None,
            ocr_applied: false,
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_non_pdf_rejected() {
        let provider = PyMuPdfProvider::new();
        let mut req = DocumentReadRequest::new("test.txt");
        req.format = Some(DocumentFormat::PlainText);
        let err = provider.read(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    #[tokio::test]
    async fn test_url_rejected() {
        let provider = PyMuPdfProvider::new();
        let req = DocumentReadRequest::new("https://example.com/doc.pdf");
        let err = provider.read(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    #[tokio::test]
    async fn test_nonexistent_file() {
        let provider = PyMuPdfProvider::new();
        let req = DocumentReadRequest::new("/tmp/aafp_nonexistent_test_file.pdf");
        let err = provider.read(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::NotFound(_)));
    }
}
