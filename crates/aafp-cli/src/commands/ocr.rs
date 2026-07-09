//! `aafp ocr` — extract text from an image via Tesseract.

use colored::Colorize;

pub async fn run(path: &str, json: bool, lang: Option<&str>) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    eprintln!("{} running OCR on: {}", "→".dimmed(), path);

    // Read the image file.
    let image_data = tokio::fs::read(path).await?;

    // Detect format from extension.
    let format = match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => aafp_perception::ImageFormat::Png,
        "jpg" | "jpeg" => aafp_perception::ImageFormat::Jpeg,
        "webp" => aafp_perception::ImageFormat::Webp,
        "tif" | "tiff" => aafp_perception::ImageFormat::Tiff,
        _ => {
            crate::commands::util::print_error(
                "unsupported image format (use .png, .jpg, .webp, or .tiff)",
            );
            anyhow::bail!("unsupported image format");
        }
    };

    let provider = aafp_perception::TesseractOcrProvider::new();
    let mut req = aafp_perception::OcrRequest::new(image_data, format);
    if let Some(lang) = lang {
        req = req.with_language(lang);
    }

    use aafp_perception::MediaProvider;
    let resp = provider.ocr(&req).await?;

    if json {
        let json = serde_json::json!({
            "text": resp.text,
            "confidence": resp.confidence,
            "page_count": resp.page_count,
            "blocks": resp.blocks.iter().map(|b| {
                serde_json::json!({
                    "text": b.text,
                    "x": b.x,
                    "y": b.y,
                    "width": b.width,
                    "height": b.height,
                    "confidence": b.confidence,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!();
        println!("{}", "  OCR Result  ".bold().on_cyan().black());
        println!();
        println!("  {} {}", "Text:".dimmed(), resp.text.cyan().bold());
        println!(
            "  {} {:.0}%",
            "Confidence:".dimmed(),
            resp.confidence * 100.0
        );
        println!("  {} {}", "Pages:".dimmed(), resp.page_count);
        if !resp.blocks.is_empty() {
            println!("  {} {}", "Blocks:".dimmed(), resp.blocks.len());
        }
        println!();
        println!("  {}", "✓ OCR complete".green());
    }

    Ok(())
}
