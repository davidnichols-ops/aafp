//! `aafp read-pdf` — extract text from a PDF via PyMuPDF.

use colored::Colorize;

pub async fn run(path: &str, json: bool, python: Option<&str>) -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // Determine Python path: --python flag > AAFP_PYTHON env > default python3.
    let python_path = python
        .map(|s| s.to_string())
        .or_else(|| std::env::var("AAFP_PYTHON").ok())
        .unwrap_or_else(|| "python3".to_string());

    eprintln!(
        "{} reading PDF: {} (python: {})",
        "→".dimmed(),
        path,
        python_path
    );

    let provider = aafp_perception::PyMuPdfProvider::with_config(aafp_perception::PyMuPdfConfig {
        python: python_path,
        ..Default::default()
    });

    let req = aafp_perception::DocumentReadRequest::new(path);

    use aafp_perception::DocumentReadProvider;
    let content = provider.read(&req).await?;

    if json {
        let json = serde_json::json!({
            "source": content.source,
            "type": content.doc_type,
            "title": content.title,
            "pages": content.pages.iter().map(|p| {
                serde_json::json!({
                    "page_num": p.page_num,
                    "text": p.text,
                    "sections": p.sections.iter().map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "title": s.title,
                            "level": s.level,
                        })
                    }).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!();
        println!("{}", "  PDF Content  ".bold().on_cyan().black());
        println!();
        println!("  {} {}", "Source:".dimmed(), content.source.yellow());
        println!("  {} {}", "Type:".dimmed(), content.doc_type);
        if let Some(title) = &content.title {
            println!("  {} {}", "Title:".dimmed(), title.cyan().bold());
        }
        println!("  {} {}", "Pages:".dimmed(), content.pages.len());
        println!();

        for page in &content.pages {
            println!("  {}", format!("--- Page {} ---", page.page_num).bold(),);
            // Print first 1000 chars of each page.
            let preview: String = page.text.chars().take(1000).collect();
            println!("  {}", preview.dimmed());
            if page.text.len() > 1000 {
                println!("  {}", "... (truncated)".dimmed());
            }
            println!();
        }

        println!("  {} {} pages extracted", "✓".green(), content.pages.len());
    }

    Ok(())
}
