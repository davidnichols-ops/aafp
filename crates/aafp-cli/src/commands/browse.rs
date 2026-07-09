//! `aafp browse` — fetch a web page via Firecrawl and return agent-native content.

use colored::Colorize;

pub async fn run(url: &str, json: bool) -> anyhow::Result<()> {
    // Load .env for FIRECRAWL_API_KEY.
    let _ = dotenvy::dotenv();

    eprintln!("{} browsing {} via Firecrawl...", "→".dimmed(), url);

    let provider = aafp_perception::FirecrawlBrowseProvider::from_env(Default::default())?;
    let req = aafp_perception::BrowseRequest::new(url);

    use aafp_perception::BrowseProvider;
    let content = provider.browse(&req).await?;

    if json {
        let json = serde_json::json!({
            "url": content.url,
            "title": content.title,
            "status": content.metadata.status_code,
            "language": content.metadata.language,
            "description": content.metadata.description,
            "sections": content.sections.iter().map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "title": s.title,
                    "level": s.level,
                    "content": s.content,
                    "children": s.children,
                })
            }).collect::<Vec<_>>(),
            "links": content.links.iter().map(|l| {
                serde_json::json!({
                    "text": l.text,
                    "url": l.url,
                    "internal": l.internal,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!();
        println!("{}", "  Web Content  ".bold().on_cyan().black());
        println!();
        println!("  {} {}", "URL:".dimmed(), content.url.yellow());
        println!("  {} {}", "Title:".dimmed(), content.title.cyan().bold());
        if let Some(lang) = &content.metadata.language {
            println!("  {} {}", "Language:".dimmed(), lang);
        }
        if let Some(desc) = &content.metadata.description {
            println!("  {} {}", "Description:".dimmed(), desc.dimmed());
        }
        println!();

        if content.sections.is_empty() {
            println!("  {}", "No content sections extracted.".dimmed());
        } else {
            println!("{}", "  Sections:".bold());
            println!();
            for section in &content.sections {
                let indent = "  ".repeat(section.level as usize);
                println!("{} {}", indent.dimmed(), section.title.cyan());
                if !section.content.is_empty() {
                    // Show first 500 chars of content.
                    let preview: String = section.content.chars().take(500).collect();
                    println!("{} {}", indent.dimmed(), preview.dimmed());
                    if section.content.len() > 500 {
                        println!("{} {}", indent.dimmed(), "...".dimmed());
                    }
                }
                println!();
            }
        }

        if !content.links.is_empty() {
            println!("{}", "  Links:".bold());
            for link in content.links.iter().take(20) {
                let marker = if link.internal { "↩" } else { "→" };
                println!(
                    "  {} {} {}",
                    marker.dimmed(),
                    link.text.cyan(),
                    link.url.yellow()
                );
            }
            if content.links.len() > 20 {
                println!(
                    "  {} ... and {} more",
                    "  ".dimmed(),
                    content.links.len() - 20
                );
            }
        }

        println!();
        println!(
            "  {} {} sections, {} links",
            "✓".green(),
            content.sections.len(),
            content.links.len()
        );
    }

    Ok(())
}
