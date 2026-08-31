// Command docspreview renders the provider's docs/**/*.md files to
// standalone HTML that approximates how they'll appear on the Terraform
// Registry, for local review before a release. It is a preview aid, not a
// product -- keep additions here minimal.
//
// Usage:
//
//	go run ./tools/docspreview [-docs docs] [-out build/docs-preview]
package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"gopkg.in/yaml.v3"
)

// frontmatter mirrors the subset of tfplugindocs' generated YAML frontmatter
// this tool cares about. Unknown fields are ignored.
type frontmatter struct {
	PageTitle   string `yaml:"page_title"`
	Subcategory string `yaml:"subcategory"`
	Description string `yaml:"description"`
}

type page struct {
	// SourcePath is the docs/-relative source markdown path, e.g.
	// "resources/certificate.md".
	SourcePath string
	// OutPath is the output-relative HTML path, e.g. "resources/certificate.html".
	OutPath string
	Title   string
}

func main() {
	docsDir := flag.String("docs", "docs", "path to the docs directory to render")
	outDir := flag.String("out", filepath.Join("build", "docs-preview"), "output directory for rendered HTML")
	flag.Parse()

	if err := run(*docsDir, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "docspreview:", err)
		os.Exit(1)
	}
}

func run(docsDir, outDir string) error {
	var mdPaths []string
	err := filepath.Walk(docsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".md") {
			mdPaths = append(mdPaths, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", docsDir, err)
	}
	sort.Strings(mdPaths)

	if len(mdPaths) == 0 {
		return fmt.Errorf("no .md files found under %s", docsDir)
	}

	if err := os.RemoveAll(outDir); err != nil {
		return fmt.Errorf("clearing %s: %w", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", outDir, err)
	}

	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM), // tables, strikethrough, autolink, task lists
	)

	var pages []page
	for _, srcPath := range mdPaths {
		rel, err := filepath.Rel(docsDir, srcPath)
		if err != nil {
			return err
		}
		outRel := strings.TrimSuffix(rel, filepath.Ext(rel)) + ".html"
		if rel == "index.md" {
			// docs/index.md (the provider overview page) would otherwise
			// render to "index.html" and collide with -- and later get
			// silently clobbered by -- the site index/listing page written
			// below. Give it a distinct name instead.
			outRel = "provider.html"
		}
		outPath := filepath.Join(outDir, outRel)

		title, bodyHTML, err := renderPage(md, srcPath)
		if err != nil {
			return fmt.Errorf("rendering %s: %w", srcPath, err)
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(outPath, []byte(wrapHTML(title, bodyHTML)), 0o644); err != nil {
			return err
		}

		pages = append(pages, page{SourcePath: rel, OutPath: filepath.ToSlash(outRel), Title: title})
	}

	indexPath := filepath.Join(outDir, "index.html")
	if err := os.WriteFile(indexPath, []byte(renderIndex(pages)), 0o644); err != nil {
		return err
	}

	fmt.Printf("docspreview: rendered %d pages to %s (open %s)\n", len(pages), outDir, indexPath)
	return nil
}

// renderPage strips the leading "---"-delimited YAML frontmatter (as emitted
// by tfplugindocs), renders the remaining markdown body via goldmark with
// GFM extensions, and returns a page title (frontmatter page_title, falling
// back to the source filename) plus the rendered HTML body.
func renderPage(md goldmark.Markdown, srcPath string) (title string, bodyHTML string, err error) {
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return "", "", err
	}

	fm, body := splitFrontmatter(raw)

	title = fm.PageTitle
	if title == "" {
		title = filepath.Base(srcPath)
	}

	var buf bytes.Buffer
	if err := md.Convert(body, &buf); err != nil {
		return "", "", err
	}
	return title, buf.String(), nil
}

// splitFrontmatter separates a tfplugindocs-generated markdown file into its
// YAML frontmatter (delimited by "---" lines) and the remaining markdown
// body. If no frontmatter is present, fm is zero-valued and body is the
// entire input.
func splitFrontmatter(raw []byte) (fm frontmatter, body []byte) {
	const delim = "---"
	text := string(raw)
	if !strings.HasPrefix(strings.TrimLeft(text, "\r\n"), delim) {
		return fm, raw
	}
	text = strings.TrimLeft(text, "\r\n")
	rest := strings.TrimPrefix(text, delim)
	rest = strings.TrimPrefix(rest, "\n")
	rest = strings.TrimPrefix(rest, "\r\n")

	idx := strings.Index(rest, "\n"+delim)
	if idx == -1 {
		return fm, raw
	}
	fmBlock := rest[:idx]
	after := rest[idx+len("\n"+delim):]
	after = strings.TrimPrefix(after, "\n")
	after = strings.TrimPrefix(after, "\r\n")

	if err := yaml.Unmarshal([]byte(fmBlock), &fm); err != nil {
		// Malformed frontmatter shouldn't fail the whole preview build;
		// fall back to rendering the original content untouched.
		return frontmatter{}, raw
	}
	return fm, []byte(after)
}

func wrapHTML(title, bodyHTML string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s - terraform-provider-keyfactor docs preview</title>
<style>
%s
</style>
</head>
<body>
<div class="page">
<p class="preview-banner">Local docs preview -- approximates the Terraform Registry rendering, not the real thing.</p>
<article>
%s
</article>
</div>
</body>
</html>
`, html.EscapeString(title), previewCSS, bodyHTML)
}

func renderIndex(pages []page) string {
	var byGroup = map[string][]page{}
	for _, p := range pages {
		group := "provider"
		if strings.HasPrefix(p.SourcePath, "resources"+string(filepath.Separator)) {
			group = "resources"
		} else if strings.HasPrefix(p.SourcePath, "data-sources"+string(filepath.Separator)) {
			group = "data-sources"
		}
		byGroup[group] = append(byGroup[group], p)
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<title>terraform-provider-keyfactor docs preview</title>\n<style>\n")
	b.WriteString(previewCSS)
	b.WriteString("\n</style>\n</head>\n<body>\n<div class=\"page\">\n")
	b.WriteString("<h1>terraform-provider-keyfactor docs preview</h1>\n")
	b.WriteString("<p class=\"preview-banner\">Local docs preview -- approximates the Terraform Registry rendering, not the real thing.</p>\n")

	for _, group := range []string{"provider", "resources", "data-sources"} {
		list := byGroup[group]
		if len(list) == 0 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Title < list[j].Title })
		b.WriteString(fmt.Sprintf("<h2>%s</h2>\n<ul>\n", html.EscapeString(group)))
		for _, p := range list {
			b.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a></li>\n", html.EscapeString(p.OutPath), html.EscapeString(p.Title)))
		}
		b.WriteString("</ul>\n")
	}

	b.WriteString("</div>\n</body>\n</html>\n")
	return b.String()
}

const previewCSS = `
body { margin: 0; background: #f7f8fa; color: #1b1f24; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
.page { max-width: 860px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.preview-banner { background: #fff3cd; border: 1px solid #ffe69c; color: #664d03; padding: 0.5rem 0.75rem; border-radius: 4px; font-size: 0.85rem; }
article, .page h1 { line-height: 1.55; }
h1, h2, h3, h4 { color: #0b1b32; }
code, pre { background: #eef0f3; border-radius: 4px; }
code { padding: 0.1rem 0.3rem; font-size: 0.9em; }
pre { padding: 0.75rem 1rem; overflow-x: auto; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #d8dce1; padding: 0.4rem 0.6rem; text-align: left; }
a { color: #1f5eff; }
blockquote { border-left: 4px solid #d8dce1; margin: 1rem 0; padding: 0.25rem 1rem; color: #444; }
ul, ol { padding-left: 1.4rem; }
`
