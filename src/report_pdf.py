"""
Markdown to PDF report rendering.
"""

from pathlib import Path


class PdfReportRenderer:
    """Render Markdown reports to PDF using HTML and CSS."""

    def generate_pdf(self, markdown_content: str, output_pdf_path: Path) -> Path:
        """Generate a PDF report from Markdown content."""
        try:
            import markdown
            from weasyprint import HTML, CSS
        except Exception as exc:
            raise RuntimeError("Missing markdown or weasyprint dependency") from exc

        html_body = markdown.markdown(
            markdown_content,
            extensions=["tables", "fenced_code", "nl2br"],
        )

        css = """
        @page {
            size: A4;
            margin: 2cm;
            @bottom-right {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #666;
            }
        }
        body {
            font-family: Helvetica, Arial, sans-serif;
            color: #333;
            line-height: 1.6;
            font-size: 11pt;
        }
        h1, h2, h3 {
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        h1 {
            font-size: 20pt;
            text-align: center;
            margin-bottom: 30px;
        }
        h2 {
            font-size: 16pt;
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 10pt;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            color: #2c3e50;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #fbfcff;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: "Courier New", Courier, monospace;
            color: #c7254e;
        }
        .page-break {
            page-break-before: always;
        }
        """

        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset=\"utf-8\"></head>
        <body>
            {html_body}
        </body>
        </html>
        """

        output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=full_html).write_pdf(
            str(output_pdf_path),
            stylesheets=[CSS(string=css)],
        )
        return output_pdf_path
