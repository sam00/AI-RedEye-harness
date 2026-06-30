#!/usr/bin/env python3
"""Render a Markdown file to a styled PDF using xhtml2pdf (pure Python).

Usage: python3 md_to_pdf.py <input.md> <output.pdf>
"""

import sys

import markdown
from xhtml2pdf import pisa

# xhtml2pdf has limited CSS support: no border-radius/flex/nth-child.
# Keep styling to what its renderer honours (fonts, borders, backgrounds).
CSS = """
@page {
  size: letter; margin: 2cm 1.6cm 2.2cm 1.6cm;
  @frame footer { -pdf-frame-content: footerContent;
    bottom: 1.1cm; margin-left: 1.6cm; margin-right: 1.6cm; height: 1cm; }
}
body { font-family: Helvetica; font-size: 10pt; line-height: 1.4; color: #1a1a1a; }
.cover { text-align: center; }
.cover h1 { font-size: 30pt; border: none; color: #b00020; margin-bottom: 2px; }
.cover h2 { font-size: 17pt; border: none; color: #333333; margin-top: 0; }
.pb { page-break-before: always; }
#footerContent { font-size: 7.5pt; color: #888888; text-align: center;
  border-top: 1px solid #dddddd; padding-top: 3px; }
h1 { font-size: 21pt; color: #b00020; border-bottom: 3px solid #b00020;
     padding-bottom: 4px; }
h2 { font-size: 14pt; color: #222; border-bottom: 1px solid #cccccc;
     padding-bottom: 3px; margin-top: 18px; }
h3 { font-size: 11.5pt; color: #333333; margin-top: 14px; }
p, li { font-size: 10pt; }
code { font-family: Courier; font-size: 8.5pt; background: #f2f2f2; }
pre { font-family: Courier; background: #f6f8fa; border: 1px solid #e1e4e8;
      padding: 8px; font-size: 8pt; }
pre code { background: #f6f8fa; font-size: 8pt; }
table { border: 1px solid #cccccc; margin: 10px 0; font-size: 8.5pt; }
th { background: #b00020; color: #ffffff; border: 1px solid #cccccc;
     padding: 4px 6px; text-align: left; }
td { border: 1px solid #cccccc; padding: 4px 6px; text-align: left; }
blockquote { border-left: 4px solid #b00020; background: #fcf3f4;
             padding: 4px 12px; color: #444444; }
a { color: #b00020; }
hr { border-top: 1px solid #dddddd; }
"""


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    body = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "sane_lists", "md_in_html"],
    )
    footer = (
        "<div id='footerContent'>AI-RedEye-Harness &mdash; Structure &amp; Design"
        "&nbsp;&nbsp;&middot;&nbsp;&nbsp;Agentic SAST harness"
        "&nbsp;&nbsp;&middot;&nbsp;&nbsp;Page <pdf:pagenumber />"
        " of <pdf:pagecount /></div>"
    )
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<style>{CSS}</style></head><body>{footer}{body}</body></html>"
    )
    with open(dst, "wb") as out:
        result = pisa.CreatePDF(html, dest=out, encoding="utf-8")
    if result.err:
        print(f"xhtml2pdf reported {result.err} error(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
