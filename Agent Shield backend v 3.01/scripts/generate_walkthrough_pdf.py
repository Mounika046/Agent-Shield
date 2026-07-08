from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 54
RIGHT_MARGIN = 54
TOP_MARGIN = 56
BOTTOM_MARGIN = 48
CONTENT_WIDTH = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


@dataclass
class Line:
    text: str
    font: str
    size: int
    leading: int


class SimplePDF:
    def __init__(self) -> None:
        self.objects: list[bytes] = []

    def add_object(self, data: bytes) -> int:
        self.objects.append(data)
        return len(self.objects)

    def build(self, output_path: Path, pages_content: list[bytes], page_size: tuple[int, int]) -> None:
        width, height = page_size
        font_helvetica = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_bold = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        font_courier = self.add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        content_ids = [self.add_object(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content)) for content in pages_content]

        page_ids: list[int] = []
        pages_kids = []
        pages_id_placeholder = len(self.objects) + len(pages_content) + 1

        for content_id in content_ids:
            page_obj = (
                f"<< /Type /Page /Parent {pages_id_placeholder} 0 R "
                f"/MediaBox [0 0 {width} {height}] "
                f"/Resources << /Font << /F1 {font_helvetica} 0 R /F2 {font_bold} 0 R /F3 {font_courier} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode("utf-8")
            page_id = self.add_object(page_obj)
            page_ids.append(page_id)
            pages_kids.append(f"{page_id} 0 R")

        pages_obj = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{' '.join(pages_kids)}] >>".encode("utf-8")
        pages_id = self.add_object(pages_obj)
        catalog_id = self.add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("utf-8"))

        offsets = []
        pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        for index, obj in enumerate(self.objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode("utf-8"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {len(self.objects) + 1}\n".encode("utf-8"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
        pdf.extend(
            (
                f"trailer\n<< /Size {len(self.objects) + 1} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF"
            ).encode("utf-8")
        )
        output_path.write_bytes(pdf)


def escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_text(text: str, max_chars: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def parse_markdown(markdown_text: str) -> list[Line]:
    lines: list[Line] = []
    in_code = False

    for raw in markdown_text.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            in_code = not in_code
            lines.append(Line("", "F1", 10, 12))
            continue

        if in_code:
            code_text = line if line else " "
            chunks = [code_text[i:i + 92] for i in range(0, len(code_text), 92)] or [" "]
            for chunk in chunks:
                lines.append(Line(chunk, "F3", 8, 10))
            continue

        if not line.strip():
            lines.append(Line("", "F1", 10, 12))
            continue

        heading_match = re.match(r"^(#{1,3})\s+(.*)$", line)
        if heading_match:
            level = len(heading_match.group(1))
            text = heading_match.group(2).strip()
            if level == 1:
                lines.append(Line(text, "F2", 20, 24))
            elif level == 2:
                lines.append(Line(text, "F2", 15, 19))
            else:
                lines.append(Line(text, "F2", 12, 16))
            continue

        bullet_match = re.match(r"^(\- |\d+\. )(.*)$", line)
        if bullet_match:
            prefix = bullet_match.group(1)
            body = bullet_match.group(2).strip()
            wrapped = wrap_text(body, 82)
            lines.append(Line(f"{prefix}{wrapped[0]}", "F1", 10, 13))
            indent = " " * len(prefix)
            for chunk in wrapped[1:]:
                lines.append(Line(f"{indent}{chunk}", "F1", 10, 13))
            continue

        for chunk in wrap_text(line.strip(), 88):
            lines.append(Line(chunk, "F1", 10, 13))

    return lines


def paginate(lines: list[Line]) -> list[list[Line]]:
    pages: list[list[Line]] = []
    current_page: list[Line] = []
    y = PAGE_HEIGHT - TOP_MARGIN

    for line in lines:
        if y - line.leading < BOTTOM_MARGIN:
            pages.append(current_page)
            current_page = []
            y = PAGE_HEIGHT - TOP_MARGIN
        current_page.append(line)
        y -= line.leading

    if current_page:
        pages.append(current_page)
    return pages


def render_page(lines: list[Line], page_number: int) -> bytes:
    commands = ["BT"]
    y = PAGE_HEIGHT - TOP_MARGIN

    for line in lines:
        if line.text:
            commands.append(f"/{line.font} {line.size} Tf")
            commands.append(f"1 0 0 1 {LEFT_MARGIN} {y} Tm")
            commands.append(f"({escape_pdf_text(line.text)}) Tj")
        y -= line.leading

    commands.append(f"/F1 9 Tf")
    commands.append(f"1 0 0 1 {LEFT_MARGIN} {BOTTOM_MARGIN - 14} Tm")
    commands.append(f"(AgentShield walkthrough - page {page_number}) Tj")
    commands.append("ET")
    return "\n".join(commands).encode("utf-8")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "docs" / "agentshield_backend_walkthrough.md"
    output = root / "docs" / "agentshield_backend_walkthrough.pdf"

    markdown_text = source.read_text(encoding="utf-8")
    parsed_lines = parse_markdown(markdown_text)
    pages = paginate(parsed_lines)
    page_streams = [render_page(page_lines, index + 1) for index, page_lines in enumerate(pages)]

    pdf = SimplePDF()
    pdf.build(output, page_streams, (PAGE_WIDTH, PAGE_HEIGHT))
    print(output)


if __name__ == "__main__":
    main()
