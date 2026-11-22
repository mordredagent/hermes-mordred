"""Document attachments are read into text (PDF, Office, OpenDocument, RTF, text); images are not."""

from __future__ import annotations

import io
import sys
import zipfile
from collections import Counter
from email.message import EmailMessage

import pytest

from mordred_hermes.imports.mail import attachments
from mordred_hermes.imports.mail.body import extract_body

darwin = pytest.mark.skipif(sys.platform != "darwin", reason="PDFKit and textutil are macOS")


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
DOCX = _zip(
    {
        "word/document.xml": f"<w:document {W}><w:body>"
        "<w:p><w:r><w:t>見積書</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>Kestrel 基板 3 枚、</w:t></w:r><w:r><w:t>合計 144,000 円</w:t></w:r></w:p>"
        "</w:body></w:document>"
    }
)
S = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
XLSX = _zip(
    {
        "xl/sharedStrings.xml": f"<sst {S}><si><t>品名</t></si>"
        "<si><r><t>予算</t></r><rPh><t>ヨサン</t></rPh></si></sst>",
        "xl/worksheets/sheet1.xml": f'<worksheet {S}><sheetData><row><c t="inlineStr"><is><t>メモ</t></is></c>'
        "<c><v>240</v></c></row></sheetData></worksheet>",
    }
)
A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
PPTX = _zip(
    {
        "ppt/slides/slide2.xml": f"<p:sld xmlns:p='x' {A}><a:p><a:r><a:t>二枚目</a:t></a:r></a:p></p:sld>",
        "ppt/slides/slide1.xml": f"<p:sld xmlns:p='x' {A}><a:p><a:r><a:t>一枚目</a:t></a:r></a:p></p:sld>",
    }
)
ODT = _zip(
    {
        "content.xml": '<office:document-content xmlns:office="o" xmlns:text="t"><office:body>'
        "<text:h>議事録</text:h><text:p>次回は <text:span>11 月 30 日</text:span></text:p>"
        "</office:body></office:document-content>"
    }
)


def _pdf(text: str) -> bytes:
    """A one-page PDF with ``text`` in Helvetica (ASCII)."""
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref))
    return out.getvalue()


def _mail(*files: tuple[str, str, str, bytes]) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["To"] = "b@example.com"
    msg["Subject"] = "資料"
    msg.set_content("添付をご確認ください。")
    for maintype, subtype, name, data in files:
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg


def _texts(msg: EmailMessage) -> dict[str, str]:
    return dict(extract_body(msg, Counter()).attachment_texts)


def test_office_and_opendocument_text_is_read() -> None:
    texts = _texts(
        _mail(
            ("application", "octet-stream", "q.docx", DOCX),
            ("application", "octet-stream", "b.xlsx", XLSX),
            ("application", "octet-stream", "s.pptx", PPTX),
            ("application", "vnd.oasis.opendocument.text", "m.odt", ODT),
        )
    )
    assert texts["docx"] == "見積書\nKestrel 基板 3 枚、合計 144,000 円"
    assert texts["xlsx"] == "品名\n予算\nメモ"  # no furigana, no numbers
    assert texts["pptx"] == "一枚目\n\n二枚目"  # slides in their order
    assert texts["odf"] == "議事録\n次回は 11 月 30 日"


def test_images_are_not_read_and_still_counted() -> None:
    result = extract_body(_mail(("image", "png", "photo.png", b"\x89PNG\r\n\x1a\n" + b"0" * 64)), Counter())
    assert result.attachment_texts == ()
    assert result.attachments == ("image",)


def test_text_attachments_are_read() -> None:
    texts = _texts(_mail(("text", "csv", "list.csv", b"name,amount\nKestrel,48000\n")))
    assert texts["text"] == "name,amount\nKestrel,48000"


@darwin
def test_a_pdf_is_read_with_pdfkit() -> None:
    texts = _texts(_mail(("application", "pdf", "invoice.pdf", _pdf("Invoice 4471 total 144000"))))
    assert "Invoice 4471 total 144000" in texts["pdf"]


@darwin
def test_rtf_is_read_with_textutil() -> None:
    rtf = rb"{\rtf1\ansi\deff0 {\fonttbl {\f0 Helvetica;}}\f0 Budget agreed: 240\par}"
    assert _texts(_mail(("application", "rtf", "note.rtf", rtf)))["rtf"] == "Budget agreed: 240"


def test_hostile_or_broken_files_yield_nothing_and_are_counted() -> None:
    bomb = _zip({"word/document.xml": "<!DOCTYPE x [<!ENTITY a 'aaaa'>]><w:document>&a;</w:document>"})
    stats: Counter[str] = Counter()
    result = extract_body(
        _mail(("application", "octet-stream", "x.docx", bomb), ("application", "octet-stream", "y.docx", b"not a zip")),
        stats,
    )
    assert result.attachment_texts == ()
    assert stats["attachment_text_failed:docx"] == 2


def test_a_member_larger_than_the_budget_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attachments, "MAX_ZIP_READ_BYTES", 100)
    big = _zip(
        {
            "word/document.xml": f"<w:document {W}><w:body><w:p><w:r><w:t>{'x' * 500}</w:t></w:r></w:p>"
            "</w:body></w:document>"
        }
    )
    assert _texts(_mail(("application", "octet-stream", "big.docx", big))) == {}


def test_attachment_text_becomes_labelled_parts_of_the_sender() -> None:
    from mordred_hermes.imports.mail.normalize import NormalizeContext, NormalizedMessage, normalize
    from mordred_hermes.imports.mail.owner import OwnAddresses
    from mordred_hermes.imports.mail.source import RawMessage
    from mordred_hermes.imports.records import PartKind, validate_message

    long_docx = _zip(
        {
            "word/document.xml": f"<w:document {W}><w:body>"
            + "".join(f"<w:p><w:r><w:t>{'仕様' * 400}</w:t></w:r></w:p>" for _ in range(40))
            + "</w:body></w:document>"
        }
    )
    msg = _mail(
        ("application", "octet-stream", "q.docx", DOCX), ("application", "octet-stream", "spec.docx", long_docx)
    )
    ctx = NormalizeContext(account="work", own_addresses=OwnAddresses.of(["b@example.com"]), imported_at=1_800_000_000)
    result = normalize(RawMessage(data=bytes(msg), origin_index=0), ctx)
    assert isinstance(result, NormalizedMessage)
    validate_message(result.message)
    parts = result.message.parts
    assert parts[0].part_kind is PartKind.AUTHORED and parts[0].text == "添付をご確認ください。"
    attached = [p for p in parts if p.part_kind is PartKind.FORWARDED]
    assert attached[0].text == "[attachment: docx]\n見積書\nKestrel 基板 3 枚、合計 144,000 円"
    assert attached[1].text.startswith("[attachment: docx]\n仕様")
    assert attached[2].text.startswith("[attachment: docx, continued]\n")
    assert all(len(p.text.encode()) <= 64 * 1024 for p in parts)
    # The sender attached them: the parts are the sender's.
    assert {p.author_id for p in attached} == {parts[0].author_id}
    assert "q.docx" not in "".join(p.text for p in parts)  # file names are never kept
