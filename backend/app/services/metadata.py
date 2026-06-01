"""Metadata нормчлол — MIME төрөл, эрсдэлийн үнэлгээ, timeline үүсгэх.

Эрсдэлийн үнэлгээ нь **дүрэмд суурилсан оноо**-гоор тооцогдоно. Дүрэм бүр оноо
нэмж, шалтгааныг бүртгэнэ. Нийт онооноос хамаарч 3 түвшинд ангилна:

    Онооны нийлбэр  ≥ 5  → Өндөр (HIGH)
    Онооны нийлбэр 2..4 → Дунд (MEDIUM)
    Онооны нийлбэр  < 2  → Хэвийн (NORMAL)

Энэ нь forensic шинжээчид тогтмол, давтагдах, тайлбарлах боломжтой үнэлгээ өгөх
зорилготой (subjective биш).
"""
from __future__ import annotations

import mimetypes
import os
from dataclasses import dataclass, field
from datetime import datetime

from app.models import Finding, FindingType, Severity, TimelineEvent
from app.services import tools

# --------------------------------------------------------------------------- #
# Эрсдэлийн шалгуурын тогтмолууд
# --------------------------------------------------------------------------- #
# Эмзэг түлхүүр үг (нэр/замд) — нууц мэдээлэлтэй холбоотой.
_SENSITIVE_KEYWORDS = (
    "password", "passwd", "secret", "confidential", "leak", "private",
    "credential", "token", "dump", "backup", "нууц", "data_breach",
)
# Эмзэг өргөтгөл (баримт, мэдээллийн сан, түлхүүр).
_SENSITIVE_EXT = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv",
    "sql", "db", "sqlite", "mdb", "pst", "ost",
    "pem", "key", "p12", "pfx", "kdbx",
}
# Шифрлэгдсэн / архив (мэдээлэл нуух боломжтой).
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "gpg", "enc", "kdbx"}
# Гүйцэтгэх / скрипт файл.
_EXECUTABLE_EXT = {"exe", "dll", "bat", "cmd", "ps1", "sh", "scr", "vbs", "js"}

# Threshold-ууд.
_HIGH_THRESHOLD = 5
_MEDIUM_THRESHOLD = 2


@dataclass
class RiskAssessment:
    severity: Severity
    score: int
    reasons: list[str] = field(default_factory=list)


def guess_mime(path: str, file_name: str = "") -> str:
    """MIME төрлийг `file` команд эсвэл өргөтгөлөөр тодорхойлно."""
    if path and os.path.exists(path) and tools.is_available("file"):
        result = tools.run(["file", "--brief", "--mime-type", path])
        if result.ok and result.stdout.strip():
            return result.stdout.strip()
    name = file_name or path
    mime, _ = mimetypes.guess_type(name)
    return mime or "application/octet-stream"


def assess_risk(
    *,
    finding_type: FindingType,
    file_name: str,
    original_path: str = "",
    recovered: bool = False,
) -> RiskAssessment:
    """Дүрэмд суурилсан эрсдэлийн үнэлгээ (оноо + шалтгаан + түвшин).

    Шалгуур бүр тодорхой оноо нэмж, монгол хэлээр тайлбар үлдээнэ.
    """
    text = f"{file_name} {original_path}".lower()
    ext = os.path.splitext(file_name)[1].lstrip(".").lower()
    score = 0
    reasons: list[str] = []

    # 1. Эмзэг түлхүүр үг — хамгийн өндөр жинтэй.
    matched_kw = [kw for kw in _SENSITIVE_KEYWORDS if kw in text]
    if matched_kw:
        score += 5
        reasons.append(f"Нэр/замд эмзэг түлхүүр үг илэрсэн: '{', '.join(matched_kw[:3])}' (+5)")

    # 2. Эмзэг өргөтгөл (баримт / мэдээллийн сан / түлхүүр).
    if ext in _SENSITIVE_EXT:
        score += 3
        reasons.append(f"Эмзэг төрлийн файл (.{ext}) — баримт/мэдээллийн сан/түлхүүр (+3)")

    # 3. Шифрлэгдсэн / архив (агуулга нуух боломжтой).
    if ext in _ARCHIVE_EXT:
        score += 2
        reasons.append(f"Архив/шифрлэгдсэн формат (.{ext}) — мэдээлэл нуусан байж болзошгүй (+2)")

    # 4. Гүйцэтгэх / скрипт файл.
    if ext in _EXECUTABLE_EXT:
        score += 2
        reasons.append(f"Гүйцэтгэх/скрипт файл (.{ext}) — хортой програм байж болзошгүй (+2)")

    # 5. Илрүүлэлтийн төрлөөс хамаарсан context.
    if finding_type == FindingType.DELETED_FILE:
        score += 1
        reasons.append("Файлын системээс устгагдсан — устгах санаатай үйлдэл (+1)")
    elif finding_type == FindingType.CARVED_FILE:
        score += 2
        reasons.append("File-system бүртгэлгүй carving (unallocated)-аас сэргээгдсэн — идэвхтэй устгасан/нуусан ул мөр (+2)")
    elif finding_type == FindingType.RECYCLE_ARTIFACT:
        score += 1
        reasons.append("Recycle Bin / Trash-д устгагдсан артефакт (+1)")
    elif finding_type == FindingType.SLACK_SPACE:
        score += 1
        reasons.append("Slack/unallocated space-аас үлдэгдэл текст илэрсэн (+1)")

    # 6. Амжилттай сэргээгдсэн — бодит нотлох баримт болох боломжтой.
    if recovered:
        score += 1
        reasons.append("Агуулга нь амжилттай сэргээгдсэн — бодит нотлох баримт (+1)")

    # Түвшин тогтоох.
    if score >= _HIGH_THRESHOLD:
        severity = Severity.HIGH
    elif score >= _MEDIUM_THRESHOLD:
        severity = Severity.MEDIUM
    else:
        severity = Severity.NORMAL

    if not reasons:
        reasons.append("Эмзэг шинж тэмдэг олдсонгүй — хэвийн")

    return RiskAssessment(severity=severity, score=score, reasons=reasons)


# Дүрмийн жагсаалт (UI/тайланд шалгуурыг харуулах зорилгоор).
RISK_RULES = [
    {"rule": "Эмзэг түлхүүр үг (password, secret, нууц г.м.)", "points": 5},
    {"rule": "Эмзэг өргөтгөл (docx, xlsx, pdf, db, pem, key г.м.)", "points": 3},
    {"rule": "Архив/шифрлэгдсэн формат (zip, rar, 7z, kdbx, gpg)", "points": 2},
    {"rule": "Гүйцэтгэх/скрипт файл (exe, dll, ps1, sh г.м.)", "points": 2},
    {"rule": "Carving (unallocated)-аас сэргээгдсэн", "points": 2},
    {"rule": "Устгагдсан файл / Recycle / Slack", "points": 1},
    {"rule": "Агуулга амжилттай сэргээгдсэн", "points": 1},
]


def build_timeline_events(finding: Finding) -> list[TimelineEvent]:
    """Finding-ийн MAC timestamp бүрээс timeline үйл явдал үүсгэнэ."""
    events: list[TimelineEvent] = []
    mapping: list[tuple[datetime | None, str, str]] = [
        (finding.crtime, "B", "Created (үүсгэсэн)"),
        (finding.mtime, "M", "Modified (өөрчилсөн)"),
        (finding.atime, "A", "Accessed (нээсэн)"),
        (finding.ctime, "C", "Changed (MFT Entry өөрчлөгдсөн)"),
    ]
    label = finding.file_name or finding.original_path or finding.inode
    mft = (finding.meta or {}).get("mft_entry")
    mft_note = f" [MFT #{mft}]" if mft is not None else ""
    for ts, kind, desc in mapping:
        if ts is None:
            continue
        events.append(
            TimelineEvent(
                scan_id=finding.scan_id,
                timestamp=ts,
                event_type=kind,
                description=f"{desc}: {label}{mft_note}",
            )
        )
    return events


def enrich_filesystem_meta(finding: Finding, fs_type: str = "") -> dict:
    """Finding.meta-д filesystem түвшний metadata нэмнэ."""
    from app.services.fat_metadata import annotate_deleted_fat32, slack_space_info
    from app.services.ntfs_artifacts import mft_entry_from_inode

    meta = dict(finding.meta or {})
    mft = mft_entry_from_inode(finding.inode)
    if mft is not None:
        meta["mft_entry"] = mft

    meta["filesystem_timestamps"] = {
        "created": finding.crtime.isoformat() if finding.crtime else None,
        "modified": finding.mtime.isoformat() if finding.mtime else None,
        "accessed": finding.atime.isoformat() if finding.atime else None,
        "changed": finding.ctime.isoformat() if finding.ctime else None,
    }

    if finding.finding_type == FindingType.DELETED_FILE:
        meta = annotate_deleted_fat32(meta, fs_type, is_deleted=True)
    elif finding.finding_type == FindingType.SLACK_SPACE:
        samples = meta.get("sample_strings")
        meta = {**meta, **slack_space_info(finding.finding_type, samples if isinstance(samples, list) else None)}

    return meta


def apply_exiftool_meta(finding: Finding, path: str = "") -> None:
    """Файлын ExifTool metadata олборлоно (path байхгүй бол нэрээр mock)."""
    from app.services.exiftool import extract, to_meta_dict

    target = path if path and os.path.isfile(path) else ""
    extracted = extract(target, finding.file_name)
    if extracted.available or extracted.tool.endswith("mock"):
        finding.meta = {**(finding.meta or {}), **to_meta_dict(extracted)}


def build_forensic_timeline(
    scan_id: int,
    *,
    audit_events: list | None = None,
    usn_events: list | None = None,
) -> list[TimelineEvent]:
    """Audit + USN journal-ийг forensic timeline-д нэмнэ."""
    from app.services.ntfs_artifacts import UsnEvent

    events: list[TimelineEvent] = []

    audit_labels = {
        "device_connected": "USB залгагдсан",
        "device_disconnected": "USB салгагдсан",
        "scan_started": "Шинжилгээ эхэлсэн",
        "scan_completed": "Шинжилгээ дууссан",
    }

    for log in audit_events or []:
        ts = getattr(log, "timestamp", None)
        action = getattr(log, "action", "")
        target = getattr(log, "target", "")
        if ts is None:
            continue
        label = audit_labels.get(action, action)
        events.append(
            TimelineEvent(
                scan_id=scan_id,
                timestamp=ts,
                event_type="SYS",
                description=f"[{label}] {target}",
            )
        )

    for usn in usn_events or []:
        if not isinstance(usn, UsnEvent):
            continue
        path = usn.full_path or usn.file_name
        events.append(
            TimelineEvent(
                scan_id=scan_id,
                timestamp=usn.timestamp,
                event_type="USN",
                description=f"{usn.reason_label}: {path}",
            )
        )

    return events
