"""ExifTool wrapper — файлын дотоод metadata (Word/Excel/PDF/EXIF).

Практик forensic шинжилгээнд ExifTool-ийг бүх төрлийн файлын
metadata олборлоход ашиглана. Хэрэгсэл байхгүй үед mock өгөгдөл буцаана.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.exiftool")
settings = get_settings()

# Document metadata keys (Office / PDF)
_DOC_KEYS = {
    "author": ("Author", "Creator", "LastAuthor"),
    "company": ("Company", "Organization"),
    "last_modified_by": ("LastModifiedBy", "Modifier"),
    "revision_count": ("RevisionNumber", "RevNumber"),
    "created": ("CreateDate", "CreationDate", "DateCreated"),
    "modified": ("ModifyDate", "LastModified", "DateModified"),
    "template": ("Template", "TemplateName"),
    "title": ("Title",),
    "subject": ("Subject",),
    "keywords": ("Keywords",),
}

# EXIF / image keys
_EXIF_KEYS = {
    "camera_make": ("Make",),
    "camera_model": ("Model", "CameraModelName"),
    "datetime_original": ("DateTimeOriginal", "CreateDate"),
    "iso": ("ISO", "ISOSpeedRatings"),
    "aperture": ("FNumber", "ApertureValue"),
    "shutter_speed": ("ShutterSpeed", "ExposureTime"),
    "focal_length": ("FocalLength",),
    "gps_latitude": ("GPSLatitude",),
    "gps_longitude": ("GPSLongitude",),
    "gps_altitude": ("GPSAltitude",),
    "software": ("Software", "ProcessingSoftware"),
}


@dataclass
class ExtractedMetadata:
    raw: dict = field(default_factory=dict)
    document: dict = field(default_factory=dict)
    exif: dict = field(default_factory=dict)
    other: dict = field(default_factory=dict)
    tool: str = "exiftool"
    available: bool = True


def exiftool_available() -> bool:
    return tools.is_available("exiftool")


def _first(raw: dict, keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = raw.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


def _classify(raw: dict) -> ExtractedMetadata:
    doc: dict = {}
    for field_name, keys in _DOC_KEYS.items():
        val = _first(raw, keys)
        if val:
            doc[field_name] = val

    exif: dict = {}
    for field_name, keys in _EXIF_KEYS.items():
        val = _first(raw, keys)
        if val:
            exif[field_name] = val

    if exif.get("gps_latitude") and exif.get("gps_longitude"):
        exif["gps"] = f"{exif['gps_latitude']}, {exif['gps_longitude']}"

    used = set()
    for keys in _DOC_KEYS.values():
        used.update(keys)
    for keys in _EXIF_KEYS.values():
        used.update(keys)

    other = {k: v for k, v in raw.items() if k not in used and v}

    return ExtractedMetadata(raw=raw, document=doc, exif=exif, other=other)


def extract(path: str, file_name: str = "") -> ExtractedMetadata:
    """Нэг файлын metadata ExifTool-оор олборлоно."""
    if not path or not os.path.isfile(path):
        return _mock_metadata(file_name or os.path.basename(path))

    if not exiftool_available():
        if settings.allow_mock:
            return _mock_metadata(file_name or os.path.basename(path))
        return ExtractedMetadata(available=False, tool="none")

    try:
        result = tools.run(
            ["exiftool", "-j", "-G1", "-charset", "utf8", path],
            timeout=120,
        )
        if not result.ok or not result.stdout.strip():
            logger.warning("exiftool алдаа: %s", result.stderr.strip())
            return ExtractedMetadata(available=False, tool="exiftool")

        data = json.loads(result.stdout)
        raw = data[0] if data else {}
        # -G1 prefix: "System:FileName" → flatten to last segment for lookup
        flat: dict = {}
        for k, v in raw.items():
            short = k.split(":")[-1] if ":" in k else k
            flat[short] = v
            flat[k] = v
        meta = _classify(flat)
        meta.raw = flat
        return meta
    except (json.JSONDecodeError, tools.ToolNotFoundError) as exc:
        logger.warning("exiftool parse алдаа: %s", exc)
        if settings.allow_mock:
            return _mock_metadata(file_name or os.path.basename(path))
        return ExtractedMetadata(available=False, tool="exiftool")


def to_meta_dict(meta: ExtractedMetadata) -> dict:
    """Finding.meta-д хадгалах бүтэц."""
    return {
        "exiftool": {
            "available": meta.available,
            "tool": meta.tool,
            "document": meta.document,
            "exif": meta.exif,
            "other_count": len(meta.other),
            "raw_sample": dict(list(meta.raw.items())[:20]),
        }
    }


def _mock_metadata(file_name: str) -> ExtractedMetadata:
    """Dev/demo — файлын төрлөөр жишээ metadata."""
    lower = file_name.lower()
    raw: dict = {"FileName": file_name, "mock": True}

    if lower.endswith((".docx", ".doc")):
        raw.update(
            {
                "Author": "Б.Батбаяр",
                "Company": "Монгол Телеком",
                "LastModifiedBy": "С.Саран",
                "RevisionNumber": "4",
                "CreateDate": "2024-01-10 09:15:00",
                "ModifyDate": "2024-01-15 14:22:33",
                "Template": "Normal.dotm",
                "Title": "Тайлан",
            }
        )
    elif lower.endswith((".xlsx", ".xls")):
        raw.update(
            {
                "Author": "Д.Дорж",
                "Company": "Audit LLC",
                "LastModifiedBy": "Д.Дорж",
                "RevisionNumber": "7",
                "CreateDate": "2024-01-12 08:00:00",
                "ModifyDate": "2024-01-15 09:25:33",
                "Template": "Book.xltx",
            }
        )
    elif lower.endswith(".pdf"):
        raw.update(
            {
                "Author": "Forensic Lab",
                "Creator": "Microsoft Word",
                "CreateDate": "2024-01-14 11:00:00",
                "ModifyDate": "2024-01-14 11:05:00",
            }
        )
    elif lower.endswith((".jpg", ".jpeg", ".png", ".heic")):
        raw.update(
            {
                "Make": "Canon",
                "Model": "EOS 90D",
                "DateTimeOriginal": "2024-01-15 09:24:12",
                "ISO": "400",
                "FNumber": "2.8",
                "ExposureTime": "1/125",
                "FocalLength": "50mm",
                "GPSLatitude": "47.9184 N",
                "GPSLongitude": "106.9176 E",
            }
        )
    else:
        raw["Comment"] = "Metadata mock — ExifTool суулгаагүй эсвэл файл хоосон"

    meta = _classify(raw)
    meta.raw = raw
    meta.tool = "exiftool-mock"
    return meta
