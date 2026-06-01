"""Metadata API — файлын forensic metadata, NTFS артефакт, CSV export."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, FindingType, ScanJob, TimelineEvent
from app.schemas import FindingOut, TimelineEventOut
from app.services import ntfs_artifacts
from app.services.exiftool import exiftool_available

router = APIRouter(prefix="/api", tags=["metadata"])


@router.get("/findings/{finding_id}/metadata")
def finding_metadata(finding_id: int, db: Session = Depends(get_db)) -> dict:
    """Файлын бүрэн forensic metadata (filesystem + ExifTool + FAT32)."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")

    meta = finding.meta or {}
    exif_block = meta.get("exiftool", {})
    return {
        "finding_id": finding.id,
        "file_name": finding.file_name,
        "original_path": finding.original_path,
        "finding_type": finding.finding_type.value,
        "filesystem": {
            "created": finding.crtime,
            "modified": finding.mtime,
            "accessed": finding.atime,
            "changed": finding.ctime,
            "mft_entry": meta.get("mft_entry"),
            "inode": finding.inode,
            "size_bytes": finding.size_bytes,
            "mime_type": finding.mime_type,
        },
        "ntfs_system": {
            "artifact": meta.get("ntfs_artifact"),
            "description": meta.get("description"),
            "importance": meta.get("importance"),
        } if finding.finding_type == FindingType.NTFS_ARTIFACT else None,
        "fat32": meta.get("fat32"),
        "slack_space": meta.get("slack_space"),
        "document": exif_block.get("document", {}),
        "exif": exif_block.get("exif", {}),
        "exiftool_available": exiftool_available(),
        "usn": {
            "reason": meta.get("usn_reason"),
            "reason_label": meta.get("usn_reason_label"),
        } if finding.finding_type == FindingType.USN_EVENT else None,
        "raw_meta": meta,
    }


@router.get("/scans/{scan_id}/ntfs-artifacts", response_model=list[FindingOut])
def scan_ntfs_artifacts(scan_id: int, db: Session = Depends(get_db)) -> list[Finding]:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")
    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.finding_type == FindingType.NTFS_ARTIFACT)
        .all()
    )


@router.get("/scans/{scan_id}/usn-events", response_model=list[FindingOut])
def scan_usn_events(scan_id: int, db: Session = Depends(get_db)) -> list[Finding]:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")
    return (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.finding_type == FindingType.USN_EVENT)
        .all()
    )


@router.get("/scans/{scan_id}/forensic-timeline", response_model=list[TimelineEventOut])
def forensic_timeline(scan_id: int, db: Session = Depends(get_db)) -> list[TimelineEvent]:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")
    return (
        db.query(TimelineEvent)
        .filter(TimelineEvent.scan_id == scan_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )


@router.get("/scans/{scan_id}/metadata/csv")
def metadata_csv_export(scan_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    """ExifTool-style CSV — бүх файлын metadata."""
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.finding_type.in_([
                FindingType.EXISTING_FILE,
                FindingType.DELETED_FILE,
                FindingType.CARVED_FILE,
                FindingType.RECYCLE_ARTIFACT,
            ]),
        )
        .all()
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "FileName", "Path", "Type", "MFT_Entry", "Created", "Modified", "Accessed",
        "Author", "Company", "LastModifiedBy", "Revision", "Template",
        "CameraMake", "CameraModel", "GPS", "ISO", "SourceTool",
    ])

    for f in findings:
        meta = f.meta or {}
        doc = (meta.get("exiftool") or {}).get("document", {})
        exif = (meta.get("exiftool") or {}).get("exif", {})
        writer.writerow([
            f.file_name,
            f.original_path,
            f.finding_type.value,
            meta.get("mft_entry", ""),
            f.crtime.isoformat() if f.crtime else "",
            f.mtime.isoformat() if f.mtime else "",
            f.atime.isoformat() if f.atime else "",
            doc.get("author", ""),
            doc.get("company", ""),
            doc.get("last_modified_by", ""),
            doc.get("revision_count", ""),
            doc.get("template", ""),
            exif.get("camera_make", ""),
            exif.get("camera_model", ""),
            exif.get("gps", ""),
            exif.get("iso", ""),
            f.source_tool,
        ])

    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}_metadata.csv"'},
    )


@router.get("/forensic/tools")
def forensic_tools_status() -> dict:
    """Шинжлэх хэрэгслүүдийн төлөв."""
    from app.config import get_settings
    from app.services import tools

    settings = get_settings()
    usn_available = tools.is_available("fsutil") or settings.allow_mock
    return {
        "tools": [
            {"name": "ExifTool", "id": "exiftool", "role": "Бүх файлын metadata", "available": exiftool_available()},
            {"name": "The Sleuth Kit (fls/icat)", "id": "tsk", "role": "Файлын системийн metadata, устгагдсан файл", "available": True},
            {"name": "Metadata Interrogator", "id": "metadata_interrogator", "role": "Document metadata (ExifTool-оор)", "available": exiftool_available()},
            {"name": "FOCA-style extraction", "id": "foca", "role": "Автомат metadata олборлолт", "available": exiftool_available()},
            {"name": "USN Journal (fsutil)", "id": "usn", "role": "NTFS $UsnJrnl — устгасан файл ч бүртгэгддэг", "available": usn_available},
        ],
        "ntfs_artifacts": list(ntfs_artifacts.NTFS_SYSTEM_FILES.keys()),
    }
