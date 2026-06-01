"""NTFS forensic артефакт — $MFT, $LogFile, $UsnJrnl, $I30, MFT Entry.

NTFS файлын системийн системийн файлууд болон USN Journal нь
устгасан файлын үйлдлийг ч бүртгэдэг тул forensic timeline-д чухал.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.ntfs")
settings = get_settings()

NTFS_SYSTEM_FILES = {
    "$MFT": {
        "name": "$MFT",
        "description": "Master File Table — бүх файлын бүртгэл",
        "importance": "critical",
    },
    "$LogFile": {
        "name": "$LogFile",
        "description": "Файлын системийн өөрчлөлтийн лог (transaction log)",
        "importance": "high",
    },
    "$UsnJrnl": {
        "name": "$UsnJrnl",
        "description": "USN Journal — файл үүсгэх/устгах/нэр өөрчлөх бүртгэл",
        "importance": "critical",
    },
    "$I30": {
        "name": "$I30",
        "description": "Директорийн индекс ($I30 INDEX)",
        "importance": "medium",
    },
    "$Bitmap": {
        "name": "$Bitmap",
        "description": "Cluster allocation bitmap",
        "importance": "low",
    },
    "$Secure": {
        "name": "$Secure",
        "description": "Security descriptors",
        "importance": "low",
    },
}

USN_REASONS = {
    "FILE_CREATE": "Файл үүсгэсэн",
    "DATA_OVERWRITE": "Өгөгдөл бичсэн",
    "DATA_EXTEND": "Өгөгдөл өргөтгөсөн",
    "DATA_TRUNCATION": "Өгөгдөл тасалсан",
    "RENAME_OLD_NAME": "Хуучин нэр",
    "RENAME_NEW_NAME": "Шинэ нэр",
    "FILE_DELETE": "Файл устгасан",
    "CLOSE": "Файл хаасан",
}


@dataclass
class NtfsArtifact:
    name: str
    path: str
    inode: str
    mft_entry: int | None
    size_bytes: int
    description: str
    importance: str
    meta: dict = field(default_factory=dict)


@dataclass
class UsnEvent:
    timestamp: datetime
    file_name: str
    full_path: str
    reason: str
    reason_label: str
    mft_entry: int | None = None
    meta: dict = field(default_factory=dict)


def mft_entry_from_inode(inode: str) -> int | None:
    """TSK NTFS inode-оос MFT Entry дугаар гаргана (жишээ: 16-128-1 → 16)."""
    if not inode:
        return None
    m = re.match(r"^(\d+)", str(inode))
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def detect_system_files(entries: list) -> list[NtfsArtifact]:
    """File listing-ээс NTFS системийн файлуудыг илрүүлнэ."""
    artifacts: list[NtfsArtifact] = []
    seen: set[str] = set()

    for entry in entries:
        path = getattr(entry, "name", "") or ""
        base = path.rstrip("/").split("/")[-1].upper()
        for key, info in NTFS_SYSTEM_FILES.items():
            if key.upper() in base or base == key.upper().replace("$", ""):
                if key in seen:
                    continue
                seen.add(key)
                inode = getattr(entry, "inode", "")
                artifacts.append(
                    NtfsArtifact(
                        name=info["name"],
                        path=path if path.startswith("/") else f"/{path}",
                        inode=inode,
                        mft_entry=mft_entry_from_inode(inode),
                        size_bytes=getattr(entry, "size", 0),
                        description=info["description"],
                        importance=info["importance"],
                        meta={"ntfs_system_file": True},
                    )
                )
    return artifacts


def mock_system_files() -> list[NtfsArtifact]:
    """Mock NTFS системийн файлууд."""
    return [
        NtfsArtifact(
            name="$MFT",
            path="/$MFT",
            inode="0-128-1",
            mft_entry=0,
            size_bytes=262144,
            description=NTFS_SYSTEM_FILES["$MFT"]["description"],
            importance="critical",
            meta={"mock": True},
        ),
        NtfsArtifact(
            name="$LogFile",
            path="/$LogFile",
            inode="2-128-1",
            mft_entry=2,
            size_bytes=67108864,
            description=NTFS_SYSTEM_FILES["$LogFile"]["description"],
            importance="high",
            meta={"mock": True},
        ),
        NtfsArtifact(
            name="$UsnJrnl",
            path="/$Extend/$UsnJrnl:$J",
            inode="11-128-1",
            mft_entry=11,
            size_bytes=33554432,
            description=NTFS_SYSTEM_FILES["$UsnJrnl"]["description"],
            importance="critical",
            meta={"mock": True},
        ),
        NtfsArtifact(
            name="$I30",
            path="/$I30 (directory index)",
            inode="5-128-1",
            mft_entry=5,
            size_bytes=0,
            description=NTFS_SYSTEM_FILES["$I30"]["description"],
            importance="medium",
            meta={"mock": True, "note": "Directory index entries"},
        ),
    ]


def read_usn_journal(source_path: str, fs_type: str = "ntfs") -> list[UsnEvent]:
    """USN Journal унших — Windows fsutil эсвэл mock."""
    if "ntfs" not in (fs_type or "").lower():
        return []

    # Windows: fsutil usn readjournal
    if tools.is_available("fsutil"):
        return _read_usn_fsutil(source_path)

    if settings.allow_mock:
        return _mock_usn_events()

    return []


def _read_usn_fsutil(drive: str) -> list[UsnEvent]:
    """Windows fsutil usn readjournal csv гаралт."""
    events: list[UsnEvent] = []
    try:
        result = tools.run(["fsutil", "usn", "readjournal", drive, "csv"], timeout=60)
        if not result.ok:
            return _mock_usn_events()
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(",")
            if len(parts) < 4:
                continue
            # CSV format varies; best-effort parse
            try:
                ts = datetime.fromisoformat(parts[0].strip('"'))
            except ValueError:
                ts = datetime.now(timezone.utc)
            events.append(
                UsnEvent(
                    timestamp=ts,
                    file_name=parts[1].strip('"') if len(parts) > 1 else "",
                    full_path=parts[2].strip('"') if len(parts) > 2 else "",
                    reason=parts[3].strip('"') if len(parts) > 3 else "UNKNOWN",
                    reason_label=USN_REASONS.get(parts[3].strip('"'), parts[3].strip('"')),
                )
            )
    except tools.ToolNotFoundError:
        return _mock_usn_events()
    return events or _mock_usn_events()


def _mock_usn_events() -> list[UsnEvent]:
    """Forensic timeline demo — USN Journal үйлдлүүд."""
    base = datetime(2024, 1, 15, 9, 23, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    return [
        UsnEvent(
            timestamp=base,
            file_name="",
            full_path="\\",
            reason="VOLUME_CHANGE",
            reason_label="Том хэмжээний өөрчлөлт",
            meta={"mock": True},
        ),
        UsnEvent(
            timestamp=base + timedelta(seconds=45),
            file_name="report.docx",
            full_path="/Documents/report.docx",
            reason="FILE_CREATE",
            reason_label=USN_REASONS["FILE_CREATE"],
            mft_entry=128,
            meta={"mock": True},
        ),
        UsnEvent(
            timestamp=base + timedelta(minutes=1, seconds=12),
            file_name="budget.xlsx",
            full_path="/Documents/budget.xlsx",
            reason="RENAME_NEW_NAME",
            reason_label="Файл нэр өөрчлөгдсөн / нээгдсэн",
            mft_entry=129,
            meta={"mock": True},
        ),
        UsnEvent(
            timestamp=base + timedelta(minutes=2, seconds=21),
            file_name="secret_plan.docx",
            full_path="/secret_plan.docx",
            reason="FILE_DELETE",
            reason_label=USN_REASONS["FILE_DELETE"],
            mft_entry=130,
            meta={"mock": True},
        ),
    ]
