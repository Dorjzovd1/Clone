"""FAT32 flash drive түвшний metadata — устгасан файлын үлдэгдэл, slack space."""

from __future__ import annotations

from app.models import FindingType


def annotate_deleted_fat32(finding_meta: dict, fs_type: str, is_deleted: bool) -> dict:
    """FAT32 дээр устгасан файлын forensic тайлбар нэмнэ."""
    fs = (fs_type or "").lower()
    if not is_deleted or "fat" not in fs:
        return finding_meta

    return {
        **finding_meta,
        "fat32": {
            "deleted_marker": "0xE5",
            "deleted_marker_desc": "Файлын нэрний эхний тэмдэгт 0xE5 болсон (deleted)",
            "cluster_status": "free",
            "cluster_status_desc": "Cluster-үүд 'чөлөөт' гэж тэмдэглэгдсэн",
            "data_remainder": True,
            "data_remainder_desc": "Өгөгдөл физикийн хувьд cluster-д үлдсэн — forensic сэргээлт боломжтой",
            "recovery_tool": "TSK fls/icat, PhotoRec, Foremost",
        },
    }


def slack_space_info(finding_type: FindingType, sample_strings: list | None = None) -> dict:
    """Slack space forensic тайлбар."""
    if finding_type != FindingType.SLACK_SPACE:
        return {}
    return {
        "slack_space": {
            "description": "Cluster-ийг бүрэн дүүргэхгүй үлдсэн хэсэг (slack)",
            "risk": "Өмнөх файлын өгөгдөл slack-д үлдсэн байж болно",
            "sample_count": len(sample_strings or []),
            "forensic_note": "Unallocated/slack space-аас string эсвэл carving-аар уншиж болно",
        },
    }
