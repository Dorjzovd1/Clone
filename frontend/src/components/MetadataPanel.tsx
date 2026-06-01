import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Finding, FindingMetadata } from "../api/types";
import { formatBytes, formatDate } from "../lib/format";

interface Props {
  finding: Finding;
}

export default function MetadataPanel({ finding }: Props) {
  const [detail, setDetail] = useState<FindingMetadata | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .findingMetadata(finding.id)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [finding.id]);

  if (loading) return <div className="empty sm">Metadata ачаалж байна…</div>;
  if (!detail) return <div className="empty sm">Metadata олдсонгүй.</div>;

  const doc = detail.document ?? {};
  const exif = detail.exif ?? {};
  const fs = detail.filesystem ?? {};

  return (
    <div className="metadata-panel">
      <section className="meta-section">
        <h3>1. Файлын системийн metadata</h3>
        <table className="meta-table">
          <tbody>
            <tr><td>Created (үүсгэсэн)</td><td>{formatDate(fs.created ?? null)}</td></tr>
            <tr><td>Modified (өөрчилсөн)</td><td>{formatDate(fs.modified ?? null)}</td></tr>
            <tr><td>Accessed (нээсэн)</td><td>{formatDate(fs.accessed ?? null)}</td></tr>
            <tr><td>Changed (MFT)</td><td>{formatDate(fs.changed ?? null)}</td></tr>
            <tr><td>MFT Entry</td><td className="mono">{fs.mft_entry ?? "—"}</td></tr>
            <tr><td>Inode</td><td className="mono">{fs.inode || "—"}</td></tr>
            <tr><td>Хэмжээ</td><td>{formatBytes(fs.size_bytes ?? 0)}</td></tr>
            <tr><td>MIME</td><td>{fs.mime_type || "—"}</td></tr>
          </tbody>
        </table>
      </section>

      {detail.ntfs_system && (
        <section className="meta-section">
          <h3>NTFS системийн файл</h3>
          <table className="meta-table">
            <tbody>
              <tr><td>Артефакт</td><td className="mono">{detail.ntfs_system.artifact}</td></tr>
              <tr><td>Тайлбар</td><td>{detail.ntfs_system.description}</td></tr>
              <tr><td>Ач холбогдол</td><td><span className={`badge importance-${detail.ntfs_system.importance}`}>{detail.ntfs_system.importance}</span></td></tr>
            </tbody>
          </table>
          <p className="meta-note">$MFT — бүх файлын бүртгэл · $LogFile — FS өөрчлөлт · $UsnJrnl — устгасан файл ч бүртгэгддэг · $I30 — директорийн индекс</p>
        </section>
      )}

      {detail.fat32 && (
        <section className="meta-section">
          <h3>FAT32 — устгасан файлын үлдэгдэл</h3>
          <table className="meta-table">
            <tbody>
              <tr><td>Deleted marker</td><td className="mono">{detail.fat32.deleted_marker}</td></tr>
              <tr><td>Cluster статус</td><td>{detail.fat32.cluster_status_desc}</td></tr>
              <tr><td>Өгөгдөл үлдсэн</td><td>{detail.fat32.data_remainder ? "Тийм — forensic сэргээлт боломжтой" : "Үгүй"}</td></tr>
            </tbody>
          </table>
        </section>
      )}

      {detail.slack_space && (
        <section className="meta-section">
          <h3>Slack Space</h3>
          <p className="meta-note">{detail.slack_space.description}. {detail.slack_space.risk}</p>
        </section>
      )}

      {Object.keys(doc).length > 0 && (
        <section className="meta-section">
          <h3>2. Баримт бичгийн metadata (Word/Excel/PDF)</h3>
          <table className="meta-table">
            <tbody>
              {doc.author && <tr><td>Зохиогч (Author)</td><td>{doc.author}</td></tr>}
              {doc.company && <tr><td>Компани</td><td>{doc.company}</td></tr>}
              {doc.last_modified_by && <tr><td>Сүүлд засварласан</td><td>{doc.last_modified_by}</td></tr>}
              {doc.revision_count && <tr><td>Засварласан тоо</td><td>{doc.revision_count}</td></tr>}
              {doc.created && <tr><td>Анх үүсгэсэн</td><td>{doc.created}</td></tr>}
              {doc.modified && <tr><td>Өөрчилсөн</td><td>{doc.modified}</td></tr>}
              {doc.template && <tr><td>Template</td><td className="mono">{doc.template}</td></tr>}
              {doc.title && <tr><td>Гарчиг</td><td>{doc.title}</td></tr>}
            </tbody>
          </table>
        </section>
      )}

      {Object.keys(exif).length > 0 && (
        <section className="meta-section">
          <h3>Зургийн EXIF metadata</h3>
          <table className="meta-table">
            <tbody>
              {exif.camera_make && <tr><td>Камерын брэнд</td><td>{exif.camera_make}</td></tr>}
              {exif.camera_model && <tr><td>Загвар</td><td>{exif.camera_model}</td></tr>}
              {exif.datetime_original && <tr><td>Зураг авсан цаг</td><td>{exif.datetime_original}</td></tr>}
              {exif.gps && <tr><td>GPS байршил</td><td className="mono">{exif.gps}</td></tr>}
              {exif.iso && <tr><td>ISO</td><td>{exif.iso}</td></tr>}
              {exif.aperture && <tr><td>Aperture</td><td>{exif.aperture}</td></tr>}
              {exif.shutter_speed && <tr><td>Shutter</td><td>{exif.shutter_speed}</td></tr>}
              {exif.focal_length && <tr><td>Focal length</td><td>{exif.focal_length}</td></tr>}
            </tbody>
          </table>
        </section>
      )}

      {detail.usn && (
        <section className="meta-section">
          <h3>USN Journal үйлдэл</h3>
          <table className="meta-table">
            <tbody>
              <tr><td>Шалтгаан</td><td>{detail.usn.reason_label}</td></tr>
              <tr><td>Код</td><td className="mono">{detail.usn.reason}</td></tr>
            </tbody>
          </table>
        </section>
      )}

      <div className="meta-footer">
        ExifTool: {detail.exiftool_available ? "бэлэн" : "mock/demo горим"}
      </div>
    </div>
  );
}
