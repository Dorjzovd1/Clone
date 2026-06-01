import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ForensicToolInfo } from "../api/types";

export default function ForensicToolsPanel() {
  const [tools, setTools] = useState<ForensicToolInfo[]>([]);
  const [ntfsArtifacts, setNtfsArtifacts] = useState<string[]>([]);

  useEffect(() => {
    api.forensicTools().then((r) => {
      setTools(r.tools);
      setNtfsArtifacts(r.ntfs_artifacts);
    });
  }, []);

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Шинжлэх хэрэгслүүд</h3>
      <table>
        <thead>
          <tr>
            <th>Хэрэгсэл</th>
            <th>Төрөл</th>
            <th>Төлөв</th>
          </tr>
        </thead>
        <tbody>
          {tools.map((t) => (
            <tr key={t.id}>
              <td><strong>{t.name}</strong></td>
              <td>{t.role}</td>
              <td>
                <span className={`badge ${t.available ? "sev-normal" : "sev-medium"}`}>
                  {t.available ? "Бэлэн" : "Mock/Demo"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>NTFS системийн файлууд</h3>
      <div className="ntfs-grid">
        {ntfsArtifacts.map((a) => (
          <div key={a} className="ntfs-card">
            <code>{a}</code>
          </div>
        ))}
      </div>

      <h3>Metadata-с олж болох мэдээлэл</h3>
      <table className="meta-table">
        <thead>
          <tr><th>Metadata</th><th>Ямар зүйл илчлэгддэг</th></tr>
        </thead>
        <tbody>
          <tr><td>Author field</td><td>Файл үүсгэсэн хүний нэр</td></tr>
          <tr><td>Company field</td><td>Байгууллагын нэр</td></tr>
          <tr><td>Template path</td><td>Компьютерийн username, path</td></tr>
          <tr><td>Created/Modified</td><td>Үйл явдлын цаг</td></tr>
          <tr><td>Revision count</td><td>Хэдэн удаа засварласан</td></tr>
          <tr><td>GPS data</td><td>Байршил</td></tr>
          <tr><td>Camera model</td><td>Ямар төхөөрөмжөөр авсан</td></tr>
        </tbody>
      </table>

      <h3>ExifTool практик</h3>
      <pre className="code-block">{`# Нэг файлын metadata
exiftool filename.docx

# Бүх файлын metadata CSV
exiftool -csv /media/usb/* > usb_metadata.csv

# GPS мэдээлэл
exiftool -GPS* photo.jpg`}</pre>
    </div>
  );
}
