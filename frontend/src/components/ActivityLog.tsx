import type { AuditLog } from "../api/types";
import { auditActionLabel } from "./audit";
import { formatDate } from "./format";

export default function ActivityLog({ logs }: { logs: AuditLog[] }) {
  if (logs.length === 0) {
    return (
      <div className="empty">
        Үйлдлийн бүртгэл хоосон. Linux дээр USB/SD залгаж, шинжилгээ хийсний дараа энд харагдана.
      </div>
    );
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Цаг</th>
          <th>Үйлдэл</th>
          <th>Объект</th>
          <th>Дэлгэрэнгүй</th>
        </tr>
      </thead>
      <tbody>
        {logs.map((a) => (
          <tr key={a.id}>
            <td className="mono">{formatDate(a.timestamp)}</td>
            <td>
              <span className={`audit-action audit-${a.action}`}>{auditActionLabel(a.action)}</span>
            </td>
            <td className="mono">{a.target || "—"}</td>
            <td style={{ fontSize: 12, color: "var(--text-dim)" }}>
              {detailSummary(a)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function detailSummary(a: AuditLog): string {
  const d = a.detail ?? {};
  if (a.action === "scan_completed" && typeof d.findings === "number") {
    return `${d.findings} ул мөр`;
  }
  if (a.action === "scan_started" && d.scan_id) {
    return `scan #${d.scan_id}`;
  }
  if (d.hotplug_action) {
    return String(d.hotplug_action);
  }
  return Object.keys(d).length ? JSON.stringify(d) : "—";
}
