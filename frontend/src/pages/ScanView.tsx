import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import type { AuditLog, Finding, Scan, TimelineEvent } from "../api/types";
import { useEvents } from "../lib/events";
import {
  formatBytes,
  formatDate,
  findingDisplayName,
  findingHasOriginalName,
  findingTypeLabel,
  shortHash,
  timelineKindLabel,
} from "../lib/format";
import ActivityLog from "../components/ActivityLog";
import MetadataPanel from "../components/MetadataPanel";
import ForensicToolsPanel from "../components/ForensicToolsPanel";

type Tab = "all" | "deleted" | "recovered" | "metadata" | "ntfs" | "usn" | "timeline" | "audit" | "tools";

export default function ScanView() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [tab, setTab] = useState<Tab>("all");
  const { subscribe } = useEvents();

  const [filters, setFilters] = useState({ severity: "", q: "" });

  const loadScan = async () => setScan(await api.getScan(id));
  const loadFindings = async () => {
    const params: Record<string, string | number | boolean> = { scan_id: id };
    if (tab === "all") params.category = "existing";
    else if (tab === "deleted") params.category = "deleted";
    else if (tab === "recovered") params.category = "recovered";
    else if (tab === "ntfs") params.finding_type = "ntfs_artifact";
    else if (tab === "usn") params.finding_type = "usn_event";
    if (filters.severity) params.severity = filters.severity;
    if (filters.q) params.q = filters.q;
    setFindings(await api.listFindings(params));
  };
  const loadTimeline = async () => setTimeline(await api.forensicTimeline(id));
  const loadAudit = async () => setAudit(await api.listAudit({ limit: 200 }));

  useEffect(() => {
    loadScan();
  }, [id]);

  useEffect(() => {
    if (tab === "timeline") loadTimeline();
    else if (tab === "audit") loadAudit();
    else if (tab === "tools") return;
    else if (tab === "metadata") {
      setFindings([]);
      loadFindings();
    } else loadFindings();
  }, [id, tab, filters]);

  useEffect(() => {
    return subscribe((ev) => {
      const sid = (ev.data as any)?.scan_id;
      if (sid !== id) return;
      if (ev.type === "scan_progress") {
        setScan((prev) =>
          prev
            ? { ...prev, progress: (ev.data as any).progress, current_step: (ev.data as any).step, status: (ev.data as any).status }
            : prev
        );
      }
      if (ev.type === "scan_completed" || ev.type === "scan_failed") {
        loadScan();
        loadFindings();
      }
    });
  }, [subscribe, id]);

  if (!scan) return <div className="empty">Ачаалж байна…</div>;

  const running = scan.status === "running" || scan.status === "pending";

  const tabs: { key: Tab; label: string }[] = [
    { key: "all", label: "Бүх файл" },
    { key: "deleted", label: "Устгагдсан" },
    { key: "recovered", label: "Сэргээгдсэн" },
    { key: "metadata", label: "Metadata" },
    { key: "ntfs", label: "NTFS ($MFT)" },
    { key: "usn", label: "$UsnJrnl" },
    { key: "timeline", label: "Forensic Timeline" },
    { key: "audit", label: "Үйлдлийн log" },
    { key: "tools", label: "Хэрэгслүүд" },
  ];

  return (
    <div>
      <h1 className="page-title">Шинжилгээ #{scan.id}</h1>
      <p className="page-sub">Forensic metadata стандарт — MAC timestamp · MFT · ExifTool · USN Journal · Timeline</p>

      <div className="panel">
        <div className="row-flex">
          <strong>Төлөв: {scan.status}</strong>
          <div className="spacer" />
          {running ? (
            <button className="btn danger sm" onClick={() => api.cancelScan(id).then(loadScan)}>
              Цуцлах
            </button>
          ) : (
            <div className="row-flex">
              <a className="btn sm" href={api.metadataCsvUrl(id)}>
                Metadata CSV
              </a>
              <a className="btn sm" href={api.reportPdfUrl(id)}>
                PDF тайлан
              </a>
              <a className="btn secondary sm" href={api.reportHtmlUrl(id)} target="_blank" rel="noreferrer">
                HTML тайлан
              </a>
            </div>
          )}
        </div>
        <div style={{ margin: "14px 0 6px" }} className="progress">
          <div className="progress-bar" style={{ width: `${scan.progress}%` }} />
        </div>
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
          {scan.progress.toFixed(0)}% · {scan.current_step || "—"}
        </div>
        {scan.error && <div style={{ color: "var(--red)", marginTop: 8 }}>{scan.error}</div>}
      </div>

      <div className="panel">
        <div className="row-flex" style={{ marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
          {tabs.map((t) => (
            <button key={t.key} className={`btn sm ${tab === t.key ? "" : "secondary"}`} onClick={() => setTab(t.key)}>
              {t.label}
            </button>
          ))}
        </div>

        {tab === "timeline" ? (
          <TimelineTab events={timeline} />
        ) : tab === "audit" ? (
          <ActivityLog logs={audit} />
        ) : tab === "tools" ? (
          <ForensicToolsPanel />
        ) : tab === "metadata" ? (
          <MetadataTab scanId={id} />
        ) : (
          <FindingsTab findings={findings} filters={filters} setFilters={setFilters} mode={tab} />
        )}
      </div>
    </div>
  );
}

function MetadataTab({ scanId }: { scanId: number }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    const params: Record<string, string | number> = { scan_id: scanId };
    if (q) params.q = q;
    api.listFindings(params).then(setFindings);
  }, [scanId, q]);

  const withMeta = findings.filter(
    (f) => f.finding_type !== "ntfs_artifact" && f.finding_type !== "usn_event" && f.finding_type !== "slack_space"
  );

  return (
    <div className="grid grid-2">
      <div>
        <input
          type="text"
          placeholder="Файл хайх…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ width: "100%", marginBottom: 12 }}
        />
        <div className="file-list-scroll">
          {withMeta.map((f) => (
            <button
              key={f.id}
              className={`file-list-item ${selected?.id === f.id ? "active" : ""}`}
              onClick={() => setSelected(f)}
            >
              <span className="mono">{findingDisplayName(f.original_path, f.file_name)}</span>
              <span className="type-label">{findingTypeLabel(f.finding_type)}</span>
            </button>
          ))}
        </div>
      </div>
      <div>
        {selected ? (
          <MetadataPanel finding={selected} />
        ) : (
          <div className="empty">Metadata харах файлаа сонгоно уу.</div>
        )}
      </div>
    </div>
  );
}

function FindingsTab({
  findings,
  filters,
  setFilters,
  mode,
}: {
  findings: Finding[];
  filters: { severity: string; q: string };
  setFilters: (f: { severity: string; q: string }) => void;
  mode: Tab;
}) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [preview, setPreview] = useState<string>("");

  const showFilters = mode === "all" || mode === "deleted" || mode === "recovered";

  const emptyMsg =
    mode === "all"
      ? "Идэвхтэй файл олдсонгүй."
      : mode === "deleted"
        ? "Устгагдсан файл олдсонгүй."
        : mode === "ntfs"
          ? "NTFS артефакт олдсонгүй."
          : mode === "usn"
            ? "USN Journal үйлдэл олдсонгүй."
            : "Сэргээгдсэн файл байхгүй.";

  const openPreview = async (f: Finding) => {
    setSelected(f);
    setPreview("");
    if (f.recovered) {
      try {
        const p = await api.previewFinding(f.id);
        setPreview(p.available ? p.preview : "(урьдчилан харах боломжгүй)");
      } catch {
        setPreview("(алдаа)");
      }
    }
  };

  return (
    <div>
      {showFilters && (
        <div className="filters">
          <input
            type="text"
            placeholder="Файл/замаар хайх…"
            value={filters.q}
            onChange={(e) => setFilters({ ...filters, q: e.target.value })}
          />
          <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
            <option value="">Бүх түвшин</option>
            <option value="high">Өндөр түвшин</option>
            <option value="medium">Дунд түвшин</option>
            <option value="normal">Хэвийн</option>
          </select>
        </div>
      )}

      {findings.length === 0 ? (
        <div className="empty">{emptyMsg}</div>
      ) : (
        <table>
          <thead>
            <tr>
              {mode !== "all" && mode !== "ntfs" && mode !== "usn" && <th>Зэрэг</th>}
              <th>Төрөл</th>
              <th>Файлын нэр</th>
              <th>Эх зам</th>
              {(mode === "all" || mode === "ntfs") && <th>MFT Entry</th>}
              <th>Хэмжээ</th>
              {mode === "recovered" && <th>Hash</th>}
              <th></th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const displayName = findingDisplayName(f.original_path, f.file_name);
              const named = findingHasOriginalName(f.meta);
              const mft = f.meta?.["mft_entry"];
              return (
                <tr key={f.id}>
                  {mode !== "all" && mode !== "ntfs" && mode !== "usn" && (
                    <td>
                      <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                    </td>
                  )}
                  <td>
                    <span className="type-label">{findingTypeLabel(f.finding_type)}</span>
                    {named && mode === "deleted" && <span className="badge named">нэртэй</span>}
                  </td>
                  <td>
                    <div className="file-name-cell">{displayName}</div>
                  </td>
                  <td>
                    <div className="mono path-cell">{f.original_path || "—"}</div>
                  </td>
                  {(mode === "all" || mode === "ntfs") && (
                    <td className="mono">{mft != null ? String(mft) : f.inode || "—"}</td>
                  )}
                  <td>{formatBytes(f.size_bytes)}</td>
                  {mode === "recovered" && <td className="mono">{shortHash(f.sha256)}</td>}
                  <td>
                    <div className="row-flex">
                      <button className="btn secondary sm" onClick={() => openPreview(f)}>
                        Дэлгэрэнгүй
                      </button>
                      {f.recovered && (
                        <a className="btn sm" href={api.downloadUrl(f.id)}>
                          Татах
                        </a>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {selected && (
        <div className="panel" style={{ marginTop: 18, background: "var(--bg-panel-2)" }}>
          <div className="row-flex">
            <h2 style={{ margin: 0 }}>{findingDisplayName(selected.original_path, selected.file_name)}</h2>
            <span className={`badge sev-${selected.severity}`}>{selected.severity}</span>
            <div className="spacer" />
            <button className="btn secondary sm" onClick={() => setSelected(null)}>
              Хаах
            </button>
          </div>

          {selected.finding_type !== "existing_file" &&
            selected.finding_type !== "ntfs_artifact" &&
            selected.finding_type !== "usn_event" && <RiskExplanation finding={selected} />}

          <MetadataPanel finding={selected} />

          {selected.recovered && (
            <>
              <h3>Урьдчилан харах</h3>
              <div className="preview-box">{preview || "Ачаалж байна…"}</div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

const SEV_LABEL: Record<string, string> = {
  high: "Өндөр түвшин",
  medium: "Дунд түвшин",
  normal: "Хэвийн",
};

function RiskExplanation({ finding }: { finding: Finding }) {
  const reasons = (finding.meta?.["risk_reasons"] as string[] | undefined) ?? [];
  const score = (finding.meta?.["risk_score"] as number | undefined) ?? 0;

  return (
    <div className="risk-box">
      <div className="risk-head">
        <span>Яагаад "{SEV_LABEL[finding.severity] ?? finding.severity}" гэж үнэлсэн бэ?</span>
        <span className={`badge sev-${finding.severity}`}>Нийт оноо: {score}</span>
      </div>
      {reasons.length > 0 ? (
        <ul className="risk-reasons">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      ) : (
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>Шалтгаан бүртгэгдээгүй.</div>
      )}
    </div>
  );
}

function TimelineTab({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) return <div className="empty">Forensic timeline хоосон байна.</div>;
  return (
    <div>
      <p className="meta-note" style={{ marginBottom: 16 }}>
        Autopsy / Log2Timeline загвар — MAC timestamp · USN Journal · USB зalgah/salgah · scan үйлдэл
      </p>
      {events.map((e) => (
        <div className="timeline-item" key={e.id}>
          <div className="timeline-time">{formatDate(e.timestamp)}</div>
          <div className={`timeline-kind kind-${e.event_type}`}>{timelineKindLabel(e.event_type)}</div>
          <div>{e.description}</div>
        </div>
      ))}
    </div>
  );
}
