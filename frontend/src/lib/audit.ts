/** Audit log үйлдлийн монгол нэршил. */
export const AUDIT_LABEL: Record<string, string> = {
  device_connected: "Төхөөрөмж залгагдсан",
  device_disconnected: "Төхөөрөмж салгагдсан",
  device_registered: "Төхөөрөмж бүртгэгдсэн",
  set_read_only: "Write-block идэвхжсэн",
  scan_queued: "Шинжилгээ дараалалд",
  scan_started: "Шинжилгээ эхэлсэн",
  scan_completed: "Шинжилгээ дууссан",
  case_created: "Хэрэг үүсгэсэн",
  finding_downloaded: "Файл татсан",
};

export function auditActionLabel(action: string): string {
  return AUDIT_LABEL[action] ?? action;
}
