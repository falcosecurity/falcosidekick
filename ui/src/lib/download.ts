/** Saves data as a pretty-printed JSON file through the browser's download. */
export function downloadJSON(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

/** A file name with the export time, safe on every file system: falco-events-20261108-121530.json. */
export function exportFileName(prefix: string, now: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0")
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
  return `${prefix}-${stamp}.json`
}
