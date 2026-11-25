export function alertPeriod(
  period: string,
  fromDate: string,
  toDate: string,
  now = new Date(),
): { from: string; to: string } | null {
  let from = new Date(now)
  let to = new Date(now)
  if (period === 'custom') {
    if (!fromDate || !toDate) return null
    from = new Date(`${fromDate}T00:00:00`)
    to = new Date(`${toDate}T00:00:00`)
    to.setDate(to.getDate() + 1)
    if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) return null
  } else if (period === 'today') {
    from.setHours(0, 0, 0, 0)
  } else {
    from = new Date(now.getTime() - Number(period) * 86400000)
  }
  return { from: from.toISOString(), to: to.toISOString() }
}
