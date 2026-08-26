export function Ext({ href, label }: { href: string; label: string }) {
  const ok = href.startsWith("https:") || href.startsWith("http:")
  return ok ? <a href={href}>{label}</a> : <span>{label}</span>
}
