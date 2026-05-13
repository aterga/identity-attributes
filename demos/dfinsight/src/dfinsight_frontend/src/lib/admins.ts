// Helpers for rendering the admin allowlist. Names come from the
// canister exactly as they appear in `sso:dfinity.org:name`; we synthesise
// a `firstname.lastname@dfinity.org` slug for display only — it's never
// trusted server-side.

export function nameToEmail(name: string): string {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .split(/\s+/)
    .filter(Boolean)
    .join(".");
  return slug ? `${slug}@dfinity.org` : "";
}

export function nameToInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "·";
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
}
