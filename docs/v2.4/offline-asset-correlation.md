# Offline asset correlation (Draft)

`node packages/cli/index.js assessment assets --bundle ABS --json` calls the existing
Core L0 analysis path. MCP uses `armorbreak_analyze` with `assessment.assets` and
an explicit workspace file target. No external lookup, DNS resolution, scanner,
database, shell, plugin activation or high-risk redteam code is used.

Input is `armorbreak.offline-assets/v1`, with `observations` and `segments`.
Observations are closed records:

- `dns`: `sourceId`, `domain`, `ip`, `type`.
- `service`: `sourceId`, `ip`, `port`, `transport` (`tcp`/`udp`), `type`.
- `certificate`: `sourceId`, `sha256`, `sans` (explicit domain array), `type`.

Segments are canonical IPv4 CIDRs. Duplicate edges are idempotent; source IDs are
retained, sorted, and combined. Relation types are `resolves`, `contains`, `exposes`
and `shares_cert`. Output and evidence always label relations as imported unverified
claims. A supplied certificate hash is not certificate authentication. Inert source
labels are not authority. Network ownership, real-host compatibility, upstream
redteam database integration and IPv6 subnet normalization remain unverified or unsupported.

Asset labels are intentionally visible in reports; do not submit credentials or
configuration secrets. This is not an anonymous or secret asset vault.

Behavior research only: frozen Original/Community `skills/redteam/asset-correlation.md`.
This native subset implements the documented four relationship rules without importing
or executing the upstream Skill/tool. Both corresponding stable IDs remain PARTIAL,
not complete equivalents of upstream active reconnaissance or `redteam_asset_link`.
