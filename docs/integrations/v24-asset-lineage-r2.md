# Offline asset provenance (R2 / F-04)

`assessment.assets` retains actual untrusted `sourceId` values on all direct and
derived edges. `observationRecords` content-addresses normalized imported records
in a distinct `observation:` namespace; a source may supply several records.
Duplicates and input order do not change the graph.

Containment has `provenance.kind=DERIVED`, rule `IPV4_CIDR_CONTAINMENT`, and
the supporting observation record IDs. The v1 input's `segments` strings have no
source ID. Their provenance is honestly `INPUT_SEGMENT_DECLARATION`, `sourceId=null`,
with a separate `segment-declaration:` identity, rather than a fabricated source.
Internal record IDs and rule names never substitute for an imported source ID.

All confidence remains `IMPORTED_CLAIM_NOT_VERIFIED`. Neither content identity,
CIDR arithmetic nor the presence of a record authenticates a source or authorizes
network testing. CLI, MCP and the JSON artifact use the same full graph.
Reports truncate evidence excerpts by design; a compact lineage evidence record
therefore binds the complete JSON artifact by SHA-256 rather than claiming the
Markdown contains every observation. No active DNS, TLS, scanner or upstream
module is executed.
