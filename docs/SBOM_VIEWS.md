# Purpose-scoped and incremental SBOMs

Large SBOMs usually have two different consumers: vulnerability matching, which
needs the runtime dependency set once per artifact, and compliance or build
review, which needs development, test, and build inputs as well. cdxgen keeps
the complete BOM as its default output and offers opt-in views for the first
consumer.

All views are ordinary CycloneDX documents. They use standard `scope`,
`hashes`, `licenses`, `evidence.occurrences`, `dependencies`, and
`compositions` fields. The extra `cdx:sbom:*` metadata records the view
boundary without turning the document into a private format.

## Flags

| Flag | Purpose |
| --- | --- |
| `--sbom-trim` | Deduplicate components and keep only the `--sbom-scope` selection. |
| `--sbom-scope runtime` | Keep default/`required` components. This is the default when trimming. |
| `--sbom-scope development` | Keep `excluded` and development/test/build components. |
| `--sbom-scope all` | Deduplicate without dropping a scope. |
| `--sbom-dedupe` | Deduplicate without trimming. |
| `--sbom-stable-sort` | Sort components by purl/coordinate/hash and dependencies by ref. |
| `--sbom-report` | Add license/hash gaps, ecosystem coverage, directness, and statistics without trimming. |
| `--sbom-incremental <baseline>` | Emit a delta against a previous BOM. Aliases: `--incremental`, `--sbom-baseline`. |
| `--sbom-identity-map <file>` | Canonicalize component identities with an explicit mapping file. |
| `--sbom-checksum` | Append a self-check checksum to the root `properties`. Implied by incremental mode. |

The default remains the complete, untrimmed BOM. `--required-only` still has
its historical behavior on its own; when `--sbom-trim` is also present, cdxgen
leaves scope filtering to the view layer so excluded components can be recorded
in the BOM instead of disappearing.

## Runtime and development views

`--sbom-trim --sbom-scope runtime` keeps components whose CycloneDX scope is
`required` or absent. It removes `optional` and `excluded` components, as well
as components carrying development, optional, peer-only, type-only, or
build-only markers.

The removed identities are not lost. They are recorded in
`cdx:sbom:trim:excludedComponents` as a JSON array containing the bom-ref, purl,
name, version, type, scope, direct/transitive classification, incoming
dependency refs, hashes, licenses, and occurrence locations. The BOM also gains
an `incomplete` composition and `cdx:sbom:complete=false`.

`--sbom-scope development` performs the inverse selection and records the
runtime components in the same excluded inventory.

## Deduplication and paths

Deduplication groups components by purl, or by type/group/name/version when a
purl is unavailable. Non-empty hashes can split a group: two builds of the same
version with different SHA-256 values remain two components.

Merging preserves:

- all `hashes`, `licenses`, `externalReferences`, and `properties`;
- all `evidence.occurrences`, identities, and callstack frames;
- the strongest scope (a runtime occurrence wins over a development-only one);
- every dependency edge, with duplicate refs rewritten to the canonical
  component bom-ref.

The dependency graph itself remains the authoritative record of introduction
paths. Each component also gets `cdx:sbom:dependencyType=direct|transitive`
(`unknown` when the graph has no usable root).

## Acceptance statistics

When trimming, deduplicating, or producing an incremental BOM, cdxgen writes a
single JSON object to `cdx:sbom:stats`. It includes:

- component counts before/after, duplicates merged, and excluded components;
- estimated serialized sizes before/after;
- the number of dependency edges before/after and whether the edge set is
  unchanged;
- the number of vulnerability match keys and a SHA-256 digest of that set
  before/after, plus `matchKeysUnchanged`.

The match key is the purl when present, otherwise type/group/name/version plus
available hashes. Trimming removes non-runtime components only; deduplication
merges records for the same identity. Therefore the runtime match-key set and
its digest stay unchanged. This is the property downstream vulnerability
matching relies on.

## License and hash views

`cdx:sbom:license:missing` and `cdx:sbom:hash:missing` list retained components
that lack the corresponding field. `cdx:sbom:ecosystems:covered` and
`cdx:sbom:ecosystems:uncovered` record purl-type counts and requested project
types for which no component was found.

Licenses and hashes remain on their components; these metadata lists are an
index for compliance review, not a second source of truth.

## Identity mapping

The identity map is a JSON object. A top-level `mappings` object is optional;
the keys may be a component bom-ref or purl:

```json
{
  "mappings": {
    "pkg:deb/debian/lodash@4.17.20": {
      "purl": "pkg:npm/lodash@4.17.20",
      "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"
    }
  }
}
```

Only valid purls and CPE 2.3 strings are applied. The original purl is retained
as `cdx:sbom:originalPurl`. If the bom-ref was the old purl, dependency refs are
rewritten to the mapped purl. A missing map file, a missing entry, or an invalid
target leaves the identity exactly as it was.

## Incremental output

`--sbom-incremental baseline.json` compares the current component set with the
baseline by bom-ref/purl and a SHA-256 digest of each component. The output is a
valid CycloneDX document containing:

- added and changed components only;
- dependency entries for the delta, the root edge, and any changed edge;
- `cdx:sbom:incremental` with added/changed/removed/emitted counts;
- `cdx:sbom:incremental:removedRefs` for tombstones;
- `cdx:sbom:complete=false` and an `incomplete` composition.

View-only `cdx:sbom:*` properties are excluded from the component digest, so
re-running the same view does not make every component appear changed.

Merge procedure for a downstream tool:

1. Remove the refs listed in `cdx:sbom:incremental:removedRefs`.
2. Replace components with the same bom-ref, or the same purl when the bom-ref
   changed.
3. Replace dependency entries by `ref`; the root entry carries the current
   direct dependency list.
4. Append the new component and dependency entries otherwise.

Components are stably sorted by purl/coordinate/hash, and dependency entries are
sorted by ref, before the delta is written. This keeps repeated diffs small and
reviewable.

If the baseline cannot be read, is not a 1.x-shaped component document, or its
checksum does not verify, cdxgen reports the problem. A missing baseline leaves
the complete BOM intact and records `baseline-unavailable` in
`cdx:sbom:incremental`; it does not silently emit an empty delta.

## Ecosystem boundaries and priority

For a project that can be described by several package managers, cdxgen emits
the native components it actually discovers. The coverage properties state the
observed purl types and the requested types that produced no components.

The recommended priority is primary package manager first, then secondary
package managers that describe the same ecosystem:

- JavaScript/TypeScript: npm, then pnpm/yarn/bun aliases.
- Python: pip/requirements/lock files, then Poetry/uv/Pipenv/Pixi/conda.
- JVM: Maven, then Gradle/sbt and other Maven-shaped sources.
- Go, Rust, .NET, Ruby, PHP, Swift: the native module/package manager first.
- Containers and hosts: OCI metadata first, then OS package managers and
  language package inventories from the rootfs.

Uncovered requested ecosystems are an explicit boundary, not an implicit claim
that the SBOM is complete.

## Integrity checksum

`--sbom-checksum` appends two root-level properties:

```json
{
  "properties": [
    { "name": "cdx:sbom:checksumAlgorithm", "value": "sha256" },
    { "name": "cdx:sbom:checksum", "value": "<64 hex characters>" }
  ]
}
```

The digest covers canonical JSON (object keys sorted), excluding the root
`signature` and the `cdx:sbom:checksum` value itself. The algorithm property is
covered by the digest. This lets a signed BOM keep the same checksum.
`cdx-validate` verifies the checksum when present and exits with status 2 when
it does not match.

## Degradation

- A partial dependency tree keeps every parsed component, adds an `incomplete`
  composition, and records `cdx:sbom:complete=false`.
- Missing or invalid identity mappings are ignored rather than guessed.
- A missing baseline does not fail the scan; it records an explicit
  `baseline-unavailable` status and leaves the complete BOM intact.
- A corrupt or modified baseline checksum is a hard error because merging a
  corrupt delta is less safe than generating the complete BOM again.
