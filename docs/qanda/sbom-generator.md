# CycloneDX SBOM generator (Q&A)

## What is a CycloneDX SBOM and why generate one?

A **Software Bill of Materials (SBOM)** is a machine-readable inventory of components in an application. **CycloneDX** is an OWASP standard format used for supply chain transparency, license tracking, and pairing with vulnerability data. Arguss emits a CycloneDX JSON document so projects can archive, exchange, or gate on a structured dependency list without extra proprietary formats.

## What is in the SBOM we generate?

- **Top-level metadata:** `bomFormat`, `specVersion` `1.7`, a UUID `serialNumber`, and a `metadata` block with UTC `timestamp`, a **tool** component identifying Arguss, and a **root component** for the analyzed project (`pkg:project/...` convention).
- **Components:** One library entry per unique npm package `(name, version)` from the lockfile parser, with `bom-ref`, `purl`, `name`, `version`, and `scope: required`.
- **Dependencies:** A logical graph: the root’s `dependsOn` lists direct dependencies (per parser `parents` including `"root"`), and each package’s `dependsOn` lists packages that declare it as a dependency. The root entry is **first** in the `dependencies` array; remaining entries are sorted by `ref` for stable output.

## What is not in the SBOM (v1)?

Vulnerability annotations, file hashes, supplier/contact details, licenses, and other optional CycloneDX fields are **out of scope** for this first version. Those can be layered in a future revision or combined with other tools (e.g. VEX).

## Which spec version and why?

We emit **CycloneDX 1.7**, published October 2025 as **ECMA-424 2nd Edition** and the current standard. The subset we populate (metadata, components, dependencies) stays compatible with common 1.5-era consumers; optional CLI validation uses `--input-version v1_7`.

## How does the SBOM dependency graph relate to the parser?

The parser’s second pass fills **`parents`**: each dependency lists the logical parents that depend on it (`"root"` or another package name). The SBOM builder **inverts** that view: for each child, every parent’s `bom-ref` gets that child in its `dependsOn` list. That is the same logical graph as `Dependency.parents`, expressed in CycloneDX `dependencies` form.

## How are scoped npm packages represented in PURLs?

Per the **Package URL** spec for npm, a scoped name like `@types/node` encodes the leading `@` as **`%40`** in the name segment, e.g. `pkg:npm/%40types/node@20.1.0`. The project root uses the same encoding inside the custom `pkg:project/...` `bom-ref`.

## Known limitations (v1)

- **Version strings in PURLs** are appended as-is. Real npm semver and dist-tags rarely need escaping; if we ever hit problematic characters, we can add stricter percent-encoding.
- **Ambiguous parent names:** The parser records parent **names**, not `name@version`. If two installed versions share a name (uncommon but possible), the SBOM emits **dependsOn edges from every matching parent version** to the child. This is conservative and avoids dropping edges when the lockfile model is ambiguous.

## Optional schema validation

Unit tests cover structure and behavior. An optional integration test can run the **OWASP CycloneDX CLI** (`cyclonedx validate`, often installed as `cyclonedx` on PATH) against a generated SBOM; it is skipped when that binary is not installed. The Python package `cyclonedx-bom` is a dev dependency for related tooling but does not install the `cyclonedx` .NET CLI by itself.
