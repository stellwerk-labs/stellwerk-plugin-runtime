# Registration metadata and legal package layers

Unreleased local candidate for runtime and chart 0.1.1. No published artifact
or completed deployment is implied by these notes.

Native packages may now carry `registration-manifest.json` with media type
`application/vnd.stellwerk.plugin.metadata.v1`, and root `LICENSE` plus files
under `licenses/` with media type `application/vnd.stellwerk.plugin.license.v1`.
Each file is a separate plain-file layer at its original path. Existing package
types, publisher policy, plugin protocol and manifest schema stay compatible.

These layers require runtime 0.1.1 or later. An installation pinned to runtime
0.1.0 fails closed at `verify-envelope` on either new media type. Upgrade the
digest-pinned generic runtime image before installing a package that needs
these layers; an offline bundle must carry that compatible runtime image.
The corresponding chart release is 0.1.1. No minimum-runtime field is added to
the plugin ABI or bundle schema; operators select the qualified release set.

Metadata has a 256 KiB per-file and aggregate bound and a one-file bound. Legal
content has independent 1 MiB per-file, 16 MiB aggregate and 512-file bounds.
The complete package stays below 592.75 MiB, within the chart's 640 MiB package
volume. Unknown paths or media types, duplicate or conflicting paths, unsafe
titles, traversal and ORAS archive annotations fail closed before pulling.

The signed OCI manifest binds every descriptor. Online ORAS transport verifies
each blob's exact size and digest. Offline bundle verification first applies
the same envelope policy, then verifies every blob and the signed release set,
including SBOM and provenance. Legal and metadata bytes are retained intact;
they are not hidden under UI paths or excluded from signature coverage.

The Go toolchain requirement remains 1.26.10. Exact image digests, source commits
and publisher attestations must be qualified together before publication.
