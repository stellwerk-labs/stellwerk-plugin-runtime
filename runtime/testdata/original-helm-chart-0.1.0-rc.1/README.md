# Original public Helm chart regression

These are the unchanged public chart descriptor and three OCI graph blobs from
`stellwerk-labs/stellwerk-plugin-runtime` version `0.1.0-rc.1`, source
`369513cd4733dfa6fec8c78e263f7f731c714094`. No private TEST package, entitlement,
publisher key, or signing material is present.

The root is `sha256:e651532301bc341be962859b4d9f1f4687bda403d65db479f98a7aa29ef52702`
(650 bytes). The layout descriptor declares
`application/vnd.oci.image.manifest.v1+json`; the root manifest itself omits
`mediaType`, as Helm's registry manifest example does. The chart config is
`sha256:b1b2e5d9e274f1b8002d9e4452f189f60343d8d43a6ff0602c4f8e0a348f6a0a`
(242 bytes) and chart TGZ layer is
`sha256:7a6d46e7b935cbecfb5515ff5bfeb68c30f43dc56c521755f66e1ce017fcdcff`
(14153 bytes). Tests pin all three byte hashes before exercising the parser.

OCI 1.1.1 recommends the manifest `mediaType` field and requires its exact OCI
value when present. An absent property is distinct from null, an empty string,
or an incorrect media type. This regression does not normalize any artifact.

Sources: [OCI image manifest specification](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md#image-manifest-property-descriptions),
[Helm registry manifest example](https://helm.sh/docs/topics/registries/#helm-chart-manifest).
