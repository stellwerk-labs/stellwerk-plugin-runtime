package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

const (
	packageArtifactType = "application/vnd.stellwerk.plugin.package.v1"
	manifestMediaType   = "application/vnd.stellwerk.plugin.manifest.v1+json"
	executableMediaType = "application/vnd.stellwerk.plugin.executable.v1"
	uiAssetMediaType    = "application/vnd.stellwerk.plugin.ui.asset.v1"
	titleAnnotation     = "org.opencontainers.image.title"
	// The largest legitimate package: both platform executables, the plugin
	// and UI manifests and a full UI.
	packageLimit = 2*binaryLimit + 2*manifestLimit + uiAssetLimit
	// The UI file limit plus the UI manifest itself.
	uiLayerLimit = 2000 + 1
)

var executableTitles = map[string]bool{"bin/linux/amd64/plugin": true, "bin/linux/arm64/plugin": true}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

// verifyEnvelope runs before any package content is pulled. It binds the OCI
// manifest to the pinned package digest and the operator-approved plugin
// manifest, and admits only the layers of the package format. Because ORAS
// verifies every blob against its descriptor, the declared sizes bound what
// the pull may write. It does not authenticate a publisher; the signature
// check that follows verifies these exact bytes with the pinned public key.
func verifyEnvelope(args []string) error {
	flags := flag.NewFlagSet("verify-envelope", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("oci-manifest", "", "downloaded OCI manifest")
	packageDigest := flags.String("package-digest", "", "immutable OCI sha256 digest")
	manifestHash := flags.String("manifest-sha256", "", "operator-approved plugin manifest sha256")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || !validDigest(*packageDigest) || !validSHA256(*manifestHash) {
		return errors.New("OCI manifest, canonical package digest and plugin manifest hash are required")
	}
	data, err := boundedRegularFile(*path, 1<<20)
	if err != nil {
		return err
	}
	if "sha256:"+digest(data) != *packageDigest {
		return errors.New("OCI envelope digest does not match package reference")
	}
	var envelope struct {
		SchemaVersion int             `json:"schemaVersion"`
		ArtifactType  string          `json:"artifactType"`
		Layers        []ociDescriptor `json:"layers"`
	}
	// OCI fields unrelated to this binding (annotations, config, subject) are
	// allowed. The signature covers the complete bytes, not a re-encoded subset.
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.SchemaVersion != 2 || envelope.ArtifactType != packageArtifactType {
		return errors.New("unsupported OCI package envelope")
	}
	return checkLayers(envelope.Layers, *manifestHash)
}

func validDigest(value string) bool {
	hash, ok := strings.CutPrefix(value, "sha256:")
	return ok && validSHA256(hash)
}

// checkLayers admits plain-file layers at their fixed package paths only.
// ORAS writes each layer to its title and unpacks archive layers, so titles
// must be unique clean paths and archives are refused outright.
func checkLayers(layers []ociDescriptor, manifestHash string) error {
	titles := map[string]bool{}
	manifests, uiLayers := 0, 0
	var total int64
	for _, layer := range layers {
		title := layer.Annotations[titleAnnotation]
		if !fs.ValidPath(title) || strings.ContainsAny(title, "\\\x00") || titles[title] {
			return fmt.Errorf("OCI layer title %q is not a unique package path", title)
		}
		titles[title] = true
		for key := range layer.Annotations {
			if strings.HasPrefix(key, "io.deis.oras.content.") {
				return fmt.Errorf("OCI layer %q is an archive; packages contain plain files only", title)
			}
		}
		if !validDigest(layer.Digest) || layer.Size < 0 {
			return fmt.Errorf("OCI layer %q has an invalid descriptor", title)
		}
		var limit int64
		switch {
		case layer.MediaType == manifestMediaType && title == "plugin-manifest.json":
			manifests++
			if layer.Digest != "sha256:"+manifestHash || layer.Size == 0 {
				return errors.New("OCI plugin manifest descriptor does not match launcher inputs")
			}
			limit = manifestLimit
		case layer.MediaType == executableMediaType && executableTitles[title]:
			limit = binaryLimit
		case layer.MediaType == uiAssetMediaType && strings.HasPrefix(title, "ui/"):
			uiLayers++
			limit = uiAssetLimit
		default:
			return fmt.Errorf("OCI layer %q (%s) is not part of the package format", title, layer.MediaType)
		}
		total += layer.Size
		if layer.Size > limit || total > packageLimit || uiLayers > uiLayerLimit {
			return fmt.Errorf("OCI layer %q exceeds the package size limits", title)
		}
	}
	if manifests != 1 {
		return errors.New("OCI package requires exactly one plugin manifest layer")
	}
	return nil
}
