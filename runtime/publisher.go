package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// Trust policies of the publisher trust bootstrap.
const (
	sigstorePolicy         = "sigstore"
	managedKeyNoTlogPolicy = "managed-key-no-tlog"
	publisherKeyAlgorithm  = "ecdsa-p256-sha256"
	sigstoreBundleV03      = "application/vnd.dev.sigstore.bundle.v0.3+json"
	sigstoreBundleV03Alt   = "application/vnd.dev.sigstore.bundle+json;version=0.3"
	trustBootstrapLimit    = 1 << 20
	signatureBundleLimit   = 1 << 20
)

var publisherIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// trustBootstrap is the operator's authentic statement of which publisher may
// sign which plugin IDs, under which policy, with which keys and when, plus
// the compromise list of revoked key IDs. It is never read from a package.
type trustBootstrap struct {
	SchemaVersion int            `json:"schemaVersion"`
	Publishers    []publisherPin `json:"publishers"`
	RevokedKeyIDs []string       `json:"revokedKeyIds"`
}

type publisherPin struct {
	ID        string         `json:"id"`
	Policy    string         `json:"policy"`
	PluginIDs []string       `json:"pluginIds"`
	Keys      []publisherKey `json:"keys"`
	// Signed SBOM and provenance attestations for the package digest.
	// Unset means required for managed-key-no-tlog publishers.
	RequireSBOM       *bool `json:"requireSBOM"`
	RequireProvenance *bool `json:"requireProvenance"`
}

type publisherKey struct {
	KeyID      string    `json:"keyId"`
	Algorithm  string    `json:"algorithm"`
	PublicKey  string    `json:"publicKey"`
	ValidFrom  time.Time `json:"validFrom"`
	ValidUntil time.Time `json:"validUntil"`
	parsed     *ecdsa.PublicKey
	der        []byte
}

// publisherKeyID is Cosign's public key hint: base64 of SHA-256 over the DER
// SubjectPublicKeyInfo.
func publisherKeyID(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func loadTrustBootstrap(path string) (trustBootstrap, error) {
	var bootstrap trustBootstrap
	data, err := boundedRegularFile(path, trustBootstrapLimit)
	if err != nil {
		return bootstrap, fmt.Errorf("trust bootstrap unavailable: %w", err)
	}
	if err := decodeStrict(data, &bootstrap); err != nil {
		return bootstrap, fmt.Errorf("trust bootstrap: %w", err)
	}
	if bootstrap.SchemaVersion != 1 || len(bootstrap.Publishers) == 0 {
		return bootstrap, errors.New("trust bootstrap: schemaVersion 1 with at least one publisher is required")
	}
	revoked := map[string]bool{}
	for _, keyID := range bootstrap.RevokedKeyIDs {
		if decoded, err := base64.StdEncoding.DecodeString(keyID); err != nil || len(decoded) != sha256.Size || revoked[keyID] {
			return bootstrap, fmt.Errorf("trust bootstrap: revoked key ID %q must be a unique Cosign key hint", keyID)
		}
		revoked[keyID] = true
	}
	publishers, plugins, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range bootstrap.Publishers {
		publisher := &bootstrap.Publishers[i]
		if publisher.Policy == "" {
			publisher.Policy = sigstorePolicy
		}
		commercial := publisher.Policy == managedKeyNoTlogPolicy
		for _, required := range []**bool{&publisher.RequireSBOM, &publisher.RequireProvenance} {
			if *required == nil {
				*required = &commercial
			}
		}
		if !publisherIDPattern.MatchString(publisher.ID) || publishers[publisher.ID] ||
			(publisher.Policy != sigstorePolicy && publisher.Policy != managedKeyNoTlogPolicy) ||
			len(publisher.PluginIDs) == 0 || len(publisher.Keys) == 0 {
			return bootstrap, fmt.Errorf("trust bootstrap: publisher %q needs a unique ID, a known policy, plugin IDs and keys", publisher.ID)
		}
		publishers[publisher.ID] = true
		for _, pluginID := range publisher.PluginIDs {
			if !pluginIDPattern.MatchString(pluginID) || plugins[pluginID] {
				return bootstrap, fmt.Errorf("trust bootstrap: plugin ID %q must be valid and pinned to exactly one publisher", pluginID)
			}
			plugins[pluginID] = true
		}
		for j := range publisher.Keys {
			key := &publisher.Keys[j]
			if err := key.parse(); err != nil {
				return bootstrap, fmt.Errorf("trust bootstrap: publisher %q key %q: %w", publisher.ID, key.KeyID, err)
			}
			if keys[key.KeyID] {
				return bootstrap, fmt.Errorf("trust bootstrap: key %q is pinned more than once", key.KeyID)
			}
			keys[key.KeyID] = true
		}
	}
	return bootstrap, nil
}

func (k *publisherKey) parse() error {
	if k.Algorithm != publisherKeyAlgorithm {
		return fmt.Errorf("algorithm must be %s", publisherKeyAlgorithm)
	}
	if k.ValidFrom.IsZero() || !k.ValidUntil.After(k.ValidFrom) {
		return errors.New("validFrom must precede validUntil")
	}
	block, rest := pem.Decode([]byte(k.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("publicKey must be exactly one PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return errors.New("publicKey must be an ECDSA P-256 key")
	}
	if publisherKeyID(block.Bytes) != k.KeyID {
		return errors.New("keyId must be base64(SHA-256(DER public key))")
	}
	k.parsed, k.der = key, block.Bytes
	return nil
}

// Attestation predicates a release set carries next to its signature.
const (
	sbomPredicateType       = "https://spdx.dev/Document"
	provenancePredicateType = "https://stellwerk.dev/attestation/source-provenance/v1"
	inTotoPayloadType       = "application/vnd.in-toto+json"
)

var (
	gitCommitPattern   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	spdxVersionPattern = regexp.MustCompile(`^SPDX-2\.[0-9]+$`)
)

// sigstoreBundle holds the parts of a Sigstore bundle this policy evaluates.
// Unknown protobuf fields are tolerated; every field used is required.
type sigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKey *struct {
			Hint string `json:"hint"`
		} `json:"publicKey"`
		Certificate          json.RawMessage   `json:"certificate"`
		X509CertificateChain json.RawMessage   `json:"x509CertificateChain"`
		TlogEntries          []json.RawMessage `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
	DSSEEnvelope *struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

// parseKeyBundle accepts a Sigstore v0.3 bundle that names a key by hint and
// carries no certificate. Key material inside a bundle is never trusted.
func parseKeyBundle(data []byte, what string) (sigstoreBundle, error) {
	var bundle sigstoreBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return bundle, fmt.Errorf("the %s is not valid JSON", what)
	}
	material := bundle.VerificationMaterial
	switch {
	case bundle.MediaType != sigstoreBundleV03 && bundle.MediaType != sigstoreBundleV03Alt:
		return bundle, fmt.Errorf("the %s must be a Sigstore v0.3 bundle", what)
	case len(material.Certificate) != 0 || len(material.X509CertificateChain) != 0:
		return bundle, fmt.Errorf("the %s carries its own certificate; managed-key publishers are trusted only through pinned keys", what)
	case material.PublicKey == nil || material.PublicKey.Hint == "":
		return bundle, fmt.Errorf("the %s names no public key", what)
	}
	return bundle, nil
}

// pinnedPublisher returns the one publisher the bootstrap pins for pluginID,
// which must use the managed-key-no-tlog policy.
func pinnedPublisher(bootstrap trustBootstrap, pluginID string) (publisherPin, error) {
	index := slices.IndexFunc(bootstrap.Publishers, func(p publisherPin) bool { return slices.Contains(p.PluginIDs, pluginID) })
	if index < 0 {
		return publisherPin{}, fmt.Errorf("no publisher is pinned for plugin %s", pluginID)
	}
	publisher := bootstrap.Publishers[index]
	if publisher.Policy != managedKeyNoTlogPolicy {
		return publisherPin{}, fmt.Errorf("publisher %s is pinned with the %s policy, which requires transparency-log verification; "+
			"only %s publishers may be verified without it", publisher.ID, publisher.Policy, managedKeyNoTlogPolicy)
	}
	return publisher, nil
}

// publisherKeyFor resolves the key a bundle names. Without a transparency log
// the signing time is unprovable, so the validity window gates new
// installations only; a recorded installed digest keeps verifying after it
// ends. Revocation blocks both.
func publisherKeyFor(bootstrap trustBootstrap, publisher publisherPin, hint string, now time.Time, recorded bool) (publisherKey, error) {
	if slices.Contains(bootstrap.RevokedKeyIDs, hint) {
		return publisherKey{}, fmt.Errorf("the signature names key %s, which the trust bootstrap revokes", hint)
	}
	index := slices.IndexFunc(publisher.Keys, func(k publisherKey) bool { return k.KeyID == hint })
	if index < 0 {
		return publisherKey{}, fmt.Errorf("the signature names key %s, which publisher %s does not pin", hint, publisher.ID)
	}
	key := publisher.Keys[index]
	if !recorded && (now.Before(key.ValidFrom) || !now.Before(key.ValidUntil)) {
		return publisherKey{}, fmt.Errorf("publisher %s key %s is valid for new installations only from %s until %s", publisher.ID, key.KeyID,
			key.ValidFrom.UTC().Format(time.RFC3339), key.ValidUntil.UTC().Format(time.RFC3339))
	}
	return key, nil
}

func isInstalledDigest(installedDigest string, manifest []byte) bool {
	sum := sha256.Sum256(manifest)
	return installedDigest != "" && installedDigest == "sha256:"+hex.EncodeToString(sum[:])
}

// verifyManagedKeySignature applies the managed-key-no-tlog policy to the
// package signature: the operator-approved plugin ID must be pinned to a
// publisher with exactly that policy, the bundle must name one of its keys
// under the validity and revocation rules, and the message signature over
// the exact OCI manifest bytes must verify with that pinned key. The
// returned key is what Cosign verifies with next.
func verifyManagedKeySignature(bootstrap trustBootstrap, pluginID string, bundleData, manifest []byte, now time.Time, installedDigest string) (publisherKey, error) {
	publisher, err := pinnedPublisher(bootstrap, pluginID)
	if err != nil {
		return publisherKey{}, err
	}
	bundle, err := parseKeyBundle(bundleData, "signature bundle")
	if err != nil {
		return publisherKey{}, err
	}
	if bundle.MessageSignature == nil || bundle.DSSEEnvelope != nil {
		return publisherKey{}, errors.New("the signature bundle must hold a message signature over the OCI manifest")
	}
	key, err := publisherKeyFor(bootstrap, publisher, bundle.VerificationMaterial.PublicKey.Hint, now, isInstalledDigest(installedDigest, manifest))
	if err != nil {
		return publisherKey{}, err
	}
	sum := sha256.Sum256(manifest)
	signed := bundle.MessageSignature
	digest, digestErr := base64.StdEncoding.DecodeString(signed.MessageDigest.Digest)
	signature, signatureErr := base64.StdEncoding.DecodeString(signed.Signature)
	if signed.MessageDigest.Algorithm != "SHA2_256" || digestErr != nil || string(digest) != string(sum[:]) {
		return publisherKey{}, errors.New("the signature bundle does not cover this OCI manifest")
	}
	if signatureErr != nil || !ecdsa.VerifyASN1(key.parsed, sum[:], signature) {
		return publisherKey{}, fmt.Errorf("the signature does not verify with publisher %s key %s", publisher.ID, key.KeyID)
	}
	return key, nil
}

// dssePAE is the DSSE v1 pre-authentication encoding that is signed.
func dssePAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

// verifyAttestation checks one signed in-toto attestation of the release
// set: a DSSE envelope signed with a pinned key of the same publisher, whose
// statement names exactly the package digest as its only subject and carries
// the expected predicate.
func verifyAttestation(bootstrap trustBootstrap, publisher publisherPin, bundleData, manifest []byte, predicateType, what string, now time.Time, recorded bool) (publisherKey, error) {
	bundle, err := parseKeyBundle(bundleData, what)
	if err != nil {
		return publisherKey{}, err
	}
	envelope := bundle.DSSEEnvelope
	if envelope == nil || bundle.MessageSignature != nil || envelope.PayloadType != inTotoPayloadType || len(envelope.Signatures) != 1 {
		return publisherKey{}, fmt.Errorf("the %s must be one signed in-toto DSSE envelope", what)
	}
	key, err := publisherKeyFor(bootstrap, publisher, bundle.VerificationMaterial.PublicKey.Hint, now, recorded)
	if err != nil {
		return publisherKey{}, fmt.Errorf("%s: %w", what, err)
	}
	payload, payloadErr := base64.StdEncoding.DecodeString(envelope.Payload)
	signature, signatureErr := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	pae := sha256.Sum256(dssePAE(envelope.PayloadType, payload))
	if payloadErr != nil || signatureErr != nil || !ecdsa.VerifyASN1(key.parsed, pae[:], signature) {
		return publisherKey{}, fmt.Errorf("the %s signature does not verify with publisher %s key %s", what, publisher.ID, key.KeyID)
	}
	var statement struct {
		Type    string `json:"_type"`
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil ||
		(statement.Type != "https://in-toto.io/Statement/v1" && statement.Type != "https://in-toto.io/Statement/v0.1") {
		return publisherKey{}, fmt.Errorf("the %s does not hold an in-toto statement", what)
	}
	sum := sha256.Sum256(manifest)
	if len(statement.Subject) != 1 || statement.Subject[0].Digest["sha256"] != hex.EncodeToString(sum[:]) {
		return publisherKey{}, fmt.Errorf("the %s is about another artifact, not this package digest", what)
	}
	if statement.PredicateType != predicateType {
		return publisherKey{}, fmt.Errorf("the %s has predicate type %q, want %q", what, statement.PredicateType, predicateType)
	}
	if err := checkPredicate(predicateType, statement.Predicate); err != nil {
		return publisherKey{}, fmt.Errorf("the %s predicate: %w", what, err)
	}
	return key, nil
}

func checkPredicate(predicateType string, predicate json.RawMessage) error {
	switch predicateType {
	case sbomPredicateType:
		var document struct {
			SPDXVersion string `json:"spdxVersion"`
			SPDXID      string `json:"SPDXID"`
		}
		if json.Unmarshal(predicate, &document) != nil || !spdxVersionPattern.MatchString(document.SPDXVersion) || document.SPDXID != "SPDXRef-DOCUMENT" {
			return errors.New("not an SPDX 2 JSON document")
		}
	case provenancePredicateType:
		var provenance struct {
			SchemaVersion int `json:"schemaVersion"`
			Sources       []struct {
				Commit string `json:"commit"`
			} `json:"sources"`
		}
		if json.Unmarshal(predicate, &provenance) != nil || provenance.SchemaVersion != 1 || len(provenance.Sources) == 0 {
			return errors.New("source provenance needs schemaVersion 1 and at least one source")
		}
		for _, source := range provenance.Sources {
			if !gitCommitPattern.MatchString(source.Commit) {
				return errors.New("every source needs a full git commit ID")
			}
		}
	}
	return nil
}

// releaseKeys are the pinned keys that verified each part of a release set.
type releaseKeys struct {
	pkg, sbom, provenance *publisherKey
}

// verifyRelease verifies the package signature and the SBOM and provenance
// attestations the publisher requires (and any supplied ones) as one release
// set. A nil attestation means none was supplied.
func verifyRelease(bootstrap trustBootstrap, pluginID string, signature, sbom, provenance, manifest []byte, now time.Time, installedDigest string) (releaseKeys, error) {
	key, err := verifyManagedKeySignature(bootstrap, pluginID, signature, manifest, now, installedDigest)
	if err != nil {
		return releaseKeys{}, err
	}
	publisher, err := pinnedPublisher(bootstrap, pluginID)
	if err != nil {
		return releaseKeys{}, err
	}
	keys := releaseKeys{pkg: &key}
	recorded := isInstalledDigest(installedDigest, manifest)
	for _, part := range []struct {
		data          []byte
		required      bool
		predicateType string
		what          string
		key           **publisherKey
	}{
		{sbom, *publisher.RequireSBOM, sbomPredicateType, "SBOM attestation", &keys.sbom},
		{provenance, *publisher.RequireProvenance, provenancePredicateType, "provenance attestation", &keys.provenance},
	} {
		if part.data == nil {
			if part.required {
				return releaseKeys{}, fmt.Errorf("publisher %s requires a signed %s for this package; none was supplied", publisher.ID, part.what)
			}
			continue
		}
		verified, err := verifyAttestation(bootstrap, publisher, part.data, manifest, part.predicateType, part.what, now, recorded)
		if err != nil {
			return releaseKeys{}, err
		}
		*part.key = &verified
	}
	return keys, nil
}

func verifyPublisher(args []string) error {
	flags := flag.NewFlagSet("verify-publisher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bootstrapPath := flags.String("trust-bootstrap", "", "operator trust bootstrap (publishers.json)")
	bundlePath := flags.String("bundle", "", "detached Sigstore bundle over the OCI manifest")
	sbomPath := flags.String("sbom-bundle", "", "signed SBOM attestation bundle, if supplied")
	provenancePath := flags.String("provenance-bundle", "", "signed provenance attestation bundle, if supplied")
	manifestPath := flags.String("oci-manifest", "", "fetched OCI manifest")
	pluginID := flags.String("plugin-id", "", "operator-approved plugin ID")
	keyDir := flags.String("key-dir", "", "where to write the pinned keys Cosign verifies with")
	installedDigest := flags.String("installed-digest", "", "package digest an existing installation recorded; exempt from key validity windows")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bootstrapPath == "" || *bundlePath == "" || *manifestPath == "" || *pluginID == "" || !filepath.IsAbs(*keyDir) {
		return errors.New("trust bootstrap, bundle, OCI manifest, plugin ID and an absolute --key-dir are required")
	}
	if *installedDigest != "" && !validDigest(*installedDigest) {
		return errors.New("--installed-digest must be a canonical sha256 digest")
	}
	bootstrap, err := loadTrustBootstrap(*bootstrapPath)
	if err != nil {
		return err
	}
	read := func(path, what string) ([]byte, error) {
		if path == "" {
			return nil, nil
		}
		data, err := boundedRegularFile(path, signatureBundleLimit)
		if err != nil {
			return nil, fmt.Errorf("%s unavailable: %w", what, err)
		}
		return data, nil
	}
	signature, err := read(*bundlePath, "signature bundle")
	if err != nil {
		return err
	}
	sbom, err := read(*sbomPath, "SBOM attestation")
	if err != nil {
		return err
	}
	provenance, err := read(*provenancePath, "provenance attestation")
	if err != nil {
		return err
	}
	manifest, err := boundedRegularFile(*manifestPath, 1<<20)
	if err != nil {
		return fmt.Errorf("OCI manifest unavailable: %w", err)
	}
	keys, err := verifyRelease(bootstrap, *pluginID, signature, sbom, provenance, manifest, time.Now(), *installedDigest)
	if err != nil {
		return err
	}
	for name, key := range map[string]*publisherKey{"package.pub": keys.pkg, "sbom.pub": keys.sbom, "provenance.pub": keys.provenance} {
		if key == nil {
			continue
		}
		if err := writeFileAtomically(filepath.Join(*keyDir, name), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.der}), 0444); err != nil {
			return err
		}
	}
	return nil
}
