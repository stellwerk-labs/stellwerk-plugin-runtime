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
	DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
}

// verifyManagedKeySignature applies the managed-key-no-tlog policy: the
// operator-approved plugin ID must be pinned to a publisher with exactly
// that policy, the bundle must name one of the publisher's keys that is not
// revoked, and the signature over the exact OCI manifest bytes must verify
// with that pinned key. Key material inside the bundle is never trusted. The
// returned key is what Cosign verifies with next.
//
// Without a transparency log the signing time is unprovable, so the key's
// validity window gates new installations only. Re-fetching the digest an
// existing installation recorded (installedDigest) keeps verifying after the
// window ends; only revocation stops that.
func verifyManagedKeySignature(bootstrap trustBootstrap, pluginID string, bundleData, manifest []byte, now time.Time, installedDigest string) (publisherKey, error) {
	index := slices.IndexFunc(bootstrap.Publishers, func(p publisherPin) bool { return slices.Contains(p.PluginIDs, pluginID) })
	if index < 0 {
		return publisherKey{}, fmt.Errorf("no publisher is pinned for plugin %s", pluginID)
	}
	publisher := bootstrap.Publishers[index]
	if publisher.Policy != managedKeyNoTlogPolicy {
		return publisherKey{}, fmt.Errorf("publisher %s is pinned with the %s policy, which requires transparency-log verification; "+
			"only %s publishers may be verified without it", publisher.ID, publisher.Policy, managedKeyNoTlogPolicy)
	}
	var bundle sigstoreBundle
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		return publisherKey{}, errors.New("the signature bundle is not valid JSON")
	}
	material := bundle.VerificationMaterial
	switch {
	case bundle.MediaType != sigstoreBundleV03 && bundle.MediaType != sigstoreBundleV03Alt:
		return publisherKey{}, errors.New("the signature bundle must be a Sigstore v0.3 bundle")
	case len(material.Certificate) != 0 || len(material.X509CertificateChain) != 0:
		return publisherKey{}, errors.New("the signature bundle carries its own certificate; managed-key publishers are trusted only through pinned keys")
	case material.PublicKey == nil || material.PublicKey.Hint == "":
		return publisherKey{}, errors.New("the signature bundle names no public key")
	case bundle.MessageSignature == nil || len(bundle.DSSEEnvelope) != 0:
		return publisherKey{}, errors.New("the signature bundle must hold a message signature over the OCI manifest")
	}
	if slices.Contains(bootstrap.RevokedKeyIDs, material.PublicKey.Hint) {
		return publisherKey{}, fmt.Errorf("the signature names key %s, which the trust bootstrap revokes", material.PublicKey.Hint)
	}
	keyIndex := slices.IndexFunc(publisher.Keys, func(k publisherKey) bool { return k.KeyID == material.PublicKey.Hint })
	if keyIndex < 0 {
		return publisherKey{}, fmt.Errorf("the signature names key %s, which publisher %s does not pin", material.PublicKey.Hint, publisher.ID)
	}
	key := publisher.Keys[keyIndex]
	sum := sha256.Sum256(manifest)
	recorded := installedDigest != "" && installedDigest == "sha256:"+hex.EncodeToString(sum[:])
	if !recorded && (now.Before(key.ValidFrom) || !now.Before(key.ValidUntil)) {
		return publisherKey{}, fmt.Errorf("publisher %s key %s is valid for new installations only from %s until %s", publisher.ID, key.KeyID,
			key.ValidFrom.UTC().Format(time.RFC3339), key.ValidUntil.UTC().Format(time.RFC3339))
	}
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

func verifyPublisher(args []string) error {
	flags := flag.NewFlagSet("verify-publisher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bootstrapPath := flags.String("trust-bootstrap", "", "operator trust bootstrap (publishers.json)")
	bundlePath := flags.String("bundle", "", "detached Sigstore bundle")
	manifestPath := flags.String("oci-manifest", "", "fetched OCI manifest")
	pluginID := flags.String("plugin-id", "", "operator-approved plugin ID")
	keyOut := flags.String("key-out", "", "where to write the selected pinned public key")
	installedDigest := flags.String("installed-digest", "", "package digest an existing installation recorded; exempt from key validity windows")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bootstrapPath == "" || *bundlePath == "" || *manifestPath == "" || *pluginID == "" || !filepath.IsAbs(*keyOut) {
		return errors.New("trust bootstrap, bundle, OCI manifest, plugin ID and an absolute --key-out are required")
	}
	if *installedDigest != "" && !validDigest(*installedDigest) {
		return errors.New("--installed-digest must be a canonical sha256 digest")
	}
	bootstrap, err := loadTrustBootstrap(*bootstrapPath)
	if err != nil {
		return err
	}
	bundle, err := boundedRegularFile(*bundlePath, signatureBundleLimit)
	if err != nil {
		return fmt.Errorf("signature bundle unavailable: %w", err)
	}
	manifest, err := boundedRegularFile(*manifestPath, 1<<20)
	if err != nil {
		return fmt.Errorf("OCI manifest unavailable: %w", err)
	}
	key, err := verifyManagedKeySignature(bootstrap, *pluginID, bundle, manifest, time.Now(), *installedDigest)
	if err != nil {
		return err
	}
	return writeFileAtomically(*keyOut, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.der}), 0444)
}
