package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// publisherTestNow is the test clock. verify-publisher checks key validity
// against the wall clock, so the test clock starts at it and every validity
// window is relative to it: no fixture expires on a calendar date.
var publisherTestNow = time.Now().UTC().Truncate(time.Second)

type publisherSigner struct {
	private *ecdsa.PrivateKey
	der     []byte
	id      string
}

func newPublisherSigner(t *testing.T, curve elliptic.Curve) publisherSigner {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publisherSigner{private: private, der: der, id: publisherKeyID(der)}
}

func (s publisherSigner) pin(validFrom, validUntil time.Time) map[string]any {
	return map[string]any{
		"keyId": s.id, "algorithm": publisherKeyAlgorithm,
		"publicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: s.der})),
		"validFrom": validFrom.Format(time.RFC3339), "validUntil": validUntil.Format(time.RFC3339),
	}
}

func (s publisherSigner) validPin() map[string]any {
	return s.pin(publisherTestNow.AddDate(0, -1, 0), publisherTestNow.AddDate(1, 0, 0))
}

// sign produces the Sigstore v0.3 bundle shape that `cosign sign-blob --key
// --signing-config <no tlog> --bundle` writes: a public key hint and a
// message signature over the artifact, no transparency-log entry.
func (s publisherSigner) sign(t *testing.T, artifact []byte, hint string) []byte {
	t.Helper()
	sum := sha256.Sum256(artifact)
	signature, err := ecdsa.SignASN1(rand.Reader, s.private, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return bundleJSON(t, map[string]any{
		"mediaType": sigstoreBundleV03,
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{"hint": hint}, "timestampVerificationData": map[string]any{},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(sum[:])},
			"signature":     base64.StdEncoding.EncodeToString(signature),
		},
	})
}

func bundleJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeBootstrap(t *testing.T, publishers ...map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "publishers.json")
	if err := os.WriteFile(path, bundleJSON(t, map[string]any{"schemaVersion": 1, "publishers": publishers}), 0444); err != nil {
		t.Fatal(err)
	}
	return path
}

func managedPublisher(policy string, keys ...map[string]any) map[string]any {
	publisher := map[string]any{"id": "stellwerk", "pluginIds": []string{"dev.stellwerk.native-probe"}, "keys": keys}
	if policy != "" {
		publisher["policy"] = policy
	}
	return publisher
}

const signedManifest = `{"schemaVersion":2,"artifactType":"application/vnd.stellwerk.plugin.package.v1","layers":[{"mediaType":"application/vnd.stellwerk.plugin.executable.v1","digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `","size":10}]}`

func verifyWith(t *testing.T, bootstrapPath string, bundle []byte, manifest string) (publisherKey, error) {
	t.Helper()
	bootstrap, err := loadTrustBootstrap(bootstrapPath)
	if err != nil {
		t.Fatal(err)
	}
	return verifyManagedKeySignature(bootstrap, "dev.stellwerk.native-probe", bundle, []byte(manifest), publisherTestNow, "")
}

func expectRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("expected refusal %q, got %v", reason, err)
	}
}

func TestManagedKeyPackageVerifiesOffline(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, signer.validPin()))
	bundle := signer.sign(t, []byte(signedManifest), signer.id)
	key, err := verifyWith(t, bootstrap, bundle, signedManifest)
	if err != nil || key.KeyID != signer.id {
		t.Fatalf("selected %q: %v", key.KeyID, err)
	}

	directory := t.TempDir()
	for name, data := range map[string][]byte{"bundle.json": bundle, "oci-manifest.json": []byte(signedManifest)} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0444); err != nil {
			t.Fatal(err)
		}
	}
	keyOut := filepath.Join(directory, "publisher.pub")
	if err := execute([]string{"verify-publisher", "--trust-bootstrap=" + bootstrap, "--bundle=" + filepath.Join(directory, "bundle.json"),
		"--oci-manifest=" + filepath.Join(directory, "oci-manifest.json"), "--plugin-id=dev.stellwerk.native-probe", "--key-out=" + keyOut}); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(keyOut)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(written)
	if block == nil || string(block.Bytes) != string(signer.der) {
		t.Fatal("verify-publisher wrote a key other than the pinned one")
	}
}

func TestNoTlogSignatureFailsForAPublisherPinnedWithTheDefaultPolicy(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	bundle := signer.sign(t, []byte(signedManifest), signer.id)
	for _, policy := range []string{sigstorePolicy, ""} {
		_, err := verifyWith(t, writeBootstrap(t, managedPublisher(policy, signer.validPin())), bundle, signedManifest)
		expectRefusal(t, err, "pinned with the sigstore policy, which requires transparency-log verification")
	}
}

func TestAKeyShippedWithThePackageNeverEstablishesTrust(t *testing.T) {
	pinned := newPublisherSigner(t, elliptic.P256())
	attacker := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, pinned.validPin()))

	_, err := verifyWith(t, bootstrap, attacker.sign(t, []byte(signedManifest), attacker.id), signedManifest)
	expectRefusal(t, err, "which publisher stellwerk does not pin")

	_, err = verifyWith(t, bootstrap, attacker.sign(t, []byte(signedManifest), pinned.id), signedManifest)
	expectRefusal(t, err, "does not verify with publisher stellwerk key")

	var withCertificate map[string]any
	if err := json.Unmarshal(attacker.sign(t, []byte(signedManifest), pinned.id), &withCertificate); err != nil {
		t.Fatal(err)
	}
	material := withCertificate["verificationMaterial"].(map[string]any)
	material["certificate"] = map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(attacker.der)}
	_, err = verifyWith(t, bootstrap, bundleJSON(t, withCertificate), signedManifest)
	expectRefusal(t, err, "carries its own certificate")

	// A package-supplied bootstrap pinning the attacker changes nothing: the
	// verifier reads only the operator's bootstrap.
	packageDirectory := t.TempDir()
	attackerBootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, attacker.validPin()))
	data, err := os.ReadFile(attackerBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"publishers.json": data, "bundle.json": attacker.sign(t, []byte(signedManifest), attacker.id), "oci-manifest.json": []byte(signedManifest),
	} {
		if err := os.WriteFile(filepath.Join(packageDirectory, name), content, 0444); err != nil {
			t.Fatal(err)
		}
	}
	err = execute([]string{"verify-publisher", "--trust-bootstrap=" + bootstrap, "--bundle=" + filepath.Join(packageDirectory, "bundle.json"),
		"--oci-manifest=" + filepath.Join(packageDirectory, "oci-manifest.json"), "--plugin-id=dev.stellwerk.native-probe",
		"--key-out=" + filepath.Join(packageDirectory, "publisher.pub")})
	expectRefusal(t, err, "does not pin")
	if _, statErr := os.Stat(filepath.Join(packageDirectory, "publisher.pub")); statErr == nil {
		t.Fatal("a refused verification still wrote a key")
	}
}

func TestTamperedManifestOrLayerReferenceFails(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, signer.validPin()))
	bundle := signer.sign(t, []byte(signedManifest), signer.id)
	for name, manifest := range map[string]string{
		"manifest byte":   strings.Replace(signedManifest, `"size":10`, `"size":11`, 1),
		"layer reference": strings.Replace(signedManifest, strings.Repeat("1", 64), strings.Repeat("2", 64), 1),
		"appended data":   signedManifest + " ",
	} {
		_, err := verifyWith(t, bootstrap, bundle, manifest)
		if err == nil {
			t.Fatalf("%s: tampered manifest verified", name)
		}
		expectRefusal(t, err, "does not cover this OCI manifest")
	}
	var forged map[string]any
	if err := json.Unmarshal(bundle, &forged); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(signedManifest, strings.Repeat("1", 64), strings.Repeat("2", 64), 1)
	sum := sha256.Sum256([]byte(tampered))
	forged["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["digest"] = base64.StdEncoding.EncodeToString(sum[:])
	_, err := verifyWith(t, bootstrap, bundleJSON(t, forged), tampered)
	expectRefusal(t, err, "does not verify with publisher stellwerk key")
}

func TestPublisherKeyValidityAndRotation(t *testing.T) {
	retired := newPublisherSigner(t, elliptic.P256())
	current := newPublisherSigner(t, elliptic.P256())
	upcoming := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy,
		retired.pin(publisherTestNow.AddDate(-1, 0, 0), publisherTestNow.Add(-time.Second)),
		current.validPin(),
		upcoming.pin(publisherTestNow.Add(time.Hour), publisherTestNow.AddDate(2, 0, 0))))
	if _, err := verifyWith(t, bootstrap, current.sign(t, []byte(signedManifest), current.id), signedManifest); err != nil {
		t.Fatal(err)
	}
	for _, signer := range []publisherSigner{retired, upcoming} {
		_, err := verifyWith(t, bootstrap, signer.sign(t, []byte(signedManifest), signer.id), signedManifest)
		expectRefusal(t, err, "is valid for new installations only from")
	}
	other := managedPublisher(managedKeyNoTlogPolicy, current.validPin())
	other["pluginIds"] = []string{"dev.example.partner-plugin"}
	bootstrap = writeBootstrap(t, other)
	_, err := verifyWith(t, bootstrap, current.sign(t, []byte(signedManifest), current.id), signedManifest)
	expectRefusal(t, err, "no publisher is pinned for plugin dev.stellwerk.native-probe")
}

func TestSignatureBundleShapeIsStrict(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy, signer.validPin()))
	change := func(edit func(map[string]any)) []byte {
		var bundle map[string]any
		if err := json.Unmarshal(signer.sign(t, []byte(signedManifest), signer.id), &bundle); err != nil {
			t.Fatal(err)
		}
		edit(bundle)
		return bundleJSON(t, bundle)
	}
	for name, test := range map[string]struct {
		bundle []byte
		reason string
	}{
		"old bundle version": {change(func(b map[string]any) { b["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1" }), "v0.3 bundle"},
		"no key hint": {change(func(b map[string]any) {
			b["verificationMaterial"].(map[string]any)["publicKey"] = map[string]any{}
		}), "names no public key"},
		"DSSE envelope": {change(func(b map[string]any) { b["dsseEnvelope"] = map[string]any{"payload": "e30="} }), "message signature"},
		"other digest": {change(func(b map[string]any) {
			b["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_384"
		}), "does not cover"},
		"not JSON":         {[]byte("{"), "not valid JSON"},
		"alternative v0.3": {change(func(b map[string]any) { b["mediaType"] = sigstoreBundleV03Alt }), ""},
	} {
		_, err := verifyWith(t, bootstrap, test.bundle, signedManifest)
		if test.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: expected %q, got %v", name, test.reason, err)
		}
	}
}

func TestTrustBootstrapIsValidatedStrictly(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	p384 := newPublisherSigner(t, elliptic.P384())
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pinWith := func(key string, value any) map[string]any {
		pin := signer.validPin()
		pin[key] = value
		return pin
	}
	rsaPin := pinWith("publicKey", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})))
	rsaPin["keyId"] = publisherKeyID(rsaDER)
	p384Pin := p384.validPin()
	partner := managedPublisher(managedKeyNoTlogPolicy, newPublisherSigner(t, elliptic.P256()).validPin())
	partner["id"] = "partner"
	for name, test := range map[string]struct {
		document any
		reason   string
	}{
		"schema version":       {map[string]any{"schemaVersion": 2, "publishers": []any{managedPublisher("", signer.validPin())}}, "schemaVersion 1"},
		"no publishers":        {map[string]any{"schemaVersion": 1, "publishers": []any{}}, "schemaVersion 1"},
		"unknown field":        {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", signer.validPin())}, "trustAll": true}, "unknown field"},
		"unknown policy":       {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("trust-on-first-use", signer.validPin())}}, "known policy"},
		"wrong key ID":         {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", pinWith("keyId", "AAAA"))}}, "keyId must be"},
		"wrong algorithm":      {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", pinWith("algorithm", "ed25519"))}}, "algorithm must be"},
		"RSA key":              {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", rsaPin)}}, "ECDSA P-256"},
		"P-384 key":            {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", p384Pin)}}, "ECDSA P-256"},
		"inverted validity":    {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", signer.pin(publisherTestNow, publisherTestNow.Add(-time.Hour)))}}, "validFrom must precede"},
		"duplicate key":        {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", signer.validPin(), signer.validPin())}}, "pinned more than once"},
		"plugin of two owners": {map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", signer.validPin()), partner}}, "exactly one publisher"},
	} {
		path := filepath.Join(t.TempDir(), "publishers.json")
		if err := os.WriteFile(path, bundleJSON(t, test.document), 0444); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTrustBootstrap(path); err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: expected %q, got %v", name, test.reason, err)
		}
	}
}

func manifestDigest(manifest string) string {
	sum := sha256.Sum256([]byte(manifest))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeBootstrapDocument(t *testing.T, document map[string]any) trustBootstrap {
	t.Helper()
	path := filepath.Join(t.TempDir(), "publishers.json")
	if err := os.WriteFile(path, bundleJSON(t, document), 0444); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := loadTrustBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap
}

// Without a transparency log nobody can prove when a package was signed, so
// the validity window decides new installations only. Re-fetching the digest
// an installation recorded keeps working after rotation retired the key.
func TestKeyValidityGatesNewInstallationsOnly(t *testing.T) {
	retired := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrapDocument(t, map[string]any{"schemaVersion": 1, "publishers": []any{
		managedPublisher(managedKeyNoTlogPolicy, retired.pin(publisherTestNow.AddDate(-2, 0, 0), publisherTestNow.AddDate(0, -1, 0))),
	}})
	bundle := retired.sign(t, []byte(signedManifest), retired.id)
	upgrade := manifestDigest(strings.Replace(signedManifest, `"size":10`, `"size":12`, 1))
	for name, installed := range map[string]string{"new installation": "", "upgrade to a new digest": upgrade} {
		_, err := verifyManagedKeySignature(bootstrap, "dev.stellwerk.native-probe", bundle, []byte(signedManifest), publisherTestNow, installed)
		if err == nil || !strings.Contains(err.Error(), "valid for new installations only") {
			t.Fatalf("%s with an expired key: %v", name, err)
		}
	}
	if _, err := verifyManagedKeySignature(bootstrap, "dev.stellwerk.native-probe", bundle, []byte(signedManifest),
		publisherTestNow, manifestDigest(signedManifest)); err != nil {
		t.Fatalf("re-fetch of the installed digest with a retired key: %v", err)
	}

	directory := t.TempDir()
	bootstrapPath := writeBootstrap(t, managedPublisher(managedKeyNoTlogPolicy,
		retired.pin(publisherTestNow.AddDate(-2, 0, 0), publisherTestNow.AddDate(0, -1, 0))))
	for name, data := range map[string][]byte{"bundle.json": bundle, "oci-manifest.json": []byte(signedManifest)} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0444); err != nil {
			t.Fatal(err)
		}
	}
	command := func(installed string) error {
		return execute([]string{"verify-publisher", "--trust-bootstrap=" + bootstrapPath, "--bundle=" + filepath.Join(directory, "bundle.json"),
			"--oci-manifest=" + filepath.Join(directory, "oci-manifest.json"), "--plugin-id=dev.stellwerk.native-probe",
			"--key-out=" + filepath.Join(directory, "publisher.pub"), "--installed-digest=" + installed})
	}
	expectRefusal(t, command(""), "valid for new installations only")
	if err := command(manifestDigest(signedManifest)); err != nil {
		t.Fatalf("CLI re-fetch of the installed digest: %v", err)
	}
	expectRefusal(t, command("sha256:ABC"), "canonical sha256 digest")
}

func TestRevokedKeyFailsForNewAndInstalledPackages(t *testing.T) {
	current := newPublisherSigner(t, elliptic.P256())
	retired := newPublisherSigner(t, elliptic.P256())
	bootstrap := writeBootstrapDocument(t, map[string]any{
		"schemaVersion": 1,
		"publishers": []any{managedPublisher(managedKeyNoTlogPolicy, current.validPin(),
			retired.pin(publisherTestNow.AddDate(-2, 0, 0), publisherTestNow.AddDate(0, -1, 0)))},
		"revokedKeyIds": []string{current.id, retired.id},
	})
	for _, signer := range []publisherSigner{current, retired} {
		bundle := signer.sign(t, []byte(signedManifest), signer.id)
		for name, installed := range map[string]string{"new installation": "", "re-fetch of the installed digest": manifestDigest(signedManifest)} {
			_, err := verifyManagedKeySignature(bootstrap, "dev.stellwerk.native-probe", bundle, []byte(signedManifest), publisherTestNow, installed)
			if err == nil || !strings.Contains(err.Error(), "which the trust bootstrap revokes") {
				t.Fatalf("%s with a revoked key: %v", name, err)
			}
		}
	}
}

func TestRevocationListIsValidated(t *testing.T) {
	signer := newPublisherSigner(t, elliptic.P256())
	for name, revoked := range map[string][]string{
		"not a key ID": {"compromised"},
		"short hash":   {base64.StdEncoding.EncodeToString([]byte("short"))},
		"duplicate":    {signer.id, signer.id},
	} {
		path := filepath.Join(t.TempDir(), "publishers.json")
		document := map[string]any{"schemaVersion": 1, "publishers": []any{managedPublisher("", signer.validPin())}, "revokedKeyIds": revoked}
		if err := os.WriteFile(path, bundleJSON(t, document), 0444); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTrustBootstrap(path); err == nil || !strings.Contains(err.Error(), "unique Cosign key hint") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
