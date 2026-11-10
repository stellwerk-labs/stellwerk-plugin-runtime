package main

import (
	"archive/tar"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The transport contains only the package's unchanged OCI closure. Its hash
// is an operator input; publisher authentication remains the inner release set.
const httpsArchiveLimit = packageLimit + 8<<20 + 4096*1024
const httpsEntryLimit = 4096

type httpsCredentials struct {
	Auths map[string]struct {
		Auth string `json:"auth"`
	} `json:"auths"`
}

func packageURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("package URL must be HTTPS without credentials, query or fragment")
	}
	return u, nil
}

func downloadPackage(raw, hash, credentialsPath, caPath, destination string, redirectHosts ...string) error {
	u, err := packageURL(raw)
	if err != nil {
		return err
	}
	data, err := boundedRegularFile(credentialsPath, 16<<10)
	if err != nil {
		return errors.New("HTTPS credentials file unavailable")
	}
	var credentials httpsCredentials
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&credentials) != nil || decoder.Decode(new(any)) != io.EOF || len(credentials.Auths) != 1 {
		return errors.New("HTTPS credentials require exactly one host-scoped auth entry")
	}
	entry, ok := credentials.Auths[u.Host]
	decoded, decodeErr := base64.StdEncoding.DecodeString(entry.Auth)
	username, password, found := strings.Cut(string(decoded), ":")
	if !ok || decodeErr != nil || !found || username == "" || password == "" {
		return errors.New("HTTPS credentials require Basic auth for the exact URL host")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caPath != "" {
		ca, err := boundedRegularFile(caPath, 1<<20)
		if err != nil || !roots.AppendCertsFromPEM(ca) {
			return errors.New("HTTPS CA file is unavailable or invalid")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableCompression: true, ResponseHeaderTimeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	allowed := map[string]bool{}
	for _, host := range redirectHosts {
		parsed, err := packageURL("https://" + host)
		if err != nil || parsed.Host != host || parsed.Path != "" {
			return errors.New("invalid HTTPS redirect host")
		}
		allowed[host] = true
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		// GitLab may redirect to a signed object-store URL. That request gets
		// no GitLab headers, even if an approved redirect uses the same host.
		next.Header = make(http.Header)
		if len(via) != 1 || next.URL.Scheme != "https" || next.URL.User != nil || next.URL.Fragment != "" || !allowed[next.URL.Host] {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	request, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.New("invalid HTTPS package request")
	}
	request.SetBasicAuth(username, password)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("HTTPS package download failed (connection or TLS)")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTPS package download returned HTTP %d; redirect absent or refused", response.StatusCode)
	}
	if response.ContentLength > httpsArchiveLimit || response.Header.Get("Content-Encoding") != "" {
		return errors.New("HTTPS package exceeds the archive limit or has an unsupported encoding")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	checksum := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, checksum), io.LimitReader(response.Body, httpsArchiveLimit+1))
	if err != nil {
		return errors.New("HTTPS package download interrupted")
	}
	if size > httpsArchiveLimit {
		return errors.New("HTTPS package exceeds the archive limit")
	}
	if hex.EncodeToString(checksum.Sum(nil)) != hash {
		return errors.New("HTTPS package archive SHA256 does not match approved release")
	}
	return file.Close()
}

// Extraction owns an empty temporary directory and admits only fixed OCI
// paths. No archive-selected destination, link, mode or ownership is applied.
func extractPackageArchive(archive, destination string) (*bundleLayout, error) {
	file, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	footer := make([]byte, 1024)
	if err != nil || !info.Mode().IsRegular() || info.Size() > httpsArchiveLimit || info.Size() < 1024 || info.Size()%512 != 0 {
		return nil, errors.New("package tar is not a bounded complete archive")
	}
	if _, err := file.ReadAt(footer, info.Size()-1024); err != nil || !allZero(footer) {
		return nil, errors.New("package tar is missing its end marker")
	}
	reader := tar.NewReader(io.LimitReader(file, httpsArchiveLimit+1))
	layout := &bundleLayout{dir: destination, present: map[string]bool{}, reached: map[string]bool{}}
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid package tar: %w", err)
		}
		name := header.Name
		directory := header.Typeflag == tar.TypeDir && (name == "blobs/" || name == "blobs/sha256/" || name == "blobs" || name == "blobs/sha256")
		blob := strings.TrimPrefix(name, "blobs/sha256/")
		if count >= httpsEntryLimit || seen[strings.TrimSuffix(name, "/")] || header.Size < 0 || header.Size > binaryLimit ||
			(!directory && (header.Typeflag != tar.TypeReg || (name != "oci-layout" && name != "index.json" && (blob == name || !validSHA256(blob))))) {
			return nil, errors.New("package tar has an unexpected, duplicate or oversized entry")
		}
		seen[strings.TrimSuffix(name, "/")] = true
		if directory {
			continue
		}
		total += header.Size
		if total > httpsArchiveLimit {
			return nil, errors.New("package tar exceeds the archive limit")
		}
		if (name == "oci-layout" || name == "index.json") && header.Size > ociMetadataLimit {
			return nil, errors.New("package tar metadata exceeds the limit")
		}
		path := filepath.Join(destination, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, copyErr := io.Copy(out, reader)
		closeErr := out.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if blob != name {
			layout.present[blob] = true
		}
	}
	// tar.Reader stops at its end marker. Only tar padding may follow it.
	padding := make([]byte, 8192)
	for {
		n, err := file.Read(padding)
		if !allZero(padding[:n]) {
			return nil, errors.New("package tar has data after its end marker")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return layout, nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func fetchHTTPS(args []string) error {
	flags := flag.NewFlagSet("fetch-https", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	url := flags.String("url", "", "approved HTTPS archive URL")
	hash := flags.String("archive-sha256", "", "approved archive SHA256")
	credentials := flags.String("credentials", "", "single-host dockerconfigjson Basic credentials file")
	ca := flags.String("ca-file", "", "independent public TLS CA file")
	redirectHosts := flags.String("redirect-hosts", "", "approved exact HTTPS redirect hosts, comma separated")
	output := flags.String("package-dir", "", "empty package destination")
	evidence := flags.String("evidence-dir", "", "empty signature and attestation destination")
	bootstrapPath := flags.String("trust-bootstrap", "", "independent operator trust bootstrap")
	installed := flags.String("installed-digest", "", "digest recorded by the existing installation")
	m := bundleManifest{}
	flags.StringVar(&m.PluginID, "plugin-id", "", "approved plugin ID")
	flags.StringVar(&m.PluginVersion, "plugin-version", "", "approved plugin version")
	flags.StringVar(&m.Package.Digest, "package-digest", "", "approved package digest")
	flags.StringVar(&m.Package.ManifestSHA256, "manifest-sha256", "", "approved plugin manifest hash")
	flags.StringVar(&m.Package.Signature, "signature-digest", "", "signature referrer digest")
	flags.StringVar(&m.Package.SBOM, "sbom-digest", "", "SBOM referrer digest")
	flags.StringVar(&m.Package.Provenance, "provenance-digest", "", "provenance referrer digest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validSHA256(*hash) || !pluginIDPattern.MatchString(m.PluginID) || !versionPattern.MatchString(m.PluginVersion) || !validDigest(m.Package.Digest) || !validSHA256(m.Package.ManifestSHA256) || !validDigest(m.Package.Signature) ||
		(m.Package.SBOM != "" && !validDigest(m.Package.SBOM)) || (m.Package.Provenance != "" && !validDigest(m.Package.Provenance)) || (*installed != "" && !validDigest(*installed)) || !filepath.IsAbs(*output) || !filepath.IsAbs(*evidence) || *output == *evidence {
		return errors.New("HTTPS fetch requires approved identity/version, archive/package/manifest/signature pins and separate absolute output directories")
	}
	// Reject stale output before credentials or network use. This command is for
	// an init container's fresh emptyDir, never an in-place installation update.
	for _, dir := range []string{*output, *evidence} {
		entries, err := os.ReadDir(dir)
		info, statErr := os.Lstat(dir)
		if err != nil || statErr != nil || !info.IsDir() || len(entries) != 0 {
			return errors.New("HTTPS output directories must be empty real directories")
		}
	}
	bootstrap, err := loadTrustBootstrap(*bootstrapPath)
	if err != nil {
		return err
	}
	if _, err := pinnedPublisher(bootstrap, m.PluginID); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("", "plugin-https-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	archive := filepath.Join(temporary, "plugin.tar")
	hosts := []string{}
	if *redirectHosts != "" {
		hosts = strings.Split(*redirectHosts, ",")
	}
	if err := downloadPackage(*url, *hash, *credentials, *ca, archive, hosts...); err != nil {
		return err
	}
	layoutDir := filepath.Join(temporary, "layout")
	if err := os.Mkdir(layoutDir, 0700); err != nil {
		return err
	}
	layout, err := extractPackageArchive(archive, layoutDir)
	if err != nil {
		return err
	}
	entries := []bundleEntry{{"package", m.Package.Digest, ociManifestMediaType}, {"package signature", m.Package.Signature, ociManifestMediaType}}
	for _, part := range []struct{ name, digest string }{{"SBOM", m.Package.SBOM}, {"provenance", m.Package.Provenance}} {
		if part.digest != "" {
			entries = append(entries, bundleEntry{part.name, part.digest, ociManifestMediaType})
		}
	}
	listed, err := layout.index(entries)
	if err != nil {
		return err
	}
	signature, err := layout.verifyPackage(m, listed, bootstrap, time.Now(), *installed)
	if err != nil {
		return err
	}
	if err := layout.foreign(); err != nil {
		return err
	}
	manifest, err := layout.read(listed[m.Package.Digest], ociMetadataLimit)
	if err != nil {
		return err
	}
	var envelope ociManifest
	if err := json.Unmarshal(manifest, &envelope); err != nil {
		return err
	}
	// The existing envelope gate validated every title. These files remain
	// unexecuted until independent Cosign and normal package validation finish.
	for _, layer := range envelope.Layers {
		source, err := layout.locate(layer)
		if err != nil {
			return err
		}
		target := filepath.Join(*output, filepath.FromSlash(layer.Annotations[titleAnnotation]))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := copyPackageFile(source, target, layer.Size); err != nil {
			return err
		}
	}
	if err := writeFileAtomically(filepath.Join(*output, "oci-manifest.json"), manifest, 0444); err != nil {
		return err
	}
	if err := writeFileAtomically(filepath.Join(*evidence, "oci-manifest.sigstore.json"), signature, 0444); err != nil {
		return err
	}
	for _, part := range []struct{ name, digest, predicate string }{{"sbom", m.Package.SBOM, sbomPredicateType}, {"provenance", m.Package.Provenance, provenancePredicateType}} {
		if part.digest == "" {
			continue
		}
		data, err := layout.referrer(listed[part.digest], listed[m.Package.Digest], part.predicate)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(*evidence, part.name), 0700); err != nil {
			return err
		}
		if err := writeFileAtomically(filepath.Join(*evidence, part.name, part.name+".sigstore.json"), data, 0444); err != nil {
			return err
		}
	}
	return nil
}

func copyPackageFile(source, target string, size int64) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, size+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != size {
		return errors.New("verified package file changed size")
	}
	return nil
}
