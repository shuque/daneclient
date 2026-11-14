// Command danecert generates client keys and certificates for testing
// DANE client authentication, and prints the TLSA record to publish.
//
//	danecert ee    -name <ClientName> -out <dir>   self-signed cert, TLSA 3 1 1
//	danecert ca    -cn <CA name> -out <dir>        private CA (ca.key, ca.crt)
//	danecert issue -ca <dir> -name <ClientName> -out <dir>
//	                                               CA-issued cert, TLSA 2 0 1
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	dane "github.com/shuque/dane/v2"
)

const usage = `usage:
  danecert ee    -name <ClientName> -out <dir> [-force]
  danecert ca    -cn <CA name> -out <dir> [-force]
  danecert issue -ca <dir> -name <ClientName> -out <dir> [-allow-underscore] [-force]`

var errUsage = errors.New(usage)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "danecert:", err)
		os.Exit(1)
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	fs := newFlags(args[0])
	out := fs.String("out", "", "output directory")
	force := fs.Bool("force", false, "overwrite existing files")
	var name, cn, caDir *string
	var allowUS *bool
	switch args[0] {
	case "ee":
		name = fs.String("name", "", "ClientName")
	case "ca":
		cn = fs.String("cn", "", "CA common name")
	case "issue":
		name = fs.String("name", "", "ClientName")
		caDir = fs.String("ca", "", "CA directory")
		allowUS = fs.Bool("allow-underscore", false, "allow underscore labels in the SAN dNSName")
	default:
		return fmt.Errorf("unknown subcommand %q\n%s", args[0], usage)
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return fmt.Errorf("bad arguments\n%s", usage)
	}
	if *out == "" || (name != nil && *name == "") || (cn != nil && *cn == "") || (caDir != nil && *caDir == "") {
		return fmt.Errorf("missing required flag\n%s", usage)
	}
	switch args[0] {
	case "ee":
		return genEE(stdout, *name, *out, *force)
	case "ca":
		return genCA(*cn, *out, *force)
	default:
		return issue(stdout, *caDir, *name, *out, *allowUS, *force)
	}
}

func hasUnderscoreLabel(name string) bool {
	for _, l := range strings.Split(name, ".") {
		if strings.HasPrefix(l, "_") {
			return true
		}
	}
	return false
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func clientTemplate(name string) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	t := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	return t, nil
}

func genEE(stdout io.Writer, name, out string, force bool) error {
	paths, err := prepare(out, force, "client.key", "client.crt")
	if err != nil {
		return err
	}
	key, err := newKey()
	if err != nil {
		return err
	}
	tmpl, err := clientTemplate(name)
	if err != nil {
		return err
	}
	if !hasUnderscoreLabel(name) {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writeKeyCert(paths, key, der); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return printTLSA(stdout, name, dane.DANEEE, dane.SelectorSPKI, cert)
}

func genCA(cn, out string, force bool) error {
	paths, err := prepare(out, force, "ca.key", "ca.crt")
	if err != nil {
		return err
	}
	key, err := newKey()
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	return writeKeyCert(paths, key, der)
}

func issue(stdout io.Writer, caDir, name, out string, allowUnderscore, force bool) error {
	if hasUnderscoreLabel(name) && !allowUnderscore {
		return fmt.Errorf("name %q has a label starting with '_'. RFC 5280 section 4.2.1.6 "+
			"(preferred name syntax) forbids underscores in a dNSName, and draft section 10 "+
			"applies. Many toolkits and private CAs will still issue such certificates for "+
			"DANE-TA, so pass -allow-underscore to do so. Public CAs will not, so use a "+
			"Format 3 (freeform) name instead. DANE-EE ('danecert ee') has no such "+
			"restriction, because the name need not appear in the certificate", name)
	}
	caCert, err := loadCert(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return err
	}
	caKey, err := loadKey(filepath.Join(caDir, "ca.key"))
	if err != nil {
		return err
	}
	paths, err := prepare(out, force, "client.key", "client.crt")
	if err != nil {
		return err
	}
	key, err := newKey()
	if err != nil {
		return err
	}
	tmpl, err := clientTemplate(name)
	if err != nil {
		return err
	}
	tmpl.DNSNames = []string{name}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeKeyCert(paths, key, der); err != nil {
		return err
	}
	return printTLSA(stdout, name, dane.DANETA, dane.SelectorCert, caCert)
}

func printTLSA(w io.Writer, name string, u dane.Usage, s dane.Selector, cert *x509.Certificate) error {
	// Usage 3 uses the SPKI selector and usage 2 the full certificate,
	// each with SHA-256.
	rec, err := dane.NewTLSA(u, s, dane.MatchSHA256, cert)
	if err != nil {
		return err
	}
	owner := name
	if !strings.HasSuffix(owner, ".") {
		owner += "."
	}
	_, err = fmt.Fprintf(w, "%s IN TLSA %s\n", owner, rec)
	return err
}

// prepare creates dir and returns the paths for the key and cert files,
// refusing to overwrite existing ones unless force is set.
func prepare(dir string, force bool, keyName, certName string) ([2]string, error) {
	p := [2]string{filepath.Join(dir, keyName), filepath.Join(dir, certName)}
	if !force {
		for _, f := range p {
			if _, err := os.Lstat(f); err == nil {
				return p, fmt.Errorf("%s exists; use -force to overwrite", f)
			}
		}
	}
	return p, os.MkdirAll(dir, 0o755)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode) // in case the file pre-existed (-force)
}

func writeKeyCert(paths [2]string, key *ecdsa.PrivateKey, certDER []byte) error {
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(paths[0], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return writeFile(paths[1], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644)
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ek, nil
}
