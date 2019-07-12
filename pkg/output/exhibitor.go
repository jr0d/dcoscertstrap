package output

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"time"

	"github.com/jr0d/dcoscertstrap/pkg/gen"
	keystore "github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/afero"
)

// AppFs afero file system abstraction
var AppFs = afero.NewOsFs()

func makeTrustStore(caPath string) (keystore.KeyStore, error) {
	certBytes, err := gen.ReadCertificatePEM(caPath)
	if err != nil {
		return nil, fmt.Errorf("error reading %s : %v", caPath, err)
	}

	ks := keystore.KeyStore{}
	ks["root-cert"] = &keystore.TrustedCertificateEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: certBytes,
		},
	}
	return ks, nil
}

func makeEntityStore(alias, entity string) (keystore.KeyStore, error) {
	keyPem, certPem := gen.StorePath(entity+"-key.pem"), gen.StorePath(entity+"-cert.pem")

	key, err := gen.ReadPrivateKeyBytes(keyPem)
	if err != nil {
		return nil, fmt.Errorf("error reading %s : %v", keyPem, err)
	}

	cert, err := gen.ReadCertificatePEM(certPem)
	if err != nil {
		return nil, fmt.Errorf("error reading %s : %v", certPem, err)
	}

	ks := keystore.KeyStore{}
	ks[alias] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey: key,
		CertChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: cert,
			},
		},
	}
	return ks, nil
}

func writeKeyStore(ks keystore.KeyStore, path, password string) error {
	o, err := AppFs.Create(path)
	if err != nil {
		return fmt.Errorf("error creating %s : %v", path, err)
	}
	defer o.Close()

	log.Printf("Creating %s", path)
	if err := keystore.Encode(o, ks, []byte(password)); err != nil {
		return fmt.Errorf("error encoding keystore: %v", err)
	}
	return nil
}

func copyFile(src, destDir string, mode os.FileMode) error {
	destPath := path.Join(destDir, path.Base(src))

	s, err := AppFs.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := AppFs.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer d.Close()

	log.Printf("Copying %s to %s", src, destPath)
	_, err = io.Copy(d, s)
	if err != nil {
		return err
	}
	return nil
}

// WriteArtifacts creates exhibitor TLS artifacts for DC/OS
func WriteArtifacts(dir, caPath, serverEntity, clientEntity, password string) error {

	if err := AppFs.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating %s : %v", dir, err)
	}

	ts, err := makeTrustStore(caPath)
	if err != nil {
		return err
	}
	if err := writeKeyStore(ts, path.Join(dir, "truststore.jks"), password); err != nil {
		return err
	}

	ss, err := makeEntityStore("server", serverEntity)
	if err != nil {
		return err
	}
	if err := writeKeyStore(ss, path.Join(dir, "serverstore.jks"), password); err != nil {
		return err
	}

	cs, err := makeEntityStore("client", clientEntity)
	if err != nil {
		return err
	}
	if err := writeKeyStore(cs, path.Join(dir, "clientstore.jks"), password); err != nil {
		return err
	}

	serverKey, serverCert := gen.StorePath(serverEntity+"-key.pem"), gen.StorePath(serverEntity+"-cert.pem")
	if err := copyFile(serverKey, dir, 0600); err != nil {
		return err
	}
	if err := copyFile(serverCert, dir, 0644); err != nil {
		return err
	}

	clientKey, clientCert := gen.StorePath(clientEntity+"-key.pem"), gen.StorePath(clientEntity+"-cert.pem")
	if err := copyFile(clientKey, dir, 0600); err != nil {
		return err
	}
	if err := copyFile(clientCert, dir, 0644); err != nil {
		return err
	}

	return nil
}
