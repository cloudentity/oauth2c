package oauth2

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func ReadURL(location string, hc *http.Client) (data []byte, err error) {
	var resp *http.Response

	if resp, err = hc.Get(location); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if data, err = io.ReadAll(resp.Body); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to read data from url %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func ReadKeyPair(cert string, key string, hc *http.Client) (keyPair tls.Certificate, err error) {
	if strings.HasPrefix(cert, "http") && strings.HasPrefix(key, "http") {
		var (
			certPEM []byte
			keyPEM  []byte
		)

		if certPEM, err = ReadURL(cert, hc); err != nil {
			return tls.Certificate{}, err
		}

		if keyPEM, err = ReadURL(key, hc); err != nil {
			return tls.Certificate{}, err
		}

		return tls.X509KeyPair(certPEM, keyPEM)
	}

	return tls.LoadX509KeyPair(cert, key)
}

func ReadRootCA(location string, hc *http.Client) (pool *x509.CertPool, err error) {
	var rootCA []byte

	if pool, err = x509.SystemCertPool(); err != nil {
		return nil, err
	}

	if strings.HasPrefix(location, "http") {
		if rootCA, err = ReadURL(location, hc); err != nil {
			return nil, err
		}
	} else {
		if rootCA, err = os.ReadFile(location); err != nil {
			return nil, err
		}
	}

	pool.AppendCertsFromPEM(rootCA)

	return pool, nil
}
