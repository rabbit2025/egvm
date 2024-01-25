package keygrantor

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/edgelesssys/ego/enclave"
	"github.com/tyler-smith/go-bip32"
)

type SimpleClient struct {
	ExtPrivKey *bip32.Key
	ExtPubKey  *bip32.Key
	PrivKey    *secp256k1.PrivateKey
	PubKeyBz   []byte
}

func (sc *SimpleClient) InitKeys(keySrc string, clientData [32]byte, loadFromFile bool) {
	if loadFromFile {
		fileExists := false
		sc.ExtPrivKey, fileExists = RecoverKeyFromFile(keySrc)
		if !fileExists {
			panic("Cannot find key file: "+ keySrc)
		}
	} else {
		var err error
		sc.ExtPrivKey, err = GetKeyFromKeyGrantor(keySrc, clientData)
		if err != nil {
			panic(err)
		}
	}
	sc.ExtPubKey = sc.ExtPrivKey.PublicKey()
	sc.PrivKey = secp256k1.PrivKeyFromBytes(sc.ExtPrivKey.Key)
	sc.PubKeyBz = sc.PrivKey.PubKey().SerializeCompressed()
}

type RandReader struct {
}

func (rr RandReader) Read(p []byte) (n int, err error) {
	out := GenerateRandomBytes(len(p))
	copy(p, out)
	return len(p), nil
}

func createCertificate(serverName string) ([]byte, crypto.PrivateKey, tls.Config) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: serverName},
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		DNSNames:     []string{serverName},
	}
	randReader := RandReader{}
	priv, _ := rsa.GenerateKey(randReader, 2048)
	cert, _ := x509.CreateCertificate(randReader, template, template, &priv.PublicKey, priv)
	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}
	return cert, priv, tlsCfg
}

func (sc *SimpleClient) CreateAndStartHttpsServer(serverName, listenURL string, handlers map[string]func(w http.ResponseWriter, r *http.Request)) {
	// Create a TLS config with a self-signed certificate and an embedded report.
	//tlsCfg, err := enclave.CreateAttestationServerTLSConfig()
	cert, _, tlsCfg := createCertificate(serverName)
	certHash := sha256.Sum256(cert)
	pubKeyHash := sha256.Sum256(sc.PubKeyBz)
	reportData := append(certHash[:], pubKeyHash[:]...)

	// init handler for remote attestation
	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hex.EncodeToString(cert))) 
	})
	// look up secp256k1 pubkey
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(hex.EncodeToString(pubKeyHash[:])))
		return
	})

	// attestation report to endorse certification and pubkey
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		peerReport, err := enclave.GetRemoteReport(reportData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
		w.Write([]byte(hex.EncodeToString(peerReport)))
	})

	// send jwt token
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var token string
		var err error
		for _, url := range AttestationProviderURLs {
			token, err = enclave.CreateAzureAttestationToken(reportData, url)
			if err == nil {
				break
			}
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(token))
	})

	for name, handler := range handlers {
		http.HandleFunc(name, handler)
	}

	server := http.Server{Addr: listenURL, TLSConfig: &tlsCfg, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err := server.ListenAndServeTLS("", "")
	fmt.Println(err)
}

