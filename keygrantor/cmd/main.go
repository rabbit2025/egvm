package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/enclave"
	"github.com/tyler-smith/go-bip32"

	"github.com/smartbch/egvm/keygrantor"
)

var (
	ExtPrivKey *bip32.Key
	ExtPubKey  *bip32.Key

	KeyFile = "/data/key.txt"
	Zero32  = [32]byte{}
)

func main() {
	keySrc := flag.String("xprvsrc", "", "the server from which we can sync xprv key")
	listenAddrP := flag.String("listen", "0.0.0.0:8084", "listen address")
	keyFile := flag.String("keyfile", KeyFile, "key file")
	testData := flag.String("testdata", "", "test data")
	flag.Parse()

	if testData != nil && len(*testData) > 0 {
		cd := [32]byte{}
		td, err := hex.DecodeString(*testData)
		if err != nil {
			panic(err)
		}
		copy(cd[:], td)

		ExtPrivKey, err := keygrantor.GetKeyFromKeyGrantor(*keySrc, cd)
		fmt.Println("got priv key from KG !!!")
		fmt.Println(ExtPrivKey.String())
		if err != nil {
			panic(err)
		}
		return
	}

	var fileExists bool
	ExtPrivKey, fileExists = keygrantor.RecoverKeyFromFile(*keyFile)
	if !fileExists {
		if keySrc == nil || len(*keySrc) == 0 {
			fmt.Println("gen new priv key !!!")
			ExtPrivKey = keygrantor.GetRandomExtPrivKey()
		} else {
			var err error
			ExtPrivKey, err = keygrantor.GetKeyFromKeyGrantor(*keySrc, Zero32)
			fmt.Println("got priv key from KG !!!")
			if err != nil {
				panic(err)
			}
		}
		keygrantor.SealKeyToFile(*keyFile, ExtPrivKey)
	}
	ExtPubKey = ExtPrivKey.PublicKey()
	listenAddr := *listenAddrP
	go createAndStartHttpServer(listenAddr)
	select {}
}

func createAndStartHttpServer(listenAddr string) {
	// Return the extended public key
	http.HandleFunc("/xpub", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handle xpub ...")
		w.Write([]byte(ExtPubKey.B58Serialize()))
	})

	// Get remote attestion report to endorse the extended public key
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handle report ...")
		hash := sha256.Sum256([]byte(ExtPubKey.B58Serialize()))
		report, err := enclave.GetRemoteReport(hash[:])
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(hex.EncodeToString(report)))
	})

	// Peer keygrantors get ExtPrivKey through '/xprv'
	http.HandleFunc("/xprv", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handle xprv ...")
		pubKey, pubkeyBz := handleRequesterPubkey(w, r)
		if pubKey == nil {
			return
		}
		report := handleGetKeyParam(w, r, pubkeyBz)
		if report == nil {
			return
		}
		if len(report.Data) != 64 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("report data must 64bytes long"))
			return
		}
		if !bytes.Equal(Zero32[:], report.Data[32:]) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("non-zero clientData"))
			return
		}
		selfReport := keygrantor.GetSelfReportAndCheck()
		err := keygrantor.VerifyPeerReport(*report, selfReport)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("report check failed: " + err.Error()))
			return
		}
		derivedKeyBz, _ := ExtPrivKey.Serialize()
		bz, err := ecies.Encrypt(pubKey, derivedKeyBz)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("failed to encrypted xprv"))
			return
		}
		w.Write([]byte(hex.EncodeToString(bz)))
	})

	// For requestors to get derived key
	http.HandleFunc("/getkey", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handle getkey ...")
		pubKey, pubkeyBz := handleRequesterPubkey(w, r)
		if pubKey == nil {
			return
		}
		report := handleGetKeyParam(w, r, pubkeyBz)
		if report == nil {
			return
		}
		handleKeyDerive(w, report, pubKey)
	})

	server := http.Server{Addr: listenAddr, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	log.Fatal(server.ListenAndServe())
}

// Parse query parameter 'pubkey' to get ecies.PublicKey for encrypting the returned key
func handleRequesterPubkey(w http.ResponseWriter, r *http.Request) (*ecies.PublicKey, []byte) {
	pubkeys := r.URL.Query()["pubkey"]
	if len(pubkeys) == 0 || len(pubkeys[0]) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing pubkey parameter"))
		return nil, nil
	}
	requesterPubkeyBz, err := hex.DecodeString(pubkeys[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("pubkey hex string decode error"))
		return nil, nil
	}
	requesterPubKey, err := ecies.NewPublicKeyFromBytes(requesterPubkeyBz) // requester embeds its pubkey here
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("pubkey decode err: " + err.Error()))
		return nil, nil
	}
	return requesterPubKey, requesterPubkeyBz
}

// Decode GetKeyParams from http requet's body and then check the attestion report and the JWT
func handleGetKeyParam(w http.ResponseWriter, r *http.Request, pubkeyBz []byte) *attestation.Report {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to read request body"))
		return nil
	}
	var params keygrantor.GetKeyParams
	err = json.Unmarshal(body, &params)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("failed to unmarshal request body"))
		return nil
	}
	reportBz, err := hex.DecodeString(params.Report)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("report decode error"))
		return nil
	}
	report, err := enclave.VerifyRemoteReport(reportBz)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("report check failed: " + err.Error()))
		return nil
	}
	if len(report.Data) != 64 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("report data must 64bytes long"))
		return nil
	}
	pubkeyHash := sha256.Sum256(pubkeyBz)
	if !bytes.Equal(pubkeyHash[:], report.Data[:32]) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("pubkey not match the pubkey hash"))
		return nil
	}
	err = keygrantor.VerifyJWT(params.JWT, report)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("jwt token verify failed: " + err.Error()))
		return nil
	}
	return &report
}

// Derive a xprv key from ExtPrivKey and the requestor's UniqueID and clientData
func handleKeyDerive(w http.ResponseWriter, report *attestation.Report, requesterPubKey *ecies.PublicKey) {
	// concat uniqueid and client-specific data, then hash it for more flexible key deriving
	derivedKey := keygrantor.DeriveKey(ExtPrivKey, sha256.Sum256(append(report.UniqueID, report.Data[32:]...)))
	derivedKeyBz, _ := derivedKey.Serialize()
	bz, err := ecies.Encrypt(requesterPubKey, derivedKeyBz)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to encrypted derivedKey"))
		return
	}
	w.Write([]byte(hex.EncodeToString(bz)))
}
