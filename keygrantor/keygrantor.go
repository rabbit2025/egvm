package keygrantor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/tyler-smith/go-bip32"
)

// #include "util.h"
import "C"

var (
	ErrInDebugMode        = errors.New("Cannot work in debug mode")
	ErrTCBStatus          = errors.New("TCB is not up-to-date")
	ErrUniqueIDMismatch   = errors.New("UniqueID Mismatch")
	ErrSignerIDMismatch   = errors.New("SignerID Mismatch")
	ErrProductIDMismatch  = errors.New("ProductID Mismatch")
	ErrReportDataMismatch = errors.New("ReportData Mismatch")

	AttestationProviderURLs = []string{
		"https://sharedeus2.eus2.attest.azure.net",
		"https://sharedcus.cus.attest.azure.net",
		"https://shareduks.uks.attest.azure.net",
		"https://sharedeus.eus.attest.azure.net",
		"https://sharedcae.cae.attest.azure.net",
	}
)

type GetKeyParams struct {
	Report string `json:"Report"`
	JWT    string `json:"JWT"`
}

// Use Intel CPU's true random number generator to get random data
func GenerateRandomBytes(count int) []byte {
	out := make([]byte, count)
	var x C.uint16_t
	var retry C.int = 1
	for i := 0; i < count; i++ {
		C.rdrand16(&x, retry)
		out[i] = byte(x)
	}
	return out
}

// Use Intel CPU's true random number generator to get an extended private key
// NewMasterKey may fail if random private key < secp256k1.S256().N (very unlikely), so we need to retry
func GetRandomExtPrivKey() *bip32.Key {
	for {
		seed := GenerateRandomBytes(64)
		key, err := bip32.NewMasterKey(seed)
		if err == nil {
			return key
		}
	}
	return nil
}

// Derive from the root key using a 9-depth path. Each level consumes 31 bits.
// NewChildKey may return non-nil error because validatePrivateKey may fail with a very low
// possibility. So we must add retry logic at each depth by repeatly increasing 'm'.
// The bits 8~10/11~13/14~16/17~19/20~22/23~25/26~29/30~32 of lastAdd will be used for record the retry
// count of depth 0/1/2/3/4/5/6/7. At depth=8, lastAdd will be added to 'm' as extra entropy.
func DeriveKey(key *bip32.Key, hash [32]byte) *bip32.Key {
	twoExp31 := big.NewInt(1 << 31)
	n := big.NewInt(0).SetBytes(hash[:])
	lastAdd := uint32(0)
	lastAddUnit := uint32(1 << 8)
	for i := 0; i < 9; i++ {
		remainder := big.NewInt(0)
		n.DivMod(n, twoExp31, remainder)
		for m := uint32(remainder.Uint64()); true; m++ {
			//fmt.Printf("i %d m %08x\n", i, m)
			var err error
			if i == 8 { //last round
				key, err = key.NewChildKey(m + lastAdd)
			} else {
				key, err = key.NewChildKey(m)
			}
			if err == nil {
				break
			} else { // very unlikely
				lastAdd += lastAddUnit
			}
		}
		lastAddUnit <<= 3
	}
	return key
}

// Encrypt the extended private key with a key derived from a measurement of the enclave, and
// then save the encrypted key to file
func SealKeyToFile(fname string, extPrivKey *bip32.Key) {
	bz, err := extPrivKey.Serialize()
	if err != nil {
		panic(err)
	}
	out, err := ecrypto.SealWithUniqueKey(bz, nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(fname, out, 0600)
	if err != nil {
		panic(err)
	}
}

// Read encrypted key from file and decrypt it
func RecoverKeyFromFile(fname string) (extPrivKey *bip32.Key, fileExists bool) {
	fileData, err := os.ReadFile(fname)
	if err != nil {
		fmt.Printf("read file failed, %s\n", err.Error())
		if os.IsNotExist(err) {
			return nil, false
		}
		panic(err)
	}
	rawData, err := ecrypto.Unseal(fileData, nil)
	if err != nil {
		fmt.Printf("unseal file data failed, %s\n", err.Error())
		panic(err)
	}
	extPrivKey, err = bip32.Deserialize(rawData)
	if err != nil {
		fmt.Printf("deserialize xprv failed, %s\n", err.Error())
		panic(err)
	}
	return extPrivKey, true
}

// Get SelfReport and check it against RemoteReport of the same enclave
func GetSelfReportAndCheck() attestation.Report {
	selfReport, err := enclave.GetSelfReport()
	if err != nil {
		panic(err)
	}
	if selfReport.Debug {
		panic(ErrInDebugMode)
	}
	reportBytes, err := enclave.GetRemoteReport([]byte{0x01})
	if err != nil {
		panic(err)
	}
	report, err := enclave.VerifyRemoteReport(reportBytes)
	if err != nil {
		panic(err)
	}
	err = VerifyPeerReport(report, selfReport)
	if err != nil {
		panic(err)
	}
	return selfReport
}

// Verify report against selfReport to ensure they are from the same enclave.
func VerifyPeerReport(report, selfReport attestation.Report) error {
	if report.Debug {
		return ErrInDebugMode
	}
	if report.TCBStatus != tcbstatus.UpToDate {
		return ErrTCBStatus
	}
	if !bytes.Equal(selfReport.UniqueID, report.UniqueID) {
		fmt.Println(hex.EncodeToString(selfReport.UniqueID))
		fmt.Println(hex.EncodeToString(report.UniqueID))
		return fmt.Errorf("ErrUniqueIDMismatch: %s != %s",
			hex.EncodeToString(selfReport.UniqueID),
			hex.EncodeToString(report.UniqueID),
		)
		// return ErrUniqueIDMismatch
	}
	if !bytes.Equal(selfReport.SignerID, report.SignerID) {
		return ErrSignerIDMismatch
	}
	if !bytes.Equal(selfReport.ProductID, report.ProductID) {
		return ErrProductIDMismatch
	}
	return nil
}

// Send a http post request using json payload
func HttpPost(url string, jsonReq []byte) ([]byte, error) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(jsonReq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get key, http status:%s, content:%s", resp.Status, string(body))
	}
	return body, nil
}

// Return true if it's a valid secp256k1 private key
func IsValidPrivateKey(key []byte) bool {
	k := big.NewInt(0).SetBytes(key)
	return len(key) == 32 && k.Sign() != 0 /*not zero*/ && k.Cmp(secp256k1.S256().N) < 0 /*in range*/
}

// Generate a new eceis.PrivateKey from random data
func GenerateEciesPrivateKey() *ecies.PrivateKey {
	for {
		bz := GenerateRandomBytes(32)
		if IsValidPrivateKey(bz) {
			return ecies.NewPrivateKeyFromBytes(bz)
		}
	}
	return nil
}

// A downstream peer gets the main xprv key from the upstream peer with clientData equaling all-zero
// An enclave gets its derived key from the upstream peer with non-zero clientData
func GetKeyFromKeyGrantor(keyGrantorUrl string, clientData [32]byte) (*bip32.Key, error) {
	privKey := GenerateEciesPrivateKey()
	pubkey := privKey.PublicKey.Bytes(true)
	pubkeyHash := sha256.Sum256(pubkey)
	data := append(pubkeyHash[:], clientData[:]...)
	report, err := enclave.GetRemoteReport(data)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote report: %w", err)
	}
	var token string
	for _, url := range AttestationProviderURLs {
		token, err = enclave.CreateAzureAttestationToken(data, url)
		if err != nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation report: %w", err)
	}
	url := "%s/getkey?pubkey=%s"
	if big.NewInt(0).SetBytes(clientData[:]).Sign() == 0 { // clientData is all zero
		url = "%s/xprv?pubkey=%s"
	}
	url = fmt.Sprintf(url, keyGrantorUrl, hex.EncodeToString(pubkey))
	params := GetKeyParams{
		Report: hex.EncodeToString(report),
		JWT:    token,
	}
	jsonReq, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	res, err := HttpPost(url, jsonReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("failed to get key: no resust data")
	}
	resBz, err := hex.DecodeString(string(res))
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	keyBz, err := ecies.Decrypt(privKey, resBz)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message from server: %w", err)
	}
	outKey, err := bip32.Deserialize(keyBz)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize the key from server: %w", err)
	}
	return outKey, nil
}

// Verify JWT and ensures it's from the same enclave that generates 'report'
func VerifyJWT(token string, report attestation.Report) (err error) {
	for _, url := range AttestationProviderURLs {
		tokenReport, err := attestation.VerifyAzureAttestationToken(token, url)
		if err == nil {
			return VerifyPeerReport(tokenReport, report)
		}
	}
	return
}
