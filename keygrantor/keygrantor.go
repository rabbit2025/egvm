package keygrantor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"

	ecies "github.com/ecies/go/v2"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/tyler-smith/go-bip32"
)

// #include "util.h"
import "C"

var (
	ExtPrivKey *bip32.Key
	ExtPubKey  *bip32.Key
	PrivKey    *ecies.PrivateKey

	ErrInDebugMode       = errors.New("Cannot work in debug mode")
	ErrTCBStatus         = errors.New("TCB is not up-to-date")
	ErrUniqueIDMismatch  = errors.New("UniqueID Mismatch")
	ErrSignerIDMismatch  = errors.New("SignerID Mismatch")
	ErrProductIDMismatch = errors.New("ProductID Mismatch")
)

func generateRandom64Bytes() []byte {
	var out []byte
	var x C.uint16_t
	var retry C.int = 1
	for i := 0; i < 64; i++ {
		C.rdrand_16(&x, retry)
		out = append(out, byte(x))
	}
	return out
}

func GetRandomExtPrivKey() *bip32.Key {
	seed := generateRandom64Bytes()
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		panic(err)
	}
	return key
}

func Bip32KeyToEciesKey(key *bip32.Key) *ecies.PrivateKey {
	return ecies.NewPrivateKeyFromBytes(key.Key)
}

func DeriveKey(key *bip32.Key, hash [32]byte) *bip32.Key {
	twoExp31 := big.NewInt(1<<31)
	n := big.NewInt(0).SetBytes(hash[:])
	lastAdd := uint32(0)
	lastAddUnit := uint32(1<<8)
	for i := 0; i < 9; i++ {
		remainder := big.NewInt(0)
		n.DivMod(n, twoExp31, remainder)
		for m := uint32(remainder.Uint64()); true; m++ {
			//fmt.Printf("i %d m %08x\n", i, m)
			var err error
			if i == 8 {
				key, err = key.NewChildKey(m)
			} else { //last round
				key, err = key.NewChildKey(m + lastAdd)
			}
			if err == nil {
				break
			} else { // very unlikely
				lastAdd += lastAddUnit
			}
		}
		lastAddUnit <<= 3;
	}
	return key
}

func NewKeyFromRootKey(rootKey *bip32.Key) *bip32.Key {
	child, err := rootKey.NewChildKey(0x80000000+44) // BIP44
	if err != nil {
		panic(err)
	}
	child, err = child.NewChildKey(0x80000000)//Bitcoin
	if err != nil {
		panic(err)
	}
	child, err = child.NewChildKey(0) //account=0
	if err != nil {
		panic(err)
	}
	child, err = child.NewChildKey(0) //chain=0
	if err != nil {
		panic(err)
	}
	child, err = child.NewChildKey(0) //address=0
	if err != nil {
		panic(err)
	}
	return child
}

	
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

func RecoverKeysFromFile(fname string) (extPrivKey *bip32.Key, extPubKey *bip32.Key, privKey *ecies.PrivateKey) {
	fileData, err := os.ReadFile(fname)
	if err != nil {
		fmt.Printf("Failed to read the file: %s\n", fname)
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
	extPubKey = extPrivKey.PublicKey()
	newKey := NewKeyFromRootKey(extPrivKey)
	privKey = Bip32KeyToEciesKey(newKey)
	return
}

func GetSelfReportAndCheck() attestation.Report {
	report, err := enclave.GetSelfReport()
	if err != nil {
		panic(err)
	}
	if report.Debug {
		panic(ErrInDebugMode)
	}
	if report.TCBStatus != tcbstatus.UpToDate {
		panic(ErrTCBStatus)
	}
	return report
}

func VerifyPeerReport(reportBytes []byte, selfReport attestation.Report) (attestation.Report, error) {
	report, err := enclave.VerifyRemoteReport(reportBytes)
	if err != nil {
		return report, err
	}
	if report.Debug {
		return report, ErrInDebugMode
	}
	if report.TCBStatus != tcbstatus.UpToDate {
		return report, ErrTCBStatus
	}
	if !bytes.Equal(selfReport.UniqueID, report.UniqueID) {
		return report, ErrUniqueIDMismatch
	}
	if !bytes.Equal(selfReport.SignerID, report.SignerID) {
		return report, ErrSignerIDMismatch
	}
	if !bytes.Equal(selfReport.ProductID, report.ProductID) {
		return report, ErrProductIDMismatch
	}
	return report, nil
}
