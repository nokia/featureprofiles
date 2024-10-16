package attestz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"golang.org/x/exp/slices"

	cdpb "github.com/openconfig/attestz/proto/common_definitions"
	attestzpb "github.com/openconfig/attestz/proto/tpm_attestz"
	enrollzpb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

type AttestzSession struct {
	EnrollzClient enrollzpb.TpmEnrollzServiceClient
	AttestzClient attestzpb.TpmAttestzServiceClient
}

func NewAttestzSession(t *testing.T, target string) *AttestzSession {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{
				InsecureSkipVerify: true,
			})),
	)
	if err != nil {
		t.Fatalf("Could not connect gnsi %v", err)
	}
	return &AttestzSession{
		EnrollzClient: enrollzpb.NewTpmEnrollzServiceClient(conn),
		AttestzClient: attestzpb.NewTpmAttestzServiceClient(conn),
	}
}

type CardCert struct {
	CardName   string
	IAKCert    string
	IDevIDCert string
	OIAKCert   string
	ODevIDCert string
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// Return crafted getRequest with cardIDSelection_Role
func ParseRoleSelection(t *testing.T, inputRole cdpb.ControlCardRole) *cdpb.ControlCardSelection {
	return &cdpb.ControlCardSelection{
		ControlCardId: &cdpb.ControlCardSelection_Role{
			Role: inputRole,
		},
	}
}

// Return crafted getRequest with cardIDSelection_Serial
func ParseSerialSelection(t *testing.T, inputSerial string) *cdpb.ControlCardSelection {
	return &cdpb.ControlCardSelection{
		ControlCardId: &cdpb.ControlCardSelection_Serial{
			Serial: inputSerial,
		},
	}
}

// Return crafted getRequest with cardIDSelection_Slot
func ParseSlotSelection(t *testing.T, enzList *enrollzpb.GetIakCertRequest, inputSlot string) *cdpb.ControlCardSelection {
	return &cdpb.ControlCardSelection{
		ControlCardId: &cdpb.ControlCardSelection_Slot{
			Slot: inputSlot,
		},
	}
}

// Get vendor certs
func GetVendorCerts(t *testing.T, target string, cardSelection *cdpb.ControlCardSelection) (string, string) {
	as := NewAttestzSession(t, target)
	data, err := as.EnrollzClient.GetIakCert(context.Background(), &enrollzpb.GetIakCertRequest{
		ControlCardSelection: cardSelection,
	})
	if err != nil {
		t.Errorf("Error getting vendor certs %v", err)
	}
	return data.IakCert, data.IdevidCert
}

// Rotate Owner certs
func RotateOwnerCerts(t *testing.T, target string, cardRole cdpb.ControlCardRole, oIAKCert string, oDevIDCert string, sslProfileId string) {
	as := NewAttestzSession(t, target)
	attestzRequest := &enrollzpb.RotateOIakCertRequest{
		ControlCardSelection: ParseRoleSelection(t, cardRole),
		OiakCert:             oIAKCert,
		OidevidCert:          oDevIDCert,
		SslProfileId:         sslProfileId,
	}
	t.Logf("Sending Attestz.Rotate request on device: \n %s", prettyPrint(attestzRequest))
	_, err := as.EnrollzClient.RotateOIakCert(context.Background(), attestzRequest)
	if err != nil {
		t.Errorf("Error with RotateOIakCert %v", err)
	}
}

func LoadCertificate(certBytes []byte) (*x509.Certificate, error) {
	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		return nil, fmt.Errorf("Error decoding cert")
	}
	return x509.ParseCertificate(certPem.Bytes)
}

// Need to rework this as not using cardCert anymore.
func ValidateCertInfo(t *testing.T, dut *ondatra.DUTDevice, vendorCertBytes []byte, cardName string, vendorCaCertBytes []byte) {
	vendorCa, err := LoadCertificate(vendorCaCertBytes)
	if err != nil {
		t.Fatalf("Error loading vendor CA certificate: %v", err)
	}
	vendorCert, err := LoadCertificate(vendorCertBytes)
	if err != nil {
		t.Fatalf("Error loading vendor certificate: %v", err)
	}

	// Formatting time to RFC3339 to ensure ease for comparing.
	expectedTime, _ := time.Parse(time.RFC3339, "9999-12-31T23:59:59Z")
	if !expectedTime.Equal(vendorCert.NotAfter) {
		t.Fatalf("Did not get expected NotAfter date, got: %v, want: %v", vendorCert.NotAfter, expectedTime)
	}

	// Ensure that NotBefore is in the past (should be creation date of the cert, which should always be in the past)
	currentTime := time.Now()
	if currentTime.Before(vendorCert.NotBefore) {
		t.Fatalf("Did not get expected NotBefore date, got: %v, want: earlier than %v", vendorCert.NotBefore, currentTime)
	}

	// Verify that the certs match the serial number of the controller queried.
	serialNo := gnmi.Get(t, dut, gnmi.OC().Component(cardName).SerialNo().State())
	if vendorCert.Subject.SerialNumber != serialNo {
		t.Fatalf("Got wrong Serial number, got: %v, want: %v", vendorCert.Subject.SerialNumber, serialNo)
	}

	if !strings.EqualFold(vendorCert.Subject.Organization[0], dut.Vendor().String()) {
		t.Fatalf("Wrong Signature on Sub Org. got: %v, want: %v", strings.ToLower(vendorCert.Subject.Organization[0]), strings.ToLower(dut.Vendor().String()))
	}

	// Verify Cert is signed by Switch Vendor CA
	switch vendorCert.SignatureAlgorithm {
	case x509.SHA384WithRSA:
		// Generate Hash from Raw Certificate
		certHash := generateHash(t, vendorCert.RawTBSCertificate, crypto.SHA384)

		// Retrieve CA Public Key
		vendorCaPubKey := vendorCa.PublicKey.(*rsa.PublicKey)

		// Verify digital signature with oIAK cert.
		err = rsa.VerifyPKCS1v15(vendorCaPubKey, crypto.SHA384, certHash, vendorCert.Signature)
		if err != nil {
			t.Fatalf("Failed verifying vendor certificate's signature: %v", err)
		}
	}
}

// Request Attestaion
func RequestAttestation(t *testing.T, target string, cardRole cdpb.ControlCardRole, nonce []byte, hashAlgo attestzpb.Tpm20HashAlgo, pcrIndices []int32) *attestzpb.AttestResponse {
	as := NewAttestzSession(t, target)
	response, err := as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
		ControlCardSelection: ParseRoleSelection(t, cardRole),
		Nonce:                nonce,
		HashAlgo:             hashAlgo,
		PcrIndices:           pcrIndices,
	})
	if err != nil {
		t.Errorf("Error with AttestRequest %v", err)
	}
	return response
}

func generateHash(t *testing.T, quote []byte, hashAlgo crypto.Hash) []byte {
	switch hashAlgo {
	case crypto.SHA1:
		quoteHash := sha1.Sum(quote)
		return quoteHash[:]
	case crypto.SHA256:
		quoteHash := sha256.Sum256(quote)
		return quoteHash[:]
	case crypto.SHA384:
		quoteHash := sha512.Sum384(quote)
		return quoteHash[:]
	case crypto.SHA512:
		quoteHash := sha512.Sum512(quote)
		return quoteHash[:]
	}
	return nil
}

// Verify Nokia PCR with expected values
// Ensure secure-boot is enabled
func nokiaPCRVerify(t *testing.T, dut *ondatra.DUTDevice, cardName string, hashAlgo attestzpb.Tpm20HashAlgo, gotPcrValues map[int32][]byte) {
	ver := gnmi.Get(t, dut, gnmi.OC().System().SoftwareVersion().State())
	t.Logf("Found Software Version: %v", ver)

	// Expected Pcr values for Nokia present in /mnt/nokiaos/<build binary.bin>/known_good_pcr_values.json
	sshC, err := dut.RawAPIs().BindingDUT().DialCLI(context.Background())
	if err != nil {
		t.Logf("Could not connect ssh: %v", err)
	}
	cmd := fmt.Sprintf("cat /mnt/nokiaos/%s/known_good_pcr_values.json", ver)
	res, err := sshC.RunCommand(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Could not run command: %v, err: %v", cmd, err)
	}

	// Parse Json file into object
	type PcrValuesData struct {
		Pcr   int32  `json:"pcr"`
		Value string `json:"value"`
	}
	type PcrBankData struct {
		Bank   string          `json:"bank"`
		Values []PcrValuesData `json:"values"`
	}
	type CardData struct {
		Card string        `json:"card"`
		Pcrs []PcrBankData `json:"pcrs"`
	}
	type PcrData struct {
		Cards []CardData `json:"cards"`
	}
	var nokiaPcrData PcrData
	err = json.Unmarshal([]byte(res.Output()), &nokiaPcrData)
	if err != nil {
		t.Fatalf("Could not parse json: %v", err)
	}

	hashAlgoMap := map[attestzpb.Tpm20HashAlgo]string{
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA1:   "sha1",
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256: "sha256",
	}

	// Verify pcr_values match expectations
	pcrIndices := []int32{0, 2, 4, 6, 9, 14}
	cardDesc := gnmi.Get(t, dut, gnmi.OC().Component(cardName).Description().State())
	idx := slices.IndexFunc(nokiaPcrData.Cards, func(c CardData) bool {
		return c.Card == cardDesc
	})
	if idx == -1 {
		t.Fatalf("Could not find %v card in nokiaPcrData", cardDesc)
	}

	pcrBankData := nokiaPcrData.Cards[idx].Pcrs
	idx = slices.IndexFunc(pcrBankData, func(p PcrBankData) bool {
		return p.Bank == hashAlgoMap[hashAlgo]
	})
	if idx == -1 {
		t.Fatalf("Could not find %v pcr bank in nokiaPcrData", hashAlgoMap[hashAlgo])
	}

	wantPcrValues := pcrBankData[idx].Values
	for _, pcrIndex := range pcrIndices {
		idx = slices.IndexFunc(wantPcrValues, func(p PcrValuesData) bool {
			return p.Pcr == pcrIndex
		})
		if idx == -1 {
			t.Fatalf("Could not find pcr index %v in nokiaPcrData", pcrIndex)
		}
		got := hex.EncodeToString(gotPcrValues[pcrIndex])
		want := wantPcrValues[idx].Value
		if got != want {
			t.Errorf("%v pcr %v value does not match expectations, got: %v want: %v", hashAlgoMap[hashAlgo], pcrIndex, got, want)
		}
	}
}

// Verify Attestation
func VerifyAttestation(t *testing.T, dut *ondatra.DUTDevice, attestResponse *attestzpb.AttestResponse, cardCert *CardCert, wantNonce []byte, hashAlgo attestzpb.Tpm20HashAlgo, pcrIndices []int32) {
	// Verify oIAK cert is the same as the one installed earlier.
	if attestResponse.OiakCert != cardCert.OIAKCert {
		t.Errorf("Got incorrect oIAK Cert, got: %v, want: %v", attestResponse.OiakCert, cardCert.OIAKCert)
	}

	// Verify all pcr_values match expectations
	switch dut.Vendor() {
	case ondatra.NOKIA:
		nokiaPCRVerify(t, dut, cardCert.CardName, hashAlgo, attestResponse.PcrValues)
	}

	certPem, _ := pem.Decode([]byte(cardCert.OIAKCert))
	if certPem == nil {
		t.Fatal("Error loading IDevID Certificate")
	}
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve quote signature in TPM Object
	quoteTpmtSignature, err := tpm2.Unmarshal[tpm2.TPMTSignature](attestResponse.QuoteSignature)
	if err != nil {
		t.Fatalf("Error unmarshalling signature: %v", err)
	}

	var sigHashAlgo crypto.Hash
	switch quoteTpmtSignature.SigAlg {
	case tpm2.TPMAlgRSASSA:
		quoteTpmsSignature, err := quoteTpmtSignature.Signature.RSASSA()
		if err != nil {
			t.Fatalf("Error getting TPMS Signature: %v", err)
		}

		// Retrieve Signature's Hash Algo
		sigHashAlgo, err = quoteTpmsSignature.Hash.Hash()
		if err != nil {
			t.Fatalf("Error retrieving Signature Hash Algorithm: %v", err)
		}

		// Generate Hash from Original Quote
		quoteHash := generateHash(t, attestResponse.Quoted, sigHashAlgo)

		// Retrieve oIAK Public Key
		oIAKPubKey := cert.PublicKey.(*rsa.PublicKey)

		// Verify quote signature with oIAK cert.
		err = rsa.VerifyPKCS1v15(oIAKPubKey, sigHashAlgo, quoteHash, quoteTpmsSignature.Sig.Buffer)
		if err != nil {
			t.Fatalf("Failed verifying Quote Signature: %v", err)
		}
	}

	// Concatenate PCR Values & Generate PCR digest
	// Default Hash Algo is SHA256 as per TPM2_Quote()
	var concatPcrs []byte
	for _, idx := range pcrIndices {
		concatPcrs = append(concatPcrs, attestResponse.PcrValues[idx]...)
	}
	wantPcrDigest := generateHash(t, concatPcrs, sigHashAlgo)

	// Retrieve PCR digest from Quote
	quoted, err := tpm2.Unmarshal[tpm2.TPMSAttest](attestResponse.Quoted)
	if err != nil {
		t.Fatalf("Error unmarshalling quote: %v", err)
	}
	tpmsQuoteInfo, err := quoted.Attested.Quote()
	if err != nil {
		t.Fatalf("Error getting TPMS Quote Info: %v", err)
	}
	gotPcrDigest := tpmsQuoteInfo.PCRDigest.Buffer

	// Verify recomputed PCR digest matches with PCR digest in Quote
	if !bytes.Equal(gotPcrDigest, wantPcrDigest) {
		t.Fatalf("Did not receive expected PCR Digest from Attest, got: %v, want: %v", gotPcrDigest, wantPcrDigest)
	}

	// Verify Nonce
	gotNonce := quoted.ExtraData.Buffer
	if !bytes.Equal(gotNonce, wantNonce) {
		t.Logf("Did not receive expected Nonce, got: %v, want: %v", gotNonce, wantNonce)
	}
}
