package attestz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/featureprofiles/internal/security/svid"
	"github.com/openconfig/ondatra/gnmi/oc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/testing/protocmp"
	"math/big"
	"net"
	"os"
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
	"github.com/openconfig/featureprofiles/internal/components"
)

type ControlCard struct {
	Role       cdpb.ControlCardRole
	Name       string
	IAKCert    string
	IDevIDCert string
	OIAKCert   string
	ODevIDCert string
	MtlsCert   string
}

var (
	chassisName     string
	activeCard      *ControlCard
	standbyCard     *ControlCard
	pcrBankHashAlgo = []attestzpb.Tpm20HashAlgo{
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA1,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA384,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA512,
	}
	PcrBankHashAlgoMap = map[ondatra.Vendor][]attestzpb.Tpm20HashAlgo{
		ondatra.NOKIA:   {attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA1, attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256},
		ondatra.ARISTA:  pcrBankHashAlgo,
		ondatra.JUNIPER: pcrBankHashAlgo,
		ondatra.CISCO:   pcrBankHashAlgo,
	}
	PcrIndices = []int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}
)

func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func GenOwnerCert(t *testing.T, caKey any, caCert *x509.Certificate, inputCert string, pubKey any, attestzTarget string) string {
	cert, err := LoadCertificate(inputCert)
	if err != nil {
		t.Fatalf("Error loading vendor certificate: %v", err)
	}
	if pubKey == nil {
		pubKey = cert.PublicKey
	}

	// Generate Random Serial Number as per TCG Spec (between 64 and 160 bits)
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf#page=55
	minBits := 64
	maxBits := 160
	minVal := new(big.Int).Lsh(big.NewInt(1), uint(minBits-1)) // minVal = 2^63
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(maxBits))   // maxVal = 2^160
	// Random number between [2^63, 2^160)
	serial, err := rand.Int(rand.Reader, maxVal.Sub(maxVal, minVal))
	if err != nil {
		t.Fatalf("Error generating serial number. err: %s", err)
	}
	serial.Add(minVal, serial)
	t.Logf("Serial Number: %s", serial)

	// Get IP Address from gnsi target
	ip, _, err := net.SplitHostPort(attestzTarget)
	if err != nil {
		t.Errorf("Error parsing host-port info. err: %v", err)
	}

	// Generate Owner Certificate
	ownerCert := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     cert.NotAfter,
		Subject:      cert.Subject,
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsage:  cert.ExtKeyUsage,
		IPAddresses:  []net.IP{net.ParseIP(ip)},
	}

	// Sign Owner Certificate with Owner CA
	certBytes, err := x509.CreateCertificate(rand.Reader, ownerCert, caCert, pubKey, caKey)
	if err != nil {
		t.Fatalf("Could not generate owner certificate: %v", err)
	}

	// PEM Encode Owner Certificate
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, pemBlock); err != nil {
		t.Fatalf("Could not PEM encode owner certificate: %v", err)
	}

	return certPEM.String()
}

func (cc *ControlCard) EnrollzWorkflow(t *testing.T, dut *ondatra.DUTDevice, tc *TlsConf, vendorCaCertFile string) {
	var as *AttestzSession
	as = tc.NewAttestzSession(t)
	defer as.Conn.Close()

	// Determines how the getRequest is crafted (role)
	roleA := ParseRoleSelection(t, cc.Role)

	// Get Vendor Certs
	resp := as.GetVendorCerts(t, roleA)
	cc.IAKCert, cc.IDevIDCert = resp.IakCert, resp.IdevidCert

	// Validate correct cert used for TLS connection.
	var certPem *pem.Block
	if activeCard.MtlsCert != "" {
		certPem, _ = pem.Decode([]byte(activeCard.MtlsCert))
	} else if activeCard.ODevIDCert != "" {
		// TLS session is secured with active controller's oDevID if enrolling secondary controller.
		certPem, _ = pem.Decode([]byte(activeCard.ODevIDCert))
	} else {
		certPem, _ = pem.Decode([]byte(activeCard.IDevIDCert))
	}
	if certPem == nil {
		t.Fatalf("Unable to PEM decode cert")
	}
	wantPeerCert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		t.Fatalf("Unable to parse cert. err: %s", err)
	}
	tlsInfo := as.Peer.AuthInfo.(credentials.TLSInfo)
	gotPeerCert := tlsInfo.State.PeerCertificates[0]
	if diff := cmp.Diff(wantPeerCert, gotPeerCert); diff != "" {
		t.Errorf("Incorrect certificate used for enrollz TLS session. -want,+got: %s", diff)
	}

	// Load Vendor CA Cert
	vendorCaPem, err := os.ReadFile(vendorCaCertFile)
	if err != nil {
		t.Fatalf("Error reading vendor cert: %v", err)
	}

	// Validate Cert Info
	t.Logf("Verifying IDevID cert for card %v", cc.Name)
	cc.validateCert(t, dut, string(vendorCaPem), "idevid")
	t.Logf("Verifying IAK cert for card %v", cc.Name)
	cc.validateCert(t, dut, string(vendorCaPem), "iak")
	t.Logf("Validating control card details for card %v", cc.Name)
	cc.validateControlCardInfo(t, dut, resp.ControlCardId)

	// Generate Owner Certs
	caKey, caCert, err := svid.LoadKeyPair(tc.CaKeyFile, tc.CaCertFile)
	if err != nil {
		t.Fatalf("Could not load ca key/cert: %v", err)
	}
	t.Logf("Generating oIAK cert for card %v", cc.Name)
	cc.OIAKCert = GenOwnerCert(t, caKey, caCert, cc.IAKCert, nil, tc.Target)
	t.Logf("Generating oDevID cert for card %v", cc.Name)
	cc.ODevIDCert = GenOwnerCert(t, caKey, caCert, cc.IDevIDCert, nil, tc.Target)

	// Rotate Owner Certificates
	as.RotateOwnerCerts(t, cc.Role, cc.OIAKCert, cc.ODevIDCert, sslProfileId)
}

func (cc *ControlCard) AttestzWorkflow(t *testing.T, dut *ondatra.DUTDevice, tc *TlsConf) {
	var as *AttestzSession
	as = tc.NewAttestzSession(t)
	defer as.Conn.Close()

	for _, hashAlgo := range PcrBankHashAlgoMap[dut.Vendor()] {
		// Generate Random Nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Error generating nonce: %v", err)
		}

		t.Logf("Attest & Verify for card %v, hash algo: %v", cc.Name, hashAlgo.String())
		attestResponse := as.RequestAttestation(t, cc.Role, nonce, hashAlgo, PcrIndices)

		// Validate active controller's oDevID cert is used for TLS connection.
		var certPem *pem.Block
		if activeCard.MtlsCert != "" {
			certPem, _ = pem.Decode([]byte(activeCard.MtlsCert))
		} else {
			certPem, _ = pem.Decode([]byte(activeCard.ODevIDCert))
		}
		if certPem == nil {
			t.Fatalf("Unable to PEM decode cert")
		}
		wantPeerCert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			t.Fatalf("Unable to parse cert. err: %s", err)
		}
		tlsInfo := as.Peer.AuthInfo.(credentials.TLSInfo)
		gotPeerCert := tlsInfo.State.PeerCertificates[0]
		if diff := cmp.Diff(wantPeerCert, gotPeerCert); diff != "" {
			t.Errorf("Incorrect certificate used for attestz TLS session. -want,+got:\n%s", diff)
		}

		cc.verifyAttestation(t, dut, attestResponse, nonce, hashAlgo, PcrIndices)
	}
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
func (as *AttestzSession) GetVendorCerts(t *testing.T, cardSelection *cdpb.ControlCardSelection) *enrollzpb.GetIakCertResponse {
	enrollzRequest := &enrollzpb.GetIakCertRequest{
		ControlCardSelection: cardSelection,
	}
	t.Logf("Sending Enrollz.GetIakCert request on device: \n %s", PrettyPrint(enrollzRequest))
	response, err := as.EnrollzClient.GetIakCert(context.Background(), enrollzRequest, grpc.Peer(as.Peer))
	if err != nil {
		t.Fatalf("Error getting vendor certs %v", err)
	}
	t.Logf("GetIakCert response: \n %s", PrettyPrint(response))
	return response
}

// Rotate Owner certs
func (as *AttestzSession) RotateOwnerCerts(t *testing.T, cardRole cdpb.ControlCardRole, oIAKCert string, oDevIDCert string, sslProfileId string) {
	enrollzRequest := &enrollzpb.RotateOIakCertRequest{
		ControlCardSelection: ParseRoleSelection(t, cardRole),
		OiakCert:             oIAKCert,
		OidevidCert:          oDevIDCert,
		SslProfileId:         sslProfileId,
	}
	t.Logf("Sending Enrollz.Rotate request on device: \n %s", PrettyPrint(enrollzRequest))
	_, err := as.EnrollzClient.RotateOIakCert(context.Background(), enrollzRequest, grpc.Peer(as.Peer))
	if err != nil {
		t.Fatalf("Error with RotateOIakCert %v", err)
	}
	// Brief sleep for rotate to get processed.
	time.Sleep(time.Second)
}

// Request Attestaion
func (as *AttestzSession) RequestAttestation(t *testing.T, cardRole cdpb.ControlCardRole, nonce []byte, hashAlgo attestzpb.Tpm20HashAlgo, pcrIndices []int32) *attestzpb.AttestResponse {
	attestzRequest := &attestzpb.AttestRequest{
		ControlCardSelection: ParseRoleSelection(t, cardRole),
		Nonce:                nonce,
		HashAlgo:             hashAlgo,
		PcrIndices:           pcrIndices,
	}
	t.Logf("Sending Attestz.Attest request on device: \n %s", PrettyPrint(attestzRequest))
	response, err := as.AttestzClient.Attest(context.Background(), attestzRequest, grpc.Peer(as.Peer))
	if err != nil {
		t.Fatalf("Error with AttestRequest %v", err)
	}
	t.Logf("Attest response: \n %s", PrettyPrint(response))
	return response
}

func LoadCertificate(cert string) (*x509.Certificate, error) {
	certPem, _ := pem.Decode([]byte(cert))
	if certPem == nil {
		return nil, fmt.Errorf("Error decoding certificate.")
	}
	return x509.ParseCertificate(certPem.Bytes)
}

// Need to rework this as not using cardCert anymore.
func (cc *ControlCard) validateCert(t *testing.T, dut *ondatra.DUTDevice, vendorCaCert string, certType string) {
	vendorCa, err := LoadCertificate(vendorCaCert)
	if err != nil {
		t.Fatalf("Error loading vendor ca certificate: %v", err)
	}

	var cert string
	switch certType {
	case "idevid":
		cert = cc.IDevIDCert
	case "iak":
		cert = cc.IAKCert
	}

	vendorCert, err := LoadCertificate(cert)
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
	serialNo := gnmi.Get[string](t, dut, gnmi.OC().Component(cc.Name).SerialNo().State())
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
	default:
		t.Errorf("Cannot verify signature for %v. Certificate: %s", vendorCert.SignatureAlgorithm, PrettyPrint(vendorCert))
	}
}

func (cc *ControlCard) validateControlCardInfo(t *testing.T, dut *ondatra.DUTDevice, gotCardDetails *cdpb.ControlCardVendorId) {
	controller := gnmi.Get[*oc.Component](t, dut, gnmi.OC().Component(cc.Name).State())
	if chassisName == "" {
		chassisName = components.FindComponentsByType(t, dut, oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CHASSIS)[0]
	}
	chassis := gnmi.Get[*oc.Component](t, dut, gnmi.OC().Component(chassisName).State())
	wantCardDetails := &cdpb.ControlCardVendorId{
		ControlCardRole:     cc.Role,
		ControlCardSerial:   controller.GetSerialNo(),
		ControlCardSlot:     string(controller.GetLocation()[len(controller.GetLocation())-1]),
		ChassisManufacturer: chassis.GetMfgName(),
		ChassisSerialNumber: chassis.GetSerialNo(),
		ChassisPartNumber:   chassis.GetPartNo(),
	}

	if diff := cmp.Diff(gotCardDetails, wantCardDetails, protocmp.Transform()); diff != "" {
		t.Errorf("Got diff in got/want vendor card details: %s", diff)
	}
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
	ver := gnmi.Get[string](t, dut, gnmi.OC().System().SoftwareVersion().State())
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
	cardDesc := gnmi.Get[string](t, dut, gnmi.OC().Component(cardName).Description().State())
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
func (cc *ControlCard) verifyAttestation(t *testing.T, dut *ondatra.DUTDevice, attestResponse *attestzpb.AttestResponse, wantNonce []byte, hashAlgo attestzpb.Tpm20HashAlgo, pcrIndices []int32) {
	// Verify oIAK cert is the same as the one installed earlier.
	if !cmp.Equal(attestResponse.OiakCert, cc.OIAKCert) {
		t.Errorf("Got incorrect oIAK Cert, got: %v, want: %v", attestResponse.OiakCert, cc.OIAKCert)
	}

	// Verify all pcr_values match expectations
	switch dut.Vendor() {
	case ondatra.NOKIA:
		nokiaPCRVerify(t, dut, cc.Name, hashAlgo, attestResponse.PcrValues)
	default:
		t.Error("Vendor reference pcr values not verified.")
	}

	// Retrieve quote signature in TPM Object
	quoteTpmtSignature, err := tpm2.Unmarshal[tpm2.TPMTSignature](attestResponse.QuoteSignature)
	if err != nil {
		t.Fatalf("Error unmarshalling signature: %v", err)
	}

	// Default Hash Algo is SHA256 as per TPM2_Quote()
	// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_quote.1.md
	sigHashAlgo := crypto.SHA256

	oIakCert, err := LoadCertificate(cc.OIAKCert)
	if err != nil {
		t.Fatalf("Error loading vendor oIAK certificate: %v", err)
	}

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
		oIAKPubKey := oIakCert.PublicKey.(*rsa.PublicKey)
		// Verify quote signature with oIAK cert.
		err = rsa.VerifyPKCS1v15(oIAKPubKey, sigHashAlgo, quoteHash, quoteTpmsSignature.Sig.Buffer)
		if err != nil {
			t.Fatalf("Failed verifying Quote Signature: %v", err)
		}
	default:
		t.Errorf("Cannot verify signature for %v. quote sig: %s", quoteTpmtSignature.SigAlg, PrettyPrint(quoteTpmtSignature))
	}

	// Concatenate PCR Values & Generate PCR digest
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
	if !cmp.Equal(gotPcrDigest, wantPcrDigest) {
		t.Fatalf("Did not receive expected PCR Digest from Attest, got: %v, want: %v", gotPcrDigest, wantPcrDigest)
	}

	// Verify Nonce
	gotNonce := quoted.ExtraData.Buffer
	if !cmp.Equal(gotNonce, wantNonce) {
		t.Logf("Did not receive expected Nonce, got: %v, want: %v", gotNonce, wantNonce)
	}
}
