package attestz_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openconfig/featureprofiles/internal/security/svid"

	common_definitions "github.com/openconfig/attestz/proto/common_definitions"
	attestz "github.com/openconfig/attestz/proto/tpm_enrollz"
	cmp "github.com/openconfig/featureprofiles/internal/components"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
)

var (
	controlcardType     = oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CONTROLLER_CARD
	primaryController   = oc.Platform_ComponentRedundantRole_PRIMARY
	secondaryController = oc.Platform_ComponentRedundantRole_SECONDARY
)

type cardCert struct {
	cardRole string
	certs    []string
}

var cardCertMap = []cardCert{
	{
		cardRole: "",
		certs:    []string{},
	},
	{
		cardRole: "",
		certs:    []string{},
	},
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// Ensure that we can call both controllers
func findControllers(t *testing.T, dut *ondatra.DUTDevice, controllers []string) (string, string) {
	var primary, secondary string
	for _, controller := range controllers {
		role := gnmi.Get(t, dut, gnmi.OC().Component(controller).RedundantRole().State())
		t.Logf("Component(controller).RedundantRole().Get(t): %v, Role: %v", controller, role)
		if role == secondaryController {
			secondary = controller
		} else if role == primaryController {
			primary = controller
		} else {
			t.Fatalf("Expected controller %s to be active or standby, got %v", controller, role)
		}
	}
	if secondary == "" || primary == "" {
		t.Fatalf("Expected non-empty primary and secondary Controller, got primary: %v, secondary: %v", primary, secondary)
	}
	t.Logf("Detected primary: %v, secondary: %v", primary, secondary)

	return secondary, primary
}

// Get vendor certs
func getVendorCerts(t *testing.T, enrollzC attestz.TpmEnrollzServiceClient, cardRole common_definitions.ControlCardRole) (string, string) {
	data, err := enrollzC.GetIakCert(context.Background(), &attestz.GetIakCertRequest{
		ControlCardSelection: &common_definitions.ControlCardSelection{
			ControlCardId: &common_definitions.ControlCardSelection_Role{
				Role: cardRole,
			},
		},
	})
	if err != nil {
		t.Errorf("Error with GetIAKCert %v", err)
	}
	return data.IakCert, data.IdevidCert
}

// Rotate Owner certs
func rotateOwnerCerts(t *testing.T, enrollzC attestz.TpmEnrollzServiceClient, cardRole common_definitions.ControlCardRole, oIAKCert string, oDevIDCert string) {
	_, err := enrollzC.RotateOIakCert(context.Background(), &attestz.RotateOIakCertRequest{
		ControlCardSelection: &common_definitions.ControlCardSelection{
			ControlCardId: &common_definitions.ControlCardSelection_Role{
				Role: cardRole,
			},
		},
		OiakCert:    oIAKCert,
		OidevidCert: oDevIDCert,
	})
	if err != nil {
		t.Errorf("Error with RotateOIakCert %v", err)
	}
}

// Generate Owner certs
func generateOwnerCerts(t *testing.T, caKey any, caCert *x509.Certificate, inputCert string) string {
	certPem, _ := pem.Decode([]byte(inputCert))
	if certPem == nil {
		t.Fatal("Error loading IDevID Certificate")
	}
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Generate Random Serial Number as per TCG Spec (between 64 and 160 bits)
	minVal := new(big.Int).Lsh(big.NewInt(1), 63)
	maxVal := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	serial, err := rand.Int(rand.Reader, new(big.Int).Sub(maxVal, minVal))
	if err != nil {
		t.Fatal(err)
	}
	serial = new(big.Int).Add(serial, minVal)

	// Generate Owner Certificate
	ownerCert := &x509.Certificate{
		SerialNumber:      serial,
		NotBefore:         time.Now(),
		NotAfter:          cert.NotAfter,
		Subject:           cert.Subject,
		KeyUsage:          cert.KeyUsage,
		ExtKeyUsage:       cert.ExtKeyUsage,
		PolicyIdentifiers: cert.PolicyIdentifiers,
	}

	// Sign Owner Certificate with Owner CA
	certBytes, err := x509.CreateCertificate(rand.Reader, ownerCert, caCert, cert.PublicKey, caKey)
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

// Parse through the received Certs from getIak() and validate the information received based on TCG.
// couldn't figure out how to pass []string - it didn't work with pem.Decode().
func validateCertInfo(t *testing.T, dut *ondatra.DUTDevice, cardList []cardCert) {
	for i, card := range cardList {
		certPem, _ := pem.Decode([]byte(card.certs[i]))
		if certPem == nil {
			t.Fatal("Error loading IDevID Certificate")
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		// Formatting time to RFC3339 to ensure ease for comparing.
		expectedTime, _ := time.Parse(time.RFC3339, "9999-12-31T23:59:59Z")
		if !expectedTime.Equal(cert.NotAfter) {
			t.Fatalf("Did not get expected NotAfter date, got: %v, want: %v", cert.NotAfter, expectedTime)
		}

		// Ensure that NotBefore is in the past (should be creation date of the cert, which should always be in the past)
		currentTime := time.Now()
		if currentTime.Before(cert.NotBefore) {
			t.Fatalf("Did not get expected NotBefore date, got: %v, want: earlier than %v", cert.NotBefore, currentTime)
		}

		// Verify that the certs match the serial number of the controller queried.
		serialNo := gnmi.Get(t, dut, gnmi.OC().Component(card.cardRole).SerialNo().State())
		if cert.Subject.SerialNumber != serialNo {
			t.Fatalf("Got wrong Serial number, got: %v, want: %v", cert.Subject.SerialNumber, serialNo)
		}

		if !strings.EqualFold(cert.Subject.Organization[0], dut.Vendor().String()) {
			t.Fatalf("Wrong Signature on Sub Org. got: %v, want: %v", strings.ToLower(cert.Subject.Organization[0]), strings.ToLower(dut.Vendor().String()))
		}
	}
}

func TestAttestz(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	caCertPem := flag.String("ca_cert_pem", "ca-0001-rsa-cert.pem", "a pem file for ca cert that will be used to sign oDevID/oIAK Certs")
	caKeyPem := flag.String("ca_key_pem", "ca-0001-rsa-key.pem", "a pem file for ca key that will be used to sign oDevID/oIAK Certs")

	// Setup gNSI client
	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
	if err != nil {
		t.Errorf("gNSI client error: %v", err)
	}
	// Setup Enrollz Client
	enrollzC := gnsiC.Enrollz()

	controllers := cmp.FindComponentsByType(t, dut, controlcardType)
	t.Logf("Found controller list: %v", controllers)

	// Only perform the switchover for the chassis with dual controllers.
	if len(controllers) != 2 {
		t.Skipf("Dual controllers required on %v: got %v, want 2", dut.Model(), len(controllers))
	}

	// Return the certs for Active Controller
	aIakCert, aIDevIdcert := getVendorCerts(t, enrollzC, common_definitions.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE)
	sIakCert, sIDevIdcert := getVendorCerts(t, enrollzC, common_definitions.ControlCardRole_CONTROL_CARD_ROLE_STANDBY)

	cardCertMap[0].certs = []string{aIakCert, aIDevIdcert} // position 0 = active
	cardCertMap[1].certs = []string{sIakCert, sIDevIdcert} // position 1 = standby

	// Identify which controller is Active/standby.
	secondary, primary := findControllers(t, dut, controllers)
	cardCertMap[0].cardRole = primary
	cardCertMap[1].cardRole = secondary
	// Validate certInfo
	validateCertInfo(t, dut, cardCertMap)

	// Generate Owner Certs
	caKey, caCert, err := svid.LoadKeyPair(*caKeyPem, *caCertPem)
	if err != nil {
		t.Fatalf("Could not load ca key/cert: %v", err)
	}
	aOIakCert := generateOwnerCerts(t, caKey, caCert, aIakCert)
	aODevIDCert := generateOwnerCerts(t, caKey, caCert, aIDevIdcert)
	sOIakCert := generateOwnerCerts(t, caKey, caCert, sIakCert)
	sODevIDCert := generateOwnerCerts(t, caKey, caCert, sIDevIdcert)

	// Rotate Owner Certificates
	rotateOwnerCerts(t, enrollzC, common_definitions.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE, aOIakCert, aODevIDCert)
	rotateOwnerCerts(t, enrollzC, common_definitions.ControlCardRole_CONTROL_CARD_ROLE_STANDBY, sOIakCert, sODevIDCert)

}
