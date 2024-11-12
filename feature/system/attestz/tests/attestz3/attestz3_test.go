package attestz3

import (
	"context"
	"crypto/rand"
	"flag"
	"github.com/google/go-cmp/cmp"
	cdpb "github.com/openconfig/attestz/proto/common_definitions"
	attestzpb "github.com/openconfig/attestz/proto/tpm_attestz"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/security/attestz"
	"github.com/openconfig/featureprofiles/internal/security/svid"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"testing"
)

const (
	controlcardType = oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CONTROLLER_CARD
	cdpbActive      = cdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE
	cdpbStandby     = cdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY
)

type attestResponse struct {
	activeCard  *attestzpb.AttestResponse
	standbyCard *attestzpb.AttestResponse
}

var (
	vendorCaCertPem = flag.String("switch_vendor_ca_cert", "Nokia_Bundle.pem", "a pem file for vendor ca cert used for verifying iDevID/IAK Certs")
	ownerCaCertPem  = flag.String("switch_owner_ca_cert", "ca-0001-rsa-cert.pem", "a pem file for ca cert that will be used to sign oDevID/oIAK Certs")
	ownerCaKeyPem   = flag.String("switch_owner_ca_key", "ca-0001-rsa-key.pem", "a pem file for ca key that will be used to sign oDevID/oIAK Certs")
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestAttestz3(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	attestzTarget, attestzServer := attestz.SetupBaseline(t, dut)
	t.Cleanup(func() {
		gnmi.Delete(t, dut, gnmi.OC().System().GrpcServer(*attestzServer.Name).Config())
		attestz.DeleteProfile(t, dut, *attestzServer.SslProfileId)
	})

	tc := &attestz.TlsConf{
		Target:     attestzTarget,
		CaKeyFile:  *ownerCaKeyPem,
		CaCertFile: *ownerCaCertPem,
	}

	// Find active and standby card.
	activeCard, standbyCard := attestz.SetupCards(t, dut)

	// Execute initial install workflow
	activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
	standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
	activeCard.AttestzWorkflow(t, dut, tc)
	standbyCard.AttestzWorkflow(t, dut, tc)

	// Create client and server certificates for mtls connection.
	caKey, caCert, err := svid.LoadKeyPair(tc.CaKeyFile, tc.CaCertFile)
	if err != nil {
		t.Fatalf("Could not load ca key/cert: %v", err)
	}
	clientIP, serverIP := attestz.GetGrpcPeers(t, tc)
	tc.ClientCert, tc.ClientKey, err = attestz.GenTlsCert(clientIP, caCert, caKey, caCert.PublicKeyAlgorithm)
	if err != nil {
		t.Fatalf("Error generating client tls certs. err: %s", err)
	}
	serverCert, serverKey, err := attestz.GenTlsCert(serverIP, caCert, caKey, caCert.PublicKeyAlgorithm)
	if err != nil {
		t.Fatalf("Error generating server tls certs. err: %s", err)
	}

	caCertBytes, err := os.ReadFile(tc.CaCertFile)
	if err != nil {
		t.Fatalf("Error reading owner cert: %v", err)
	}
	attestz.RotateCerts(t, dut, attestz.CertTypeRaw, *attestzServer.SslProfileId, serverKey, serverCert, caCertBytes)
	tc.Mtls = true
	activeCard.MtlsCert = string(serverCert)
	standbyCard.MtlsCert = string(serverCert)

	t.Run("Attestz-3.1 - Re-attest with mTLS", func(t *testing.T) {
		// Re-Attest for Active & Standby Card
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-3.2 - Re-attest with device reboot", func(t *testing.T) {
		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()

		// Collect attest response before reboot
		attestRespMap := make(map[attestzpb.Tpm20HashAlgo]*attestResponse)
		for _, hashAlgo := range attestz.PcrBankHashAlgoMap[dut.Vendor()] {
			// Generate Random Nonce
			nonce := make([]byte, 32)
			_, err := rand.Read(nonce)
			if err != nil {
				t.Fatalf("Error generating nonce: %v", err)
			}
			attestRespMap[hashAlgo] = new(attestResponse)
			attestRespMap[hashAlgo].activeCard = as.RequestAttestation(t, activeCard.Role, nonce, hashAlgo, attestz.PcrIndices)
			attestRespMap[hashAlgo].standbyCard = as.RequestAttestation(t, standbyCard.Role, nonce, hashAlgo, attestz.PcrIndices)
		}

		// Perform device reboot
		attestz.RebootDut(t, dut)
		t.Logf("Wait for cards to get synchronized post reboot ...")
		attestz.SwitchoverReady(t, dut, activeCard.Name, standbyCard.Name)

		// Check active card after reboot & swap controller vars if required
		rr := gnmi.Get[oc.E_Platform_ComponentRedundantRole](t, dut, gnmi.OC().Component(activeCard.Name).RedundantRole().State())
		if rr != oc.Platform_ComponentRedundantRole_PRIMARY {
			t.Logf("Card roles have changed. %s is the new active card.", standbyCard.Name)
			*activeCard, *standbyCard = *standbyCard, *activeCard
			activeCard.Role = cdpbActive
			standbyCard.Role = cdpbStandby
		}

		// Create new attestz session post reboot.
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()

		// Verify quote after reboot is different.
		for _, hashAlgo := range attestz.PcrBankHashAlgoMap[dut.Vendor()] {
			// Generate Random Nonce
			nonce := make([]byte, 32)
			_, err := rand.Read(nonce)
			if err != nil {
				t.Fatalf("Error generating nonce: %v", err)
			}
			resp := as.RequestAttestation(t, activeCard.Role, nonce, hashAlgo, attestz.PcrIndices)
			if cmp.Equal(attestRespMap[hashAlgo].activeCard.Quoted, resp.Quoted) {
				t.Logf("Active card %s attest response before reboot: \n%s", activeCard.Name, attestz.PrettyPrint(attestRespMap[hashAlgo].activeCard))
				t.Logf("Active card %s attest response after reboot: \n%s", activeCard.Name, attestz.PrettyPrint(resp.Quoted))
				t.Errorf("Received similar quotes for active card %s hash algo: %v before and after reboot but expected different.", activeCard.Name, hashAlgo)
			}
			resp = as.RequestAttestation(t, standbyCard.Role, nonce, hashAlgo, attestz.PcrIndices)
			if cmp.Equal(attestRespMap[hashAlgo].standbyCard.Quoted, resp.Quoted) {
				t.Logf("Standby card %s attest response before reboot: \n%s", standbyCard.Name, attestz.PrettyPrint(attestRespMap[hashAlgo].standbyCard))
				t.Logf("Standby card %s attest response after reboot: \n%s", standbyCard.Name, attestz.PrettyPrint(resp.Quoted))
				t.Errorf("Received similar quotes for standby card %s hash algo: %v before and after reboot but expected different.", standbyCard.Name, hashAlgo)
			}
		}

		// Re-Attest for Active & Standby Card post reboot.
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)

	})

	t.Run("Attestz-3.3 - Re-attest with switchover", func(t *testing.T) {
		// Perform switchover without waiting for card sync. Switchover will cause active card to reboot
		// simulating a scenario with just single active card.
		attestz.SwitchoverCards(t, dut, activeCard.Name, standbyCard.Name)

		// Swap active and standby card post switchover
		*activeCard, *standbyCard = *standbyCard, *activeCard
		activeCard.Role = cdpbActive
		standbyCard.Role = cdpbStandby

		// Verify device passes attestation post switchover.
		activeCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-3.4 - Re-attest with invalid trust bundle", func(t *testing.T) {
		// Server certificate can be used to simulate an invalid trust-bundle.
		attestz.RotateCerts(t, dut, attestz.CertTypeRaw, *attestzServer.SslProfileId, nil, nil, serverCert)
		as := tc.NewAttestzSession(t)
		_, err := as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{})
		if err == nil {
			t.Fatalf("Attest rpc succeeded but expected to fail.")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("Attest rpc did not receive expected error code. got error: %v, want error: Unauthenticated", err)
		}
		t.Logf("Got expected error for Attest rpc. error: %v", err)
	})

}
