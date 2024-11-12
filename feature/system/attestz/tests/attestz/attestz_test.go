package attestz_test

import (
	"context"
	"crypto/rand"
	"flag"
	cdpb "github.com/openconfig/attestz/proto/common_definitions"
	attestzpb "github.com/openconfig/attestz/proto/tpm_attestz"
	enrollzpb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/security/attestz"
	"github.com/openconfig/featureprofiles/internal/security/svid"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

const (
	cdpbActive  = cdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE
	cdpbStandby = cdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY
)

var (
	vendorCaCertPem = flag.String("switch_vendor_ca_cert", "Nokia_Bundle.pem", "a pem file for vendor ca cert used for verifying iDevID/IAK Certs")
	ownerCaCertPem  = flag.String("switch_owner_ca_cert", "ca-0001-rsa-cert.pem", "a pem file for ca cert that will be used to sign oDevID/oIAK Certs")
	ownerCaKeyPem   = flag.String("switch_owner_ca_key", "ca-0001-rsa-key.pem", "a pem file for ca key that will be used to sign oDevID/oIAK Certs")
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestAttestz1(t *testing.T) {
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

	t.Run("Attestz-1.1 - Successful enrollment and attestation", func(t *testing.T) {
		// Enroll for Active & Standby Card
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Attest for Active & Standby Card
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-1.3 - Bad Request", func(t *testing.T) {
		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()
		invalidSerial := attestz.ParseSerialSelection(t, "000")

		_, err := as.EnrollzClient.GetIakCert(context.Background(), &enrollzpb.GetIakCertRequest{
			ControlCardSelection: invalidSerial,
		})
		if err == nil {
			t.Fatal("GetIakCert rpc for invalid serial number succeeded but expected to fail.")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("GetIakCert rpc did not receive expected error code. got error: %s, want error: InvalidArgument", err)
		} else {
			t.Logf("Got expected error for GetIakCert rpc. err: %s", err)
		}

		attestzRequest := &enrollzpb.RotateOIakCertRequest{
			ControlCardSelection: invalidSerial,
		}
		_, err = as.EnrollzClient.RotateOIakCert(context.Background(), attestzRequest)
		if err == nil {
			t.Fatal("RotateOIakCert rpc for invalid serial number succeeded but expected to fail.")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("RotateOIakCert rpc did not receive expected error code. got error: %s, want error: InvalidArgument", err)
		} else {
			t.Logf("Got expected error for RotateOIakCert rpc. err: %s", err)
		}

		_, err = as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
			ControlCardSelection: invalidSerial,
		})
		if err == nil {
			t.Fatal("Attest rpc for invalid serial number succeeded but expected to fail.")
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("Attest rpc did not receive expected error code. got error: %s, want error: InvalidArgument", err)
		} else {
			t.Logf("Got expected error for Attest rpc. err: %s", err)
		}

	})

	t.Run("Attestz-1.4 - Incorrect Public Key", func(t *testing.T) {
		// Determines how the getRequest is crafted (role)
		roleA := attestz.ParseRoleSelection(t, cdpbActive)
		roleB := attestz.ParseRoleSelection(t, cdpbStandby)

		// Get Vendor Certs
		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()
		resp := as.GetVendorCerts(t, roleA)
		activeCard.IAKCert, activeCard.IDevIDCert = resp.IakCert, resp.IdevidCert
		resp = as.GetVendorCerts(t, roleB)
		standbyCard.IAKCert, standbyCard.IDevIDCert = resp.IakCert, resp.IdevidCert

		caKey, caCert, err := svid.LoadKeyPair(*ownerCaKeyPem, *ownerCaCertPem)
		if err != nil {
			t.Fatalf("Could not load ca key/cert: %v", err)
		}

		// Generate active card's oIAK/oIDevId certs with standby card's public key (to simulate incorrect public key).
		standbyIAKCert, err := attestz.LoadCertificate(standbyCard.IAKCert)
		if err != nil {
			t.Fatalf("Error loading IAK Cert for Standby Card: %v", err)
		}
		t.Logf("Generating oIAK cert for card %v with incorrect public key", activeCard.Name)
		oIAKCert := attestz.GenOwnerCert(t, caKey, caCert, activeCard.IAKCert, standbyIAKCert.PublicKey, tc.Target)

		standbyIDevIDCert, err := attestz.LoadCertificate(standbyCard.IDevIDCert)
		if err != nil {
			t.Fatalf("Error loading IDevID Cert for Standby Card: %v", err)
		}
		t.Logf("Generating oDevID cert for card %v with incorrect public key", activeCard.Name)
		oDevIDCert := attestz.GenOwnerCert(t, caKey, caCert, activeCard.IDevIDCert, standbyIDevIDCert.PublicKey, tc.Target)

		// Verify RotateOIakCert fails
		attestzRequest := &enrollzpb.RotateOIakCertRequest{
			ControlCardSelection: roleA,
			OiakCert:             oIAKCert,
			OidevidCert:          oDevIDCert,
			SslProfileId:         *attestzServer.SslProfileId,
		}
		_, err = as.EnrollzClient.RotateOIakCert(context.Background(), attestzRequest)
		if err == nil {
			t.Fatalf("RotateOIakCert rpc for card %s succeeded but expected to fail.", activeCard.Name)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("RotateOIakCert rpc for card %s did not receive expected error code. got error: %s, want error: InvalidArgument", activeCard.Name, err)
		} else {
			t.Logf("Got expected error for RotateOIakCert rpc for card %s. err: %s", activeCard.Name, err)
		}
	})

	t.Run("Attestz-1.5 - Device Reboot", func(t *testing.T) {
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Trigger Section - Reboot
		attestz.RebootDut(t, dut)
		t.Logf("Wait for cards to get synchronized post reboot ...")
		attestz.SwitchoverReady(t, dut, activeCard.Name, standbyCard.Name)

		// Check active card after reboot & swap control card if required.
		rr := gnmi.Get[oc.E_Platform_ComponentRedundantRole](t, dut, gnmi.OC().Component(activeCard.Name).RedundantRole().State())
		if rr != oc.Platform_ComponentRedundantRole_PRIMARY {
			t.Logf("Card roles have changed. %s is the new active card.", standbyCard.Name)
			*activeCard, *standbyCard = *standbyCard, *activeCard
			activeCard.Role = cdpbActive
			standbyCard.Role = cdpbStandby
		}

		// Verify attest workflow post reboot
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-1.6 - Factory Reset", func(t *testing.T) {
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Trigger factory reset.
		attestz.FactoryResetDut(t, dut)
		t.Logf("Wait for cards to get synchronized post factory reset ...")
		attestz.SwitchoverReady(t, dut, activeCard.Name, standbyCard.Name)

		// Setup baseline configs again after factory reset (ensure bootz pushes relevant configs used for
		// ondatra binding connections used prior to factory reset).
		attestzTarget, attestzServer = attestz.SetupBaseline(t, dut)
		activeCard, standbyCard = attestz.SetupCards(t, dut)

		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()

		// Generate Random Nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Error generating nonce: %v", err)
		}
		_, err = as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
			ControlCardSelection: attestz.ParseRoleSelection(t, cdpbActive),
			Nonce:                nonce,
			HashAlgo:             attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			PcrIndices:           attestz.PcrIndices,
		})
		if err == nil {
			t.Fatalf("Attest rpc for active card %s succeeded but expected to fail.", activeCard.Name)
		}
		if status.Code(err) != codes.NotFound {
			t.Errorf("Attest rpc for active card %s did not receive expected error code. got error: %s, want error: Unauthenticated", activeCard.Name, err)
		} else {
			t.Logf("Got expected error for Attest rpc for active card %s. err: %s", activeCard.Name, err)
		}
	})

	t.Run("Attestz-1.7 - Invalid PCR indices", func(t *testing.T) {
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()

		// Generate Random Nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Error generating nonce: %v", err)
		}

		_, err = as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
			ControlCardSelection: attestz.ParseRoleSelection(t, activeCard.Role),
			Nonce:                nonce,
			HashAlgo:             attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			PcrIndices:           []int32{25, -25},
		})
		if err == nil {
			t.Fatalf("Attest rpc for card %s succeeded but expected to fail.", activeCard.Name)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("Attest rpc for card %s did not receive expected error code. got error: %s, want error: InvalidArgument", activeCard.Name, err)
		} else {
			t.Logf("Got expected error for Attest rpc for card %s. err: %s", activeCard.Name, err)
		}
	})

	// Ensure factory reset test ran before running this test to simulate rma scenario.
	t.Run("Attestz-1.8 - Attest failure on standby card", func(t *testing.T) {
		// Enroll & attest active card.
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		activeCard.AttestzWorkflow(t, dut, tc)

		var as *attestz.AttestzSession
		as = tc.NewAttestzSession(t)
		defer as.Conn.Close()

		// Generate Random Nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Error generating nonce: %v", err)
		}
		_, err = as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
			ControlCardSelection: attestz.ParseRoleSelection(t, cdpbStandby),
			Nonce:                nonce,
			HashAlgo:             attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			PcrIndices:           attestz.PcrIndices,
		})
		if err != nil {
			t.Logf("Got expected error for Attest rpc of standby card %s. err: %s", standbyCard.Name, err)
		} else {
			t.Fatalf("Attest rpc for standby card %s succeeded but expected to fail.", standbyCard.Name)
		}
	})

	t.Run("Attestz-1.9 - Control Card Switchover", func(t *testing.T) {
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Perform Control Card switchover
		attestz.SwitchoverCards(t, dut, activeCard.Name, standbyCard.Name)
		t.Logf("Wait for cards to get synchronized post switchover ...")
		attestz.SwitchoverReady(t, dut, activeCard.Name, standbyCard.Name)

		// Swap active and standby card post switchover
		*activeCard, *standbyCard = *standbyCard, *activeCard
		activeCard.Role = cdpbActive
		standbyCard.Role = cdpbStandby

		// Verify Attest Workflow post switchover
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})
}
