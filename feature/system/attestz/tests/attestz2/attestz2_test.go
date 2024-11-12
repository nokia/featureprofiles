package attestz2

import (
	"context"
	"flag"
	enrollzpb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/security/attestz"
	"github.com/openconfig/featureprofiles/internal/security/svid"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"testing"
)

var (
	vendorCaCertPem = flag.String("switch_vendor_ca_cert", "Nokia_Bundle.pem", "a pem file for vendor ca cert used for verifying iDevID/IAK Certs")
	ownerCaCertPem  = flag.String("switch_owner_ca_cert", "ca-0001-rsa-cert.pem", "a pem file for ca cert that will be used to sign oDevID/oIAK Certs")
	ownerCaKeyPem   = flag.String("switch_owner_ca_key", "ca-0001-rsa-key.pem", "a pem file for ca key that will be used to sign oDevID/oIAK Certs")
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestAttestz2(t *testing.T) {
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

	t.Run("Attestz-2.1 - Successful enrollz w/o mTLS", func(t *testing.T) {
		// Re-Enroll for Active & Standby Card
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Re-Attest for Active & Standby Card
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-2.2 - Successful enrollz with mTLS", func(t *testing.T) {
		// Create client and server certificates for mtls connection.
		caKey, caCert, err := svid.LoadKeyPair(tc.CaKeyFile, tc.CaCertFile)
		if err != nil {
			t.Fatalf("Could not load ca key/cert: %v", err)
		}
		clientIP, serverIP := attestz.GetGrpcPeers(t, tc)
		tc.ClientCert, tc.ClientKey, err = attestz.GenTlsCert(clientIP, caCert, caKey, caCert.PublicKeyAlgorithm)
		if err != nil {
			t.Fatalf("Error generating client tls keypair. err: %s", err)
		}
		serverCert, serverKey, err := attestz.GenTlsCert(serverIP, caCert, caKey, caCert.PublicKeyAlgorithm)
		if err != nil {
			t.Fatalf("Error generating server tls keypair. err: %s", err)
		}

		caCertBytes, err := os.ReadFile(tc.CaCertFile)
		if err != nil {
			t.Fatalf("Error reading owner cert: %v", err)
		}
		attestz.RotateCerts(t, dut, attestz.CertTypeRaw, *attestzServer.SslProfileId, serverKey, serverCert, caCertBytes)
		tc.Mtls = true
		activeCard.MtlsCert = string(serverCert)
		standbyCard.MtlsCert = string(serverCert)

		// Re-enroll for active & standby cards with mtls.
		activeCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)
		activeCard.MtlsCert = ""
		standbyCard.EnrollzWorkflow(t, dut, tc, *vendorCaCertPem)

		// Re-attest for active & standby cards.
		activeCard.AttestzWorkflow(t, dut, tc)
		standbyCard.AttestzWorkflow(t, dut, tc)
	})

	t.Run("Attestz-2.3 - enrollz with invalid trust bundle", func(t *testing.T) {
		// Server certificate can be used to simulate an invalid trust-bundle.
		caKey, caCert, err := svid.LoadKeyPair(tc.CaKeyFile, tc.CaCertFile)
		if err != nil {
			t.Fatalf("Could not load ca key/cert: %v", err)
		}
		_, serverIP := attestz.GetGrpcPeers(t, tc)
		serverCert, _, err := attestz.GenTlsCert(serverIP, caCert, caKey, caCert.PublicKeyAlgorithm)
		if err != nil {
			t.Fatalf("Error generating server tls keypair. err: %s", err)
		}
		attestz.RotateCerts(t, dut, attestz.CertTypeRaw, *attestzServer.SslProfileId, nil, nil, serverCert)

		as := tc.NewAttestzSession(t)
		_, err = as.EnrollzClient.GetIakCert(context.Background(), &enrollzpb.GetIakCertRequest{})
		if err == nil {
			t.Fatalf("GetIakCert rpc succeeded but expected to fail.")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("GetIakCert rpc did not receive expected error code. got error: %v, want error: Unauthenticated", err)
		}
		t.Logf("Got expected error for GetIakCert rpc. error: %v", err)

		_, err = as.EnrollzClient.RotateOIakCert(context.Background(), &enrollzpb.RotateOIakCertRequest{})
		if err == nil {
			t.Fatalf("RotateOIakCert rpc succeeded but expected to fail.")
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("RotateOIakCert rpc did not receive expected error code. got error: %v, want error: Unauthenticated", err)
		}
		t.Logf("Got expected error for RotateOIakCert rpc. error: %v", err)
	})
}
