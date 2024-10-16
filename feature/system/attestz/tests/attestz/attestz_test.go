package attestz_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	enrollzpb "github.com/openconfig/attestz/proto/tpm_enrollz"
	cmp "github.com/openconfig/featureprofiles/internal/components"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/security/svid"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	gnps "github.com/openconfig/gnoi/system"
	"github.com/openconfig/gnoigo/system"
	"github.com/openconfig/ondatra/binding/introspect"
	"github.com/openconfig/ondatra/gnoi"
	"github.com/openconfig/testt"
	"github.com/openconfig/ygnmi/ygnmi"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	cdpb "github.com/openconfig/attestz/proto/common_definitions"
	attestzpb "github.com/openconfig/attestz/proto/tpm_attestz"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/security/attestz"
	"github.com/openconfig/featureprofiles/internal/security/certz"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
)

const (
	controlcardType     = oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CONTROLLER_CARD
	primaryController   = oc.Platform_ComponentRedundantRole_PRIMARY
	secondaryController = oc.Platform_ComponentRedundantRole_SECONDARY
	cdpbActive          = cdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE
	cdpbStandby         = cdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY
	attestzServerName   = "attestz-server"
	sslProfileId        = "tls-attestz"
	attestzServerPort   = 9000
	maxSwitchoverTime   = 900
	maxRebootTime       = 900
)

var (
	vendorCaCertPem = flag.String("switch_vendor_ca_cert", "Nokia_Bundle.pem", "a pem file for vendor ca cert used for verifying iDevID/IAK Certs")
	ownerCaCertPem  = flag.String("switch_owner_ca_cert", "ca-0001-rsa-cert.pem", "a pem file for ca cert that will be used to sign oDevID/oIAK Certs")
	ownerCaKeyPem   = flag.String("switch_owner_ca_key", "ca-0001-rsa-key.pem", "a pem file for ca key that will be used to sign oDevID/oIAK Certs")

	cardCertMap = map[cdpb.ControlCardRole]*attestz.CardCert{
		cdpbActive:  {"", "", "", "", ""},
		cdpbStandby: {"", "", "", "", ""},
	}

	pcrBankHashAlgos = []attestzpb.Tpm20HashAlgo{
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA1,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA384,
		attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA512,
	}

	pcrIndices = []int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}
	vrfMap     = map[ondatra.Vendor]string{
		ondatra.CISCO:   "DEFAULT",
		ondatra.NOKIA:   "mgmt",
		ondatra.JUNIPER: "DEFAULT",
		ondatra.ARISTA:  "default",
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureGrpcServer(t *testing.T, dut *ondatra.DUTDevice) {
	t.Logf("Setting grpc-server")
	root := &oc.Root{}
	dutVendor := dut.Vendor()
	s := root.GetOrCreateSystem()
	gs := s.GetOrCreateGrpcServer(attestzServerName)
	gs.SetEnable(true)
	gs.SetPort(attestzServerPort)
	gs.SetCertificateId(sslProfileId)
	gs.SetServices([]oc.E_SystemGrpc_GRPC_SERVICE{oc.SystemGrpc_GRPC_SERVICE_GNMI, oc.SystemGrpc_GRPC_SERVICE_GNSI})
	gs.SetMetadataAuthentication(false)
	gs.SetNetworkInstance(vrfMap[dutVendor])
	gnmi.Update(t, dut, gnmi.OC().System().Config(), s)
	switch dut.Vendor() {
	case ondatra.NOKIA:
		var yangModels = []any{
			map[string]any{
				"yang-models": "openconfig",
			},
		}
		yangModelsUpdate, err := json.Marshal(yangModels)
		if err != nil {
			t.Fatalf("Error with json Marshal: %v", err)
		}

		SetRequest := &gpb.SetRequest{
			Prefix: &gpb.Path{
				Origin: "native",
			},
			Update: []*gpb.Update{
				{
					Path: &gpb.Path{
						Elem: []*gpb.PathElem{
							{Name: "system"},
							{Name: "grpc-server", Key: map[string]string{"name": attestzServerName}},
						},
					},
					Val: &gpb.TypedValue{
						Value: &gpb.TypedValue_JsonIetfVal{
							JsonIetfVal: yangModelsUpdate,
						},
					},
				},
			},
		}

		gnmiClient := dut.RawAPIs().GNMI(t)
		if _, err := gnmiClient.Set(context.Background(), SetRequest); err != nil {
			t.Fatalf("Unexpected error configuring User: %v", err)
		}
	}
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

	return primary, secondary
}

// Generate Owner certs
func generateOwnerCerts(t *testing.T, caKey any, caCert *x509.Certificate, inputCert string, pubKey any) string {
	cert, err := attestz.LoadCertificate([]byte(inputCert))
	if err != nil {
		t.Fatalf("Error loading vendor certificate: %v", err)
	}
	if pubKey == nil {
		pubKey = cert.PublicKey
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
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     cert.NotAfter,
		Subject:      cert.Subject,
		KeyUsage:     cert.KeyUsage,
		ExtKeyUsage:  cert.ExtKeyUsage,
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

func setupBaseline(t *testing.T, dut *ondatra.DUTDevice) string {
	certz.AddProfile(t, dut, sslProfileId)
	certz.RotateIdevIdCert(t, dut, sslProfileId)
	configureGrpcServer(t, dut)

	// Prepare target for the newly created gRPC Server
	var newTarget string
	bindingTarget := introspect.DUTDialer(t, dut, introspect.GNSI).DialTarget
	bindingAddr, err := net.ResolveTCPAddr("tcp", bindingTarget)
	if err != nil {
		t.Logf("failed resolving gNSI target %s, will use default values", bindingTarget)
		newTarget = fmt.Sprintf("%s:%d", dut.Name(), attestzServerPort)
	} else {
		newTarget = fmt.Sprintf("%s:%d", bindingAddr.IP.String(), attestzServerPort)
	}
	t.Logf("Target for new gNSI service: %s", newTarget)
	return newTarget
}

func enrollzWorkflow(t *testing.T, dut *ondatra.DUTDevice, cardRole cdpb.ControlCardRole, attestzTarget string) {
	cardCert := cardCertMap[cardRole]

	// Determines how the getRequest is crafted (role)
	roleA := attestz.ParseRoleSelection(t, cardRole)

	// Get Vendor Certs
	cardCert.IAKCert, cardCert.IDevIDCert = attestz.GetVendorCerts(t, attestzTarget, roleA)

	// Load Vendor CA Cert
	vendorCaPem, err := os.ReadFile(*vendorCaCertPem)
	if err != nil {
		t.Fatalf("Error reading vendor cert: %v", err)
	}

	// Validate Cert Info
	t.Logf("Verifying IDevID cert for card %v", cardCert.CardName)
	attestz.ValidateCertInfo(t, dut, []byte(cardCert.IDevIDCert), cardCert.CardName, vendorCaPem)
	t.Logf("Verifying IAK cert for card %v", cardCert.CardName)
	attestz.ValidateCertInfo(t, dut, []byte(cardCert.IAKCert), cardCert.CardName, vendorCaPem)

	// Generate Owner Certs
	caKey, caCert, err := svid.LoadKeyPair(*ownerCaKeyPem, *ownerCaCertPem)
	if err != nil {
		t.Fatalf("Could not load ca key/cert: %v", err)
	}
	t.Logf("Generating oIAK cert for card %v", cardCert.CardName)
	cardCert.OIAKCert = generateOwnerCerts(t, caKey, caCert, cardCert.IAKCert, nil)
	t.Logf("Generating oDevID cert for card %v", cardCert.CardName)
	cardCert.ODevIDCert = generateOwnerCerts(t, caKey, caCert, cardCert.IDevIDCert, nil)

	// Rotate Owner Certificates
	attestz.RotateOwnerCerts(t, attestzTarget, cardRole, cardCert.OIAKCert, cardCert.ODevIDCert, sslProfileId)
}

func attestzWorkflow(t *testing.T, dut *ondatra.DUTDevice, cardRole cdpb.ControlCardRole, attestzTarget string) {
	cardCert := cardCertMap[cardRole]
	for _, hashAlgo := range pcrBankHashAlgos {
		if dut.Vendor() == ondatra.NOKIA {
			if hashAlgo != attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA1 && hashAlgo != attestzpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256 {
				continue
			}
		}
		// Generate Random Nonce
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Error generating nonce: %v", err)
		}

		t.Logf("Attest & Verify for card %v, hash algo: %v", cardCert.CardName, hashAlgo.String())
		attestResponse := attestz.RequestAttestation(t, attestzTarget, cardRole, nonce, hashAlgo, pcrIndices)
		attestz.VerifyAttestation(t, dut, attestResponse, cardCert, nonce, hashAlgo, pcrIndices)
	}
}

func switchoverReady(t *testing.T, dut *ondatra.DUTDevice, controller string) bool {
	switchoverReady := gnmi.OC().Component(controller).SwitchoverReady()
	_, ok := gnmi.Watch(t, dut, switchoverReady.State(), 30*time.Minute, func(val *ygnmi.Value[bool]) bool {
		ready, present := val.Val()
		return present && ready
	}).Await(t)
	return ok
}

func TestAttestz1(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	attestzTarget := setupBaseline(t, dut)
	controllers := cmp.FindComponentsByType(t, dut, controlcardType)
	t.Logf("Found controller list: %v", controllers)
	if len(controllers) != 2 {
		t.Skipf("Dual controllers required on %v: got %v, want 2", dut.Model(), len(controllers))
	}

	t.Run("Attestz-1.1 - Successful enrollment and attestation", func(t *testing.T) {
		cardCertMap[cdpbActive].CardName, cardCertMap[cdpbStandby].CardName = findControllers(t, dut, controllers)

		// Enroll for Active & Standby Card
		enrollzWorkflow(t, dut, cdpbActive, attestzTarget)
		enrollzWorkflow(t, dut, cdpbStandby, attestzTarget)

		// Attest for Active & Standby Card
		attestzWorkflow(t, dut, cdpbActive, attestzTarget)
		attestzWorkflow(t, dut, cdpbStandby, attestzTarget)
	})

	t.Run("Attestz-1.3 - Bad Request", func(t *testing.T) {
		invalidSerial := attestz.ParseSerialSelection(t, "000")
		as := attestz.NewAttestzSession(t, attestzTarget)
		_, err := as.EnrollzClient.GetIakCert(context.Background(), &enrollzpb.GetIakCertRequest{
			ControlCardSelection: invalidSerial,
		})
		if err != nil {
			t.Logf("Got expected error for GetIakCert bad request %v", err)
		} else {
			t.Fatal("Expected error in GetIakCert with invalid serial")
		}

		attestzRequest := &enrollzpb.RotateOIakCertRequest{
			ControlCardSelection: invalidSerial,
		}
		_, err = as.EnrollzClient.RotateOIakCert(context.Background(), attestzRequest)
		if err != nil {
			t.Logf("Got expected error for RotateOIakCert bad request %v", err)
		} else {
			t.Fatal("Expected error in RotateOIakCert with invalid serial")
		}

		_, err = as.AttestzClient.Attest(context.Background(), &attestzpb.AttestRequest{
			ControlCardSelection: invalidSerial,
		})
		if err != nil {
			t.Logf("Got expected error for Attest bad request %v", err)
		} else {
			t.Fatal("Expected error in Attest with invalid serial")
		}

	})

	t.Run("Attestz-1.4 - Incorrect Public Key", func(t *testing.T) {
		// Determines how the getRequest is crafted (role)
		roleA := attestz.ParseRoleSelection(t, cdpbActive)
		roleB := attestz.ParseRoleSelection(t, cdpbStandby)

		// Get Vendor Certs
		cardCertMap[cdpbActive].IAKCert, cardCertMap[cdpbActive].IDevIDCert = attestz.GetVendorCerts(t, attestzTarget, roleA)
		cardCertMap[cdpbStandby].IAKCert, cardCertMap[cdpbStandby].IDevIDCert = attestz.GetVendorCerts(t, attestzTarget, roleB)

		caKey, caCert, err := svid.LoadKeyPair(*ownerCaKeyPem, *ownerCaCertPem)
		if err != nil {
			t.Fatalf("Could not load ca key/cert: %v", err)
		}

		// Generate Primary Card's oIAK/oIDevId certs with Standby Card's public key
		standbyIAKCert, err := attestz.LoadCertificate([]byte(cardCertMap[cdpbStandby].IAKCert))
		if err != nil {
			t.Fatalf("Error loading IAK Cert for Standby Card: %v", err)
		}
		t.Logf("Generating oIAK cert for card %v with incorrect public key", cardCertMap[cdpbActive].CardName)
		oIAKCert := generateOwnerCerts(t, caKey, caCert, cardCertMap[cdpbActive].IAKCert, standbyIAKCert.PublicKey)

		standbyIDevIDCert, err := attestz.LoadCertificate([]byte(cardCertMap[cdpbStandby].IDevIDCert))
		if err != nil {
			t.Fatalf("Error loading IDevID Cert for Standby Card: %v", err)
		}
		t.Logf("Generating oDevID cert for card %v with incorrect public key", cardCertMap[cdpbActive].CardName)
		oDevIDCert := generateOwnerCerts(t, caKey, caCert, cardCertMap[cdpbActive].IDevIDCert, standbyIDevIDCert.PublicKey)

		// Verify RotateOIakCert fails
		as := attestz.NewAttestzSession(t, attestzTarget)
		attestzRequest := &enrollzpb.RotateOIakCertRequest{
			ControlCardSelection: roleA,
			OiakCert:             oIAKCert,
			OidevidCert:          oDevIDCert,
			SslProfileId:         sslProfileId,
		}
		_, err = as.EnrollzClient.RotateOIakCert(context.Background(), attestzRequest)
		if err != nil {
			t.Logf("Got expected error for RotateOIakCert bad request %v", err)
		} else {
			t.Fatalf("Expected error in RotateOIakCert for card %v with invalid public key", cardCertMap[cdpbActive].CardName)
		}
	})

	t.Run("Attestz-1.5 - Device Reboot", func(t *testing.T) {
		cardCertMap[cdpbActive].CardName, cardCertMap[cdpbStandby].CardName = findControllers(t, dut, controllers)

		enrollzWorkflow(t, dut, cdpbActive, attestzTarget)
		enrollzWorkflow(t, dut, cdpbStandby, attestzTarget)

		// Trigger Section - Reboot
		gnoiClient, err := dut.RawAPIs().BindingDUT().DialGNOI(context.Background())
		if err != nil {
			t.Fatalf("Failed to connect to gnoi server, err: %v", err)
		}
		rebootRequest := &gnps.RebootRequest{
			Method: gnps.RebootMethod_COLD,
			Force:  true,
		}
		bootTimeBeforeReboot := gnmi.Get(t, dut, gnmi.OC().System().BootTime().State())
		t.Logf("DUT boot time before reboot: %v", bootTimeBeforeReboot)
		var currentTime string
		currentTime = gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State())
		t.Logf("Time Before Reboot : %v", currentTime)
		rebootResponse, err := gnoiClient.System().Reboot(context.Background(), rebootRequest)
		t.Logf("Got Reboot response: %v, err: %v", rebootResponse, err)
		if err != nil {
			t.Fatalf("Failed to reboot chassis with unexpected err: %v", err)
		}
		for {
			if errMsg := testt.CaptureFatal(t, func(t testing.TB) {
				currentTime = gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State())
			}); errMsg != nil {
				t.Log("Reboot is started")
				break
			}
			t.Log("Wait for reboot to be started")
			time.Sleep(30 * time.Second)
		}
		startReboot := time.Now()
		t.Logf("Wait for DUT to boot up by polling the telemetry output.")
		for {
			t.Logf("Time elapsed %.2f seconds since reboot started.", time.Since(startReboot).Seconds())
			if errMsg := testt.CaptureFatal(t, func(t testing.TB) {
				currentTime = gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State())
			}); errMsg != nil {
				t.Logf("Got testt.CaptureFatal errMsg: %s, keep polling ...", *errMsg)
			} else {
				t.Logf("Device rebooted successfully with received time: %v", currentTime)
				break
			}
			if uint64(time.Since(startReboot).Seconds()) > maxRebootTime {
				t.Fatalf("Check boot time: got %v, want < %v", time.Since(startReboot), maxRebootTime)
			}
		}

		// Check active card after reboot & swap controller map if required
		primaryControllerName, _ := findControllers(t, dut, controllers)
		if cardCertMap[cdpbActive].CardName != primaryControllerName {
			cardCertMap[cdpbActive], cardCertMap[cdpbStandby] = cardCertMap[cdpbStandby], cardCertMap[cdpbActive]
		}

		t.Logf("Wait for Secondary Controller to get synchronized")
		if ok := switchoverReady(t, dut, cardCertMap[cdpbStandby].CardName); !ok {
			t.Fatalf("Controller %q did not become switchover-ready after test.", cardCertMap[cdpbStandby].CardName)
		}

		// Verify Attest Workflow post reboot
		attestzWorkflow(t, dut, cdpbActive, attestzTarget)
		attestzWorkflow(t, dut, cdpbStandby, attestzTarget)
	})

	t.Run("Attestz-1.7 - Invalid PCR indices", func(t *testing.T) {
		as := attestz.NewAttestzSession(t, attestzTarget)

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
			PcrIndices:           []int32{25, -25},
		})
		if err != nil {
			t.Logf("Got expected error for Attest bad request %v", err)
		} else {
			t.Fatal("Expected error in Attest with invalid pcr indices")
		}
	})

	t.Run("Attestz-1.9 - Control Card Switchover", func(t *testing.T) {
		cardCertMap[cdpbActive].CardName, cardCertMap[cdpbStandby].CardName = findControllers(t, dut, controllers)

		enrollzWorkflow(t, dut, cdpbActive, attestzTarget)
		enrollzWorkflow(t, dut, cdpbStandby, attestzTarget)

		// Perform Control Card switchover
		primaryBeforeSwitch := cardCertMap[cdpbActive].CardName
		secondaryBeforeSwitch := cardCertMap[cdpbStandby].CardName

		// Wait for Active Controller to become switch-over ready
		if ok := switchoverReady(t, dut, primaryBeforeSwitch); !ok {
			t.Fatalf("Controller %q did not become switchover-ready before test.", primaryBeforeSwitch)
		}

		switchoverResponse := gnoi.Execute(t, dut, system.NewSwitchControlProcessorOperation().Path(cmp.GetSubcomponentPath(secondaryBeforeSwitch, deviations.GNOISubcomponentPath(dut))))
		t.Logf("gnoiClient.System().SwitchControlProcessor() response: %v", switchoverResponse)

		startSwitchover := time.Now()
		t.Logf("Wait for new Primary controller to boot up by polling the telemetry output.")
		for {
			var currentTime string
			t.Logf("Time elapsed %.2f seconds since switchover started.", time.Since(startSwitchover).Seconds())
			time.Sleep(30 * time.Second)
			if errMsg := testt.CaptureFatal(t, func(t testing.TB) {
				currentTime = gnmi.Get(t, dut, gnmi.OC().System().CurrentDatetime().State())
			}); errMsg != nil {
				t.Logf("Got testt.CaptureFatal errMsg: %s, keep polling ...", *errMsg)
			} else {
				t.Logf("Controller switchover has completed successfully with received time: %v", currentTime)
				break
			}
			if uint64(time.Since(startSwitchover).Seconds()) > maxSwitchoverTime {
				t.Fatalf("time.Since(startSwitchover): got %v, want < %v", time.Since(startSwitchover), maxSwitchoverTime)
			}
		}
		t.Logf("Controller switchover time: %.2f seconds", time.Since(startSwitchover).Seconds())

		t.Logf("Wait for new Secondary Controller to get synchronized")
		if ok := switchoverReady(t, dut, primaryBeforeSwitch); !ok {
			t.Fatalf("Controller %q did not become switchover-ready after test.", primaryBeforeSwitch)
		}

		// Swap controller map post switchover
		cardCertMap[cdpbActive], cardCertMap[cdpbStandby] = cardCertMap[cdpbStandby], cardCertMap[cdpbActive]

		// Verify Attest Workflow post switchover
		attestzWorkflow(t, dut, cdpbActive, attestzTarget)
		attestzWorkflow(t, dut, cdpbStandby, attestzTarget)
	})

	t.Cleanup(func() {
		gnmi.Delete(t, dut, gnmi.OC().System().GrpcServer(attestzServerName).Config())
		certz.DeleteProfile(t, dut, sslProfileId)
	})
}
