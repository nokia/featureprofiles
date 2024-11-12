package attestz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	cdpb "github.com/openconfig/attestz/proto/common_definitions"
	attestzpb "github.com/openconfig/attestz/proto/tpm_attestz"
	enrollzpb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/featureprofiles/internal/components"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/binding/introspect"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"net"
	"os"
	"testing"
)

const (
	attestzServerName   = "attestz-server"
	sslProfileId        = "tls-attestz"
	attestzServerPort   = 9000
	controlcardType     = oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CONTROLLER_CARD
	cdpbActive          = cdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE
	cdpbStandby         = cdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY
	primaryController   = oc.Platform_ComponentRedundantRole_PRIMARY
	secondaryController = oc.Platform_ComponentRedundantRole_SECONDARY
)

var (
	vrfMap = map[ondatra.Vendor]string{
		ondatra.CISCO:   "DEFAULT",
		ondatra.NOKIA:   "mgmt",
		ondatra.JUNIPER: "DEFAULT",
		ondatra.ARISTA:  "default",
	}
)

type AttestzSession struct {
	EnrollzClient enrollzpb.TpmEnrollzServiceClient
	AttestzClient attestzpb.TpmAttestzServiceClient
	Conn          *grpc.ClientConn
	Peer          *peer.Peer
}

type TlsConf struct {
	Target     string
	Mtls       bool
	CaKeyFile  string
	CaCertFile string
	ClientCert []byte
	ClientKey  []byte
}

func (tc *TlsConf) NewAttestzSession(t *testing.T) *AttestzSession {
	tlsConf := new(tls.Config)
	if tc.Mtls {
		keyPair, err := tls.X509KeyPair(tc.ClientCert, tc.ClientKey)
		if err != nil {
			t.Fatalf("Error loading client keypair. err: %v", err)
		}
		tlsConf.Certificates = []tls.Certificate{keyPair}
		caCertBytes, err := os.ReadFile(tc.CaCertFile)
		if err != nil {
			t.Fatalf("Error reading trust bundle file. err: %v", err)
		}
		trustBundle := x509.NewCertPool()
		if !trustBundle.AppendCertsFromPEM(caCertBytes) {
			t.Fatalf("Error loading ca trust bundle.")
		}
		tlsConf.RootCAs = trustBundle
	} else {
		tlsConf.InsecureSkipVerify = true
	}

	conn, err := grpc.NewClient(
		tc.Target,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
	)

	if err != nil {
		t.Fatalf("Could not connect gnsi %v", err)
	}
	return &AttestzSession{
		Conn:          conn,
		Peer:          new(peer.Peer),
		EnrollzClient: enrollzpb.NewTpmEnrollzServiceClient(conn),
		AttestzClient: attestzpb.NewTpmAttestzServiceClient(conn),
	}
}

func createTestGrpcServer(t *testing.T, dut *ondatra.DUTDevice) *oc.System_GrpcServer {
	t.Logf("Setting grpc-server")
	root := &oc.Root{}
	dutVendor := dut.Vendor()
	s := root.GetOrCreateSystem()
	gs := s.GetOrCreateGrpcServer(attestzServerName)
	gs.SetEnable(true)
	gs.SetPort(uint16(attestzServerPort))
	gs.SetCertificateId(sslProfileId)
	gs.SetServices([]oc.E_SystemGrpc_GRPC_SERVICE{oc.SystemGrpc_GRPC_SERVICE_GNMI, oc.SystemGrpc_GRPC_SERVICE_GNSI})
	gs.SetMetadataAuthentication(false)
	gs.SetNetworkInstance(vrfMap[dutVendor])
	gnmi.Update(t, dut, gnmi.OC().System().Config(), s)
	return gnmi.Get[*oc.System_GrpcServer](t, dut, gnmi.OC().System().GrpcServer(attestzServerName).State())
}

func SetupBaseline(t *testing.T, dut *ondatra.DUTDevice) (string, *oc.System_GrpcServer) {
	AddProfile(t, dut, sslProfileId)
	RotateCerts(t, dut, CertTypeIdevid, sslProfileId, nil, nil, nil)
	gs := createTestGrpcServer(t, dut)

	// Prepare target for the newly created gRPC Server
	dialTarget := introspect.DUTDialer(t, dut, introspect.GNSI).DialTarget
	resolvedTarget, err := net.ResolveTCPAddr("tcp", dialTarget)
	if err != nil {
		t.Fatalf("Failed resolving gnsi target %s", dialTarget)
	}
	resolvedTarget.Port = attestzServerPort
	t.Logf("Target for new gNSI service: %s", resolvedTarget.String())
	return resolvedTarget.String(), gs
}

func GetGrpcPeers(t *testing.T, tc *TlsConf) (string, string) {
	var as *AttestzSession
	as = tc.NewAttestzSession(t)
	defer as.Conn.Close()
	as.EnrollzClient.GetIakCert(context.Background(), &enrollzpb.GetIakCertRequest{}, grpc.Peer(as.Peer))
	localAddr := as.Peer.LocalAddr.(*net.TCPAddr)
	remoteAddr := as.Peer.Addr.(*net.TCPAddr)
	t.Logf("Got Local Address: %v, Remote Address: %v", localAddr, remoteAddr)
	return localAddr.IP.String(), remoteAddr.IP.String()
}

// Ensure that we can call both controllers
func findControllers(t *testing.T, dut *ondatra.DUTDevice, controllers []string) (string, string) {
	var primary, secondary string
	for _, controller := range controllers {
		role := gnmi.Get[oc.E_Platform_ComponentRedundantRole](t, dut, gnmi.OC().Component(controller).RedundantRole().State())
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

func SetupCards(t *testing.T, dut *ondatra.DUTDevice) (*ControlCard, *ControlCard) {
	activeCard = &ControlCard{Role: cdpbActive}
	standbyCard = &ControlCard{Role: cdpbStandby}
	controllers := components.FindComponentsByType(t, dut, controlcardType)
	t.Logf("Found controller list: %v", controllers)
	if len(controllers) != 2 {
		t.Skipf("Dual controllers required on %v: got %v, want 2", dut.Model(), len(controllers))
	}
	activeCard.Name, standbyCard.Name = findControllers(t, dut, controllers)
	return activeCard, standbyCard
}
