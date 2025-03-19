// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package acctz provides helper APIs to simplify writing acctz test cases.
package acctz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/openconfig/featureprofiles/internal/security/credz"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	systempb "github.com/openconfig/gnoi/system"
	acctzpb "github.com/openconfig/gnsi/acctz"
	authzpb "github.com/openconfig/gnsi/authz"
	cpb "github.com/openconfig/gnsi/credentialz"
	gribi "github.com/openconfig/gribi/v1/proto/service"
	tpb "github.com/openconfig/kne/proto/topo"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/binding"
	"github.com/openconfig/ondatra/binding/introspect"
	ondatragnmi "github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	p4pb "github.com/p4lang/p4runtime/go/p4/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	successUsername   = "acctztestuser"
	successPassword   = "verysecurepassword"
	failUsername      = "bilbo"
	failPassword      = "baggins"
	failRoleName      = "acctz-fp-test-fail"
	successCliCommand = "show version"
	failCliCommand    = "show version"
	shellCommand      = "uname -a"
	defaultSSHPort    = 22
	ipProto           = 6
	userPrincipal     = "testuser_principal"
)

var (
	gRPCClientAddr net.Addr
	gRPCServerAddr net.Addr
	sshClientAddr  net.Addr
	sshServerAddr  net.Addr
	gRPCPaths      = map[acctzpb.GrpcService_GrpcServiceType]string{
		acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNMI:  "/gnmi.gNMI/Capabilities",
		acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNOI:  "/gnoi.system.System/Ping",
		acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNSI:  "/gnsi.authz.v1.Authz/Get",
		acctzpb.GrpcService_GRPC_SERVICE_TYPE_GRIBI: "/gribi.gRIBI/Get",
		acctzpb.GrpcService_GRPC_SERVICE_TYPE_P4RT:  "/p4.v1.P4Runtime/Capabilities",
	}
)

func setupUserPassword(t *testing.T, dut *ondatra.DUTDevice, username, password string) {
	request := &cpb.RotateAccountCredentialsRequest{
		Request: &cpb.RotateAccountCredentialsRequest_Password{
			Password: &cpb.PasswordRequest{
				Accounts: []*cpb.PasswordRequest_Account{
					{
						Account: username,
						Password: &cpb.PasswordRequest_Password{
							Value: &cpb.PasswordRequest_Password_Plaintext{
								Plaintext: password,
							},
						},
						Version:   "v1.0",
						CreatedOn: uint64(time.Now().Unix()),
					},
				},
			},
		},
	}

	credzClient := dut.RawAPIs().GNSI(t).Credentialz()
	credzRotateClient, err := credzClient.RotateAccountCredentials(context.Background())
	if err != nil {
		t.Fatalf("Failed fetching credentialz rotate account credentials client, error: %s", err)
	}
	err = credzRotateClient.Send(request)
	if err != nil {
		t.Fatalf("Failed sending credentialz rotate account credentials request, error: %s", err)
	}
	_, err = credzRotateClient.Recv()
	if err != nil {
		t.Fatalf("Failed receiving credentialz rotate account credentials response, error: %s", err)
	}
	err = credzRotateClient.Send(&cpb.RotateAccountCredentialsRequest{
		Request: &cpb.RotateAccountCredentialsRequest_Finalize{
			Finalize: request.GetFinalize(),
		},
	})
	if err != nil {
		t.Fatalf("Failed sending credentialz rotate account credentials finalize request, error: %s", err)
	}

	// Brief sleep for finalize to get processed.
	time.Sleep(time.Second)
}

func nokiaFailCliRole(t *testing.T) *gnmipb.SetRequest {
	failRoleData, err := json.Marshal([]any{
		map[string]any{
			"services": []string{"cli"},
			"cli": map[string][]string{
				"deny-command-list": {failCliCommand},
			},
		},
	})
	if err != nil {
		t.Fatalf("Error with json marshal: %v", err)
	}

	return &gnmipb.SetRequest{
		Prefix: &gnmipb.Path{
			Origin: "native",
		},
		Replace: []*gnmipb.Update{
			{
				Path: &gnmipb.Path{
					Elem: []*gnmipb.PathElem{
						{Name: "system"},
						{Name: "aaa"},
						{Name: "authorization"},
						{Name: "role", Key: map[string]string{"rolename": failRoleName}},
					},
				},
				Val: &gnmipb.TypedValue{
					Value: &gnmipb.TypedValue_JsonIetfVal{
						JsonIetfVal: failRoleData,
					},
				},
			},
		},
	}
}

// SetupUsers Setup users for acctz tests and optionally configure cli role for denied commands.
func SetupUsers(t *testing.T, dut *ondatra.DUTDevice, configureFailCliRole bool) {
	auth := &oc.System_Aaa_Authentication{}
	successUser := auth.GetOrCreateUser(successUsername)
	successUser.SetRole(oc.AaaTypes_SYSTEM_DEFINED_ROLES_SYSTEM_ROLE_ADMIN)
	failUser := auth.GetOrCreateUser(failUsername)
	if configureFailCliRole {
		var SetRequest *gnmipb.SetRequest

		// Create failure cli role in native.
		switch dut.Vendor() {
		case ondatra.NOKIA:
			SetRequest = nokiaFailCliRole(t)
		}

		gnmiClient := dut.RawAPIs().GNMI(t)
		if _, err := gnmiClient.Set(context.Background(), SetRequest); err != nil {
			t.Fatalf("Unexpected error configuring role: %v", err)
		}

		failUser.SetRole(oc.UnionString(failRoleName))
	}
	ondatragnmi.Update(t, dut, ondatragnmi.OC().System().Aaa().Authentication().Config(), auth)
	setupUserPassword(t, dut, successUsername, successPassword)
	setupUserPassword(t, dut, failUsername, failPassword)
}

func getGrpcTarget(t *testing.T, dut *ondatra.DUTDevice, service introspect.Service) string {
	dialTarget := introspect.DUTDialer(t, dut, service).DialTarget
	resolvedTarget, err := net.ResolveTCPAddr("tcp", dialTarget)
	if err != nil {
		t.Fatalf("Failed resolving %s target %s", service, dialTarget)
	}
	t.Logf("Target for %s service: %s", service, resolvedTarget)
	return resolvedTarget.String()
}

func getSSHTarget(t *testing.T, dut *ondatra.DUTDevice) string {
	var serviceDUT interface {
		Service(string) (*tpb.Service, error)
	}

	var target string
	err := binding.DUTAs(dut.RawAPIs().BindingDUT(), &serviceDUT)
	if err != nil {
		t.Log("DUT does not support `Service` function, will attempt to resolve dut name field.")

		// Suppose ssh could be not 22 in some cases but don't think this is exposed by introspect.
		dialTarget := fmt.Sprintf("%s:%d", dut.Name(), defaultSSHPort)
		resolvedTarget, err := net.ResolveTCPAddr("tcp", dialTarget)
		if err != nil {
			t.Fatalf("Failed resolving ssh target %s", dialTarget)
		}
		target = resolvedTarget.String()
	} else {
		dutSSHService, err := serviceDUT.Service("ssh")
		if err != nil {
			t.Fatal(err)
		}
		target = fmt.Sprintf("%s:%d", dutSSHService.GetOutsideIp(), dutSSHService.GetOutside())
	}

	t.Logf("Target for ssh service: %s", target)
	return target
}

func dialGrpc(t *testing.T, target string, cert *tls.Certificate) *grpc.ClientConn {
	conf := &tls.Config{}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	} else {
		conf.InsecureSkipVerify = true
	}

	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(
			credentials.NewTLS(conf),
		),
		grpc.WithContextDialer(func(ctx context.Context, a string) (net.Conn, error) {
			dst, err := net.ResolveTCPAddr("tcp", a)
			if err != nil {
				return nil, err
			}
			c, err := net.DialTCP("tcp", nil, dst)
			if err != nil {
				return nil, err
			}
			gRPCClientAddr = c.LocalAddr()
			gRPCServerAddr = c.RemoteAddr()
			return c, err
		}))
	if err != nil {
		t.Fatalf("Got unexpected error dialing gRPC target %q, error: %v", target, err)
	}

	return conn
}

func dialSSH(t *testing.T, dut *ondatra.DUTDevice, username, password, keyDir string, authnType acctzpb.AuthnDetail_AuthnType) (*ssh.Client, io.WriteCloser, error) {
	var authMethod ssh.AuthMethod

	switch authnType {
	case acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD:
		authMethod = ssh.Password(password)

	case acctzpb.AuthnDetail_AUTHN_TYPE_SSHKEY:
		privateKeyContents, err := os.ReadFile(fmt.Sprintf("%s/%s", keyDir, username))
		if err != nil {
			t.Fatalf("Failed reading private key contents, error: %s", err)
		}
		signer, err := ssh.ParsePrivateKey(privateKeyContents)
		if err != nil {
			t.Fatalf("Failed parsing private key, error: %s", err)
		}
		authMethod = ssh.PublicKeys(signer)

	case acctzpb.AuthnDetail_AUTHN_TYPE_SSHCERT:
		privateKeyContents, err := os.ReadFile(fmt.Sprintf("%s/%s", keyDir, username))
		if err != nil {
			t.Fatalf("Failed reading private key contents, error: %s", err)
		}
		signer, err := ssh.ParsePrivateKey(privateKeyContents)
		if err != nil {
			t.Fatalf("Failed parsing private key, error: %s", err)
		}
		certificateContents, err := os.ReadFile(fmt.Sprintf("%s/%s-cert.pub", keyDir, username))
		if err != nil {
			t.Fatalf("Failed reading certificate contents, error: %s", err)
		}
		certificate, _, _, _, err := ssh.ParseAuthorizedKey(certificateContents)
		if err != nil {
			t.Fatalf("Failed parsing certificate contents, error: %s", err)
		}
		certificateSigner, err := ssh.NewCertSigner(certificate.(*ssh.Certificate), signer)
		if err != nil {
			t.Fatalf("Failed creating certificate signer, error: %s", err)
		}
		authMethod = ssh.PublicKeys(certificateSigner)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Per https://github.com/openconfig/featureprofiles/issues/2637, waiting to see what the
	// "best"/"preferred" way is to get the v4/v6 of the dut. For now, we use this workaround
	// because ssh isn't exposed in introspection.
	target := getSSHTarget(t, dut)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatalf("Got unexpected error dialing tcp target %s, error: %v", target, err)
	}
	sshClientAddr = conn.LocalAddr()
	sshServerAddr = conn.RemoteAddr()

	c, chans, reqs, err := ssh.NewClientConn(conn, target, config)
	if err != nil {
		return nil, nil, err
	}

	client := ssh.NewClient(c, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed creating ssh session, error: %s", err)
	}

	w, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}

	term := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	err = sess.RequestPty(
		"xterm",
		40,
		80,
		term,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = sess.Shell()
	if err != nil {
		t.Fatal(err)
	}

	return client, w, nil
}

func getHostPortInfo(t *testing.T, address string) (string, uint32) {
	ip, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return ip, uint32(portNumber)
}

// SendGnmiRPCs Setup gNMI test RPCs (successful and failed) to be used in the acctz client tests.
func SendGnmiRPCs(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	serviceType := acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNMI

	// Send an unsuccessful gNMI capabilities request (bad creds in context).
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", failUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", failPassword)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%s rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status: acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
			},
		},
	})

	// Send a successful gNMI capabilities request.
	ctx = context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", successUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", successPassword)
	payload, err := sendRPC(t, dut, ctx, serviceType)
	if err != nil {
		t.Fatalf("Got unexpected error for gnmi rpc: %s, error: %s", gRPCPaths[serviceType], err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Payload: &acctzpb.GrpcService_ProtoVal{
					ProtoVal: payload,
				},
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendGnoiRPCs Setup gNOI test RPCs (successful and failed) to be used in the acctz client tests.
func SendGnoiRPCs(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	serviceType := acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNOI

	// Send an unsuccessful gNOI system ping request (bad creds in context), we don't
	// care about receiving on it, just want to make the request.
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", failUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", failPassword)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status: acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
			},
		},
	})

	// Send a successful gNOI ping request.
	ctx = context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", successUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", successPassword)
	payload, err := sendRPC(t, dut, ctx, serviceType)
	if err != nil {
		t.Fatalf("Got unexpected error for gnoi rpc: %s, error: %s", gRPCPaths[serviceType], err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Payload: &acctzpb.GrpcService_ProtoVal{
					ProtoVal: payload,
				},
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendGnsiRPCs Setup gNSI test RPCs (successful and failed) to be used in the acctz client tests.
func SendGnsiRPCs(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	serviceType := acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNSI

	// Send an unsuccessful gNSI authz get request (bad creds in context), we don't
	// care about receiving on it, just want to make the request.
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", failUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", failPassword)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status: acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
			},
		},
	})

	// Send a successful gNSI authz get request.
	ctx = context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", successUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", successPassword)
	payload, err := sendRPC(t, dut, ctx, acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNSI)
	if err != nil {
		t.Fatalf("Got unexpected error for gnsi rpc: %s, error: %s", gRPCPaths[serviceType], err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Payload: &acctzpb.GrpcService_ProtoVal{
					ProtoVal: payload,
				},
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendGribiRPCs Setup gRIBI test RPCs (successful and failed) to be used in the acctz client tests.
func SendGribiRPCs(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	serviceType := acctzpb.GrpcService_GRPC_SERVICE_TYPE_GRIBI

	// Send an unsuccessful gRIBI get request (bad creds in context), we don't
	// care about receiving on it, just want to make the request.
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", failUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", failPassword)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status: acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
			},
		},
	})

	// Send a successful gRIBI get request.
	ctx = context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", successUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", successPassword)
	payload, err := sendRPC(t, dut, ctx, acctzpb.GrpcService_GRPC_SERVICE_TYPE_GRIBI)
	if err != nil {
		// Having no messages, we get an EOF so this is not a failure.
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Got unexpected error for gribi rpc: %s, error: %s", gRPCPaths[serviceType], err)
		}
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Payload: &acctzpb.GrpcService_ProtoVal{
					ProtoVal: payload,
				},
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendP4rtRPCs Setup P4RT test RPCs (successful and failed) to be used in the acctz client tests.
func SendP4rtRPCs(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	serviceType := acctzpb.GrpcService_GRPC_SERVICE_TYPE_P4RT

	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", failUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", failPassword)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status: acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
			},
		},
	})

	ctx = context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", successUsername)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", successPassword)
	payload, err := sendRPC(t, dut, ctx, serviceType)
	if err != nil {
		t.Fatalf("Got unexpected error for p4rt rpc: %s, error: %s", gRPCPaths[serviceType], err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: acctzpb.GrpcService_GRPC_SERVICE_TYPE_P4RT,
				RpcName:     gRPCPaths[serviceType],
				Payload: &acctzpb.GrpcService_ProtoVal{
					ProtoVal: payload,
				},
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendSuccessCliCommand Setup test CLI command (successful) to be used in the acctz client tests.
func SendSuccessCliCommand(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse

	sshConn, w, err := dialSSH(t, dut, successUsername, successPassword, "", acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	if err != nil {
		t.Fatalf("Error dialing ssh connection for username: %s, password: %s, error: %s", successUsername, successPassword, err)
	}

	defer func() {
		// Give things a second to percolate then close the connection.
		time.Sleep(3 * time.Second)
		err := sshConn.Close()
		if err != nil {
			t.Logf("Error closing tcp(ssh) connection, will ignore, error: %s", err)
		}
	}()

	_, err = w.Write([]byte(fmt.Sprintf("%s\n", successCliCommand)))
	if err != nil {
		t.Fatalf("Failed sending cli command, error: %s", err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_CLI,
				Cmd:         successCliCommand,
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_OPERATION,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: successUsername,
			},
		},
	})

	return records
}

// SendFailCliCommand Setup test CLI command (failed) to be used in the acctz client tests.
func SendFailCliCommand(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	sshConn, w, err := dialSSH(t, dut, failUsername, failPassword, "", acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	if err != nil {
		t.Fatalf("Error dialing ssh connection for username: %s, password: %s, error: %s", failUsername, failPassword, err)
	}

	defer func() {
		// Give things a second to percolate then close the connection.
		time.Sleep(3 * time.Second)
		err := sshConn.Close()
		if err != nil {
			t.Logf("Error closing tcp(ssh) connection, will ignore, error: %s", err)
		}
	}()

	_, err = w.Write([]byte(fmt.Sprintf("%s\n", failCliCommand)))
	if err != nil {
		t.Fatalf("Failed sending cli command, error: %s", err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_CLI,
				Cmd:         failCliCommand,
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_DENY,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_OPERATION,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_SUCCESS,
				Cause:  "authentication_method: local",
			},
			User: &acctzpb.UserDetail{
				Identity: failUsername,
				Role:     failRoleName,
			},
		},
	})

	return records
}

// SendShellCommand Setup test shell command (successful) to be used in the acctz client tests.
func SendShellCommand(t *testing.T, dut *ondatra.DUTDevice) []*acctzpb.RecordResponse {
	var records []*acctzpb.RecordResponse
	shellUsername := successUsername
	shellPassword := successPassword

	switch dut.Vendor() {
	case ondatra.NOKIA:
		// Assuming linuxadmin is present and ssh'ing directly via this user gets us to shell
		// straight away so this is easy button to trigger a shell record.
		shellUsername = "linuxadmin"
		shellPassword = "NokiaSrl1!"
	}

	sshConn, w, err := dialSSH(t, dut, shellUsername, shellPassword, "", acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	if err != nil {
		t.Fatalf("Error dialing ssh connection for username: %s, password: %s, error: %s", shellUsername, shellPassword, err)
	}

	defer func() {
		// Give things a second to percolate then close the connection.
		time.Sleep(3 * time.Second)
		err := sshConn.Close()
		if err != nil {
			t.Logf("Error closing tcp(ssh) connection, will ignore, error: %s", err)
		}
	}()

	// This might not work for other vendors, so probably we can have a switch here and pass
	// the writer to func per vendor if needed.
	_, err = w.Write([]byte(fmt.Sprintf("%s\n", shellCommand)))
	if err != nil {
		t.Fatalf("Failed sending cli command, error: %s", err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	records = append(records, &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_SHELL,
				Cmd:         shellCommand,
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_OPERATION,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: shellUsername,
			},
		},
	})

	return records
}

// SendFailCliLogin Setup test CLI login (failed) to be used in the acctz client tests.
func SendFailCliLogin(t *testing.T, dut *ondatra.DUTDevice, username, password string, authnType acctzpb.AuthnDetail_AuthnType) *acctzpb.RecordResponse {
	defer credz.RotateAuthenticationTypes(t, dut, []cpb.AuthenticationType{
		cpb.AuthenticationType_AUTHENTICATION_TYPE_PASSWORD,
		cpb.AuthenticationType_AUTHENTICATION_TYPE_PUBKEY,
		cpb.AuthenticationType_AUTHENTICATION_TYPE_KBDINTERACTIVE,
	})

	switch authnType {
	case acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD:
		_, _, err := dialSSH(t, dut, username, password, "", authnType)
		if err == nil {
			t.Fatalf("SSH connection for username: %s, password: %s succeeded but expected to fail.", username, password)
		}
		t.Logf("SSH connection for username: %s, password: %s failed as expected. error: %s", username, password, err)

	case acctzpb.AuthnDetail_AUTHN_TYPE_SSHKEY:
		// Create temporary directory for storing ssh keys.
		dir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("Creating temp dir, err: %s", err)
		}
		defer func(dir string) {
			err = os.RemoveAll(dir)
			if err != nil {
				t.Logf("Error removing temp directory, error: %s", err)
			}
		}(dir)

		// Create ssh keys for testuser.
		credz.CreateSSHKeyPair(t, dir, username)
		credz.RotateAuthenticationTypes(t, dut, []cpb.AuthenticationType{
			cpb.AuthenticationType_AUTHENTICATION_TYPE_PUBKEY,
		})

		_, _, err = dialSSH(t, dut, username, password, dir, authnType)
		if err == nil {
			t.Fatalf("SSH connection with key for username: %s succeeded but expected to fail.", username)
		}
		t.Logf("SSH connection with key for username: %s failed as expected. error: %s", username, err)

	case acctzpb.AuthnDetail_AUTHN_TYPE_SSHCERT:
		// Create temporary directory for storing ssh keys/certificates.
		dir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatalf("Creating temp dir, err: %s", err)
		}
		defer func(dir string) {
			err = os.RemoveAll(dir)
			if err != nil {
				t.Logf("Error removing temp directory, error: %s", err)
			}
		}(dir)

		// Create ssh keys/certificates for CA & test user.
		credz.CreateSSHKeyPair(t, dir, "ca")
		credz.CreateSSHKeyPair(t, dir, username)
		credz.CreateUserCertificate(t, dir, userPrincipal)
		credz.RotateAuthenticationTypes(t, dut, []cpb.AuthenticationType{
			cpb.AuthenticationType_AUTHENTICATION_TYPE_PUBKEY,
		})

		_, _, err = dialSSH(t, dut, username, password, dir, authnType)
		if err == nil {
			t.Fatalf("SSH connection with certificate for username: %s succeeded but expected to fail.", username)
		}
		t.Logf("SSH connection with certificate for username: %s failed as expected. error: %s", username, err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	return &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_CLI,
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_LOGIN,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   authnType,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_FAIL,
			},
			User: &acctzpb.UserDetail{
				Identity: username,
			},
		},
	}
}

// SendFailShellLogin Setup test Shell login (failed) to be used in the acctz client tests.
func SendFailShellLogin(t *testing.T, dut *ondatra.DUTDevice) *acctzpb.RecordResponse {
	var shellUsername string

	switch dut.Vendor() {
	case ondatra.NOKIA:
		// Assuming linuxadmin is present and ssh'ing directly via this user gets us to shell straight away.
		shellUsername = "linuxadmin"
	}

	// Dial SSH with incorrect (empty) password.
	_, _, err := dialSSH(t, dut, shellUsername, "", "", acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	if err == nil {
		t.Fatalf("SSH connection to shell for username: %s succeeded but expected to fail.", shellUsername)
	}
	t.Logf("SSH connection to shell for username: %s, password: failed as expected. error: %s", shellUsername, err)

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	return &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_SHELL,
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_LOGIN,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_FAIL,
			},
			User: &acctzpb.UserDetail{
				Identity: shellUsername,
			},
		},
	}
}

// SendFailTlsLogin Setup test tls login (failed) to be used in the acctz client tests.
// Ensure mTLS is enabled on the dut prior to calling this function.
func SendFailTlsLogin(t *testing.T, dut *ondatra.DUTDevice) *acctzpb.RecordResponse {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key. error: %s", err)
	}

	// Prepare a dummy self-signed tls certificate.
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"OpenconfigFeatureProfiles"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		DNSNames:    []string{"localhost"},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate. error: %s", err)
	}

	// Create tls certificate object to be used for dialing gRPC.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key. error: %s", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create tls certificate. error: %s", cert)
	}

	target := getGrpcTarget(t, dut, introspect.GNMI)
	conn := dialGrpc(t, target, &cert)
	defer conn.Close()
	gnmiClient := gnmipb.NewGNMIClient(conn)
	req := &gnmipb.CapabilityRequest{}
	_, err = gnmiClient.Capabilities(context.Background(), req)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNMI])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNMI], err)

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	return &acctzpb.RecordResponse{
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_LOGIN,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_TLSCERT,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_FAIL,
			},
		},
	}
}

func sendRPC(t *testing.T, dut *ondatra.DUTDevice, ctx context.Context, serviceType acctzpb.GrpcService_GrpcServiceType) (*anypb.Any, error) {
	var payload *anypb.Any
	var err error

	// Per https://github.com/openconfig/featureprofiles/issues/2637, waiting to see what the
	// "best"/"preferred" way is to get the v4/v6 of the dut. For now, we just use introspection
	// but that won't get us v4 and v6, it will just get us whatever is configured in binding,
	// so while the test asks for v4 and v6 we'll just be doing it for whatever we get.
	switch serviceType {
	case acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNMI:
		target := getGrpcTarget(t, dut, introspect.GNMI)
		conn := dialGrpc(t, target, nil)
		defer conn.Close()
		gnmiClient := gnmipb.NewGNMIClient(conn)
		req := &gnmipb.CapabilityRequest{}
		payload, _ = anypb.New(req)
		_, err = gnmiClient.Capabilities(ctx, req)

	case acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNOI:
		target := getGrpcTarget(t, dut, introspect.GNOI)
		conn := dialGrpc(t, target, nil)
		defer conn.Close()
		gnoiSystemClient := systempb.NewSystemClient(conn)
		req := &systempb.PingRequest{
			Destination: "127.0.0.1",
			Count:       1,
		}
		payload, _ = anypb.New(req)
		var gnoiSystemPingClient systempb.System_PingClient
		gnoiSystemPingClient, err = gnoiSystemClient.Ping(ctx, req)
		if err != nil {
			t.Fatalf("Error fetching gnoi ping endpoint, error: %s", err)
		}
		_, err = gnoiSystemPingClient.Recv()

	case acctzpb.GrpcService_GRPC_SERVICE_TYPE_GNSI:
		target := getGrpcTarget(t, dut, introspect.GNSI)
		conn := dialGrpc(t, target, nil)
		defer conn.Close()
		authzClient := authzpb.NewAuthzClient(conn)
		req := &authzpb.GetRequest{}
		payload, _ = anypb.New(req)
		_, err = authzClient.Get(ctx, &authzpb.GetRequest{})

	case acctzpb.GrpcService_GRPC_SERVICE_TYPE_GRIBI:
		target := getGrpcTarget(t, dut, introspect.GRIBI)
		conn := dialGrpc(t, target, nil)
		defer conn.Close()
		gribiClient := gribi.NewGRIBIClient(conn)
		req := &gribi.GetRequest{
			NetworkInstance: &gribi.GetRequest_All{},
			Aft:             gribi.AFTType_IPV4,
		}
		payload, _ = anypb.New(req)
		var gribiGetClient grpc.ServerStreamingClient[gribi.GetResponse]
		gribiGetClient, err = gribiClient.Get(ctx, req)
		if err != nil {
			t.Fatalf("Error fetching gribi get endpoint, error: %s", err)
		}
		_, err = gribiGetClient.Recv()

	case acctzpb.GrpcService_GRPC_SERVICE_TYPE_P4RT:
		target := getGrpcTarget(t, dut, introspect.P4RT)
		conn := dialGrpc(t, target, nil)
		defer conn.Close()
		p4rtclient := p4pb.NewP4RuntimeClient(conn)
		req := &p4pb.CapabilitiesRequest{}
		payload, err = anypb.New(req)
		_, err = p4rtclient.Capabilities(ctx, req)
	}

	return payload, err
}

// SendFailRPC Setup test RPCs (failed authentication) to be used in the acctz client tests.
func SendFailRPC(t *testing.T, dut *ondatra.DUTDevice, username, password string, serviceType acctzpb.GrpcService_GrpcServiceType) *acctzpb.RecordResponse {
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "username", username)
	ctx = metadata.AppendToOutgoingContext(ctx, "password", password)
	_, err := sendRPC(t, dut, ctx, serviceType)
	if err == nil {
		t.Fatalf("%v rpc succeeded but expected to fail", gRPCPaths[serviceType])
	}
	t.Logf("%s rpc failed as expected. error: %s", gRPCPaths[serviceType], err)

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, gRPCClientAddr.String())
	localIP, localPort := getHostPortInfo(t, gRPCServerAddr.String())

	return &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_GrpcService{
			GrpcService: &acctzpb.GrpcService{
				ServiceType: serviceType,
				RpcName:     gRPCPaths[serviceType],
				Authz:       &acctzpb.AuthzDetail{},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ONCE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_FAIL,
			},
			User: &acctzpb.UserDetail{
				Identity: username,
			},
		},
	}
}

// SendEnableShellCommand Setup enable shell command (sudo calls) to be used in the acctz client tests.
func SendEnableShellCommand(t *testing.T, dut *ondatra.DUTDevice) *acctzpb.RecordResponse {
	shellUsername := successUsername
	shellPassword := successPassword

	switch dut.Vendor() {
	case ondatra.NOKIA:
		// Assuming linuxadmin is present and ssh'ing directly via this user gets us to shell straight away.
		shellUsername = "linuxadmin"
		shellPassword = "NokiaSrl1!"
	}

	sshConn, w, err := dialSSH(t, dut, shellUsername, shellPassword, "", acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	if err != nil {
		t.Fatalf("Error dialing ssh connection for username: %s, password: %s, error: %s", shellUsername, shellPassword, err)
	}

	defer func() {
		// Give things a second to percolate then close the connection.
		time.Sleep(3 * time.Second)
		err := sshConn.Close()
		if err != nil {
			t.Logf("Error closing tcp(ssh) connection, will ignore, error: %s", err)
		}
	}()

	// This might not work for other vendors, so probably we can have a switch here and pass
	// the writer to func per vendor if needed.
	_, err = w.Write([]byte(fmt.Sprintf("sudo %s\n", shellCommand)))
	if err != nil {
		t.Fatalf("Failed sending cli command, error: %s", err)
	}

	// Remote from the perspective of the router.
	remoteIP, remotePort := getHostPortInfo(t, sshClientAddr.String())
	localIP, localPort := getHostPortInfo(t, sshServerAddr.String())

	return &acctzpb.RecordResponse{
		ServiceRequest: &acctzpb.RecordResponse_CmdService{
			CmdService: &acctzpb.CommandService{
				ServiceType: acctzpb.CommandService_CMD_SERVICE_TYPE_SHELL,
				Cmd:         fmt.Sprintf("sudo %s", shellCommand),
				Authz: &acctzpb.AuthzDetail{
					Status: acctzpb.AuthzDetail_AUTHZ_STATUS_PERMIT,
				},
			},
		},
		SessionInfo: &acctzpb.SessionInfo{
			Status:        acctzpb.SessionInfo_SESSION_STATUS_ENABLE,
			LocalAddress:  localIP,
			LocalPort:     localPort,
			RemoteAddress: remoteIP,
			RemotePort:    remotePort,
			IpProto:       ipProto,
			Authn: &acctzpb.AuthnDetail{
				Type:   acctzpb.AuthnDetail_AUTHN_TYPE_UNSPECIFIED,
				Status: acctzpb.AuthnDetail_AUTHN_STATUS_UNSPECIFIED,
			},
			User: &acctzpb.UserDetail{
				Identity: shellUsername,
			},
		},
	}
}
