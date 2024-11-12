//// Copyright 2024 Google LLC
////
//// Licensed under the Apache License, Version 2.0 (the "License");
//// you may not use this file except in compliance with the License.
//// You may obtain a copy of the License at
////
////      http://www.apache.org/licenses/LICENSE-2.0
////
//// Unless required by applicable law or agreed to in writing, software
//// distributed under the License is distributed on an "AS IS" BASIS,
//// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//// See the License for the specific language governing permissions and
//// limitations under the License.
//
//package certz
//
//import (
//	"bytes"
//	"context"
//	"crypto"
//	"crypto/ecdsa"
//	"crypto/elliptic"
//	"crypto/rand"
//	"crypto/rsa"
//	"crypto/x509"
//	"crypto/x509/pkix"
//	"encoding/json"
//	"encoding/pem"
//	"fmt"
//	certzpb "github.com/openconfig/gnsi/certz"
//	"github.com/openconfig/ondatra"
//	"math/big"
//	"net"
//	"testing"
//	"time"
//)
//
//type CertType int8
//
//const (
//	CertTypeRaw    CertType = 0
//	CertTypeIdevid CertType = 1
//	CertTypeOdevid CertType = 2
//)
//
//type entityType int8
//
//const (
//	entityTypeCertificate entityType = 0
//	entityTypeTrust       entityType = 1
//)
//
//func prettyPrint(i interface{}) string {
//	s, _ := json.MarshalIndent(i, "", "\t")
//	return string(s)
//}
//
//func AddProfile(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
//	t.Logf("Performing Certz.AddProfile on device %s for profile %v", dut.Name(), sslProfileId)
//	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
//	if err != nil {
//		t.Errorf("gNSI client error: %v", err)
//	}
//	_, err = gnsiC.Certz().AddProfile(context.Background(), &certzpb.AddProfileRequest{
//		SslProfileId: sslProfileId,
//	})
//	if err != nil {
//		t.Fatalf("Error adding tls profile via certz: %v", err)
//	}
//}
//
//func DeleteProfile(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
//	t.Logf("Performing Certz.DeleteProfile on device %s for profile %v", dut.Name(), sslProfileId)
//	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
//	if err != nil {
//		t.Errorf("gNSI client error: %v", err)
//	}
//	_, err = gnsiC.Certz().DeleteProfile(context.Background(), &certzpb.DeleteProfileRequest{
//		SslProfileId: sslProfileId,
//	})
//	if err != nil {
//		t.Fatalf("Error deleting tls profile via certz: %v", err)
//	}
//}
//
//func RotateIdevIdCert(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
//	t.Logf("Performing Certz.Rotate request on device %s", dut.Name())
//	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
//	if err != nil {
//		t.Errorf("gNSI client error: %v", err)
//	}
//	rotateStream, err := gnsiC.Certz().Rotate(context.Background())
//	if err != nil {
//		t.Fatalf("Could not start a rotate stream %v", err)
//	}
//	defer rotateStream.CloseSend()
//
//	// Create Certificate Object
//	certificate := createCertificate(CertTypeIdevid, nil, nil)
//
//	// Create Entity Object
//	entity := createEntity(entityTypeCertificate, certificate)
//
//	// Create Rotate Request
//	certzRequest := &certzpb.RotateCertificateRequest{
//		ForceOverwrite: true,
//		SslProfileId:   sslProfileId,
//		RotateRequest: &certzpb.RotateCertificateRequest_Certificates{
//			Certificates: &certzpb.UploadRequest{
//				Entities: []*certzpb.Entity{entity},
//			},
//		},
//	}
//
//	// Send Rotate Request
//	t.Logf("Sending Certz.Rotate request on device: \n %s", prettyPrint(certzRequest))
//	err = rotateStream.Send(certzRequest)
//	if err != nil {
//		t.Fatalf("Error while uploading certz request: %v", err)
//	}
//	t.Logf("Certz.Rotate upload was successful, receiving response ...")
//	_, err = rotateStream.Recv()
//	if err != nil {
//		t.Fatalf("Error while receiving certz rotate reply: %v", err)
//	}
//
//	// Finalize Rotation
//	finalizeRotateRequest := &certzpb.RotateCertificateRequest{
//		SslProfileId: sslProfileId,
//		RotateRequest: &certzpb.RotateCertificateRequest_FinalizeRotation{
//			FinalizeRotation: &certzpb.FinalizeRequest{},
//		},
//	}
//	t.Logf("Sending Certz.Rotate FinalizeRotation request: \n %s", prettyPrint(finalizeRotateRequest))
//	err = rotateStream.Send(finalizeRotateRequest)
//	if err != nil {
//		t.Fatalf("Error while finalizing rotate request  %v", err)
//	}
//
//}
//
//func createEntity(entityType entityType, certificate *certzpb.Certificate) *certzpb.Entity {
//	entity := &certzpb.Entity{
//		Version:   fmt.Sprintf("v0.%v", time.Now().Unix()),
//		CreatedOn: uint64(time.Now().Unix()),
//	}
//	certChain := &certzpb.CertificateChain{
//		Certificate: certificate,
//	}
//
//	switch entityType {
//	case entityTypeCertificate:
//		entity.Entity = &certzpb.Entity_CertificateChain{
//			CertificateChain: certChain,
//		}
//	case entityTypeTrust:
//		entity.Entity = &certzpb.Entity_TrustBundle{
//			TrustBundle: certChain,
//		}
//	}
//
//	return entity
//}
//
//func createCertificate(rotateType CertType, keyContents, certContents []byte) *certzpb.Certificate {
//	cert := &certzpb.Certificate{
//		Type:     certzpb.CertificateType_CERTIFICATE_TYPE_X509,
//		Encoding: certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
//	}
//
//	switch rotateType {
//	case CertTypeIdevid:
//		cert.PrivateKeyType = &certzpb.Certificate_KeySource_{
//			KeySource: certzpb.Certificate_KEY_SOURCE_IDEVID_TPM,
//		}
//		cert.CertificateType = &certzpb.Certificate_CertSource_{
//			CertSource: certzpb.Certificate_CERT_SOURCE_IDEVID,
//		}
//	case CertTypeOdevid:
//		cert.PrivateKeyType = &certzpb.Certificate_KeySource_{
//			KeySource: certzpb.Certificate_KEY_SOURCE_IDEVID_TPM,
//		}
//		cert.CertificateType = &certzpb.Certificate_CertSource_{
//			CertSource: certzpb.Certificate_CERT_SOURCE_OIDEVID,
//		}
//	case CertTypeRaw:
//		cert.PrivateKeyType = &certzpb.Certificate_RawPrivateKey{
//			RawPrivateKey: keyContents,
//		}
//		cert.CertificateType = &certzpb.Certificate_RawCertificate{
//			RawCertificate: certContents,
//		}
//	}
//
//	return cert
//}
//
//func RotateCerts(t *testing.T, dut *ondatra.DUTDevice, rotateType CertType, sslProfileId string, dutKey, dutCert, trustBundle []byte) {
//	t.Logf("Performing Certz.Rotate request on device %s", dut.Name())
//	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
//	if err != nil {
//		t.Errorf("gNSI client error: %v", err)
//	}
//	rotateStream, err := gnsiC.Certz().Rotate(context.Background())
//	if err != nil {
//		t.Fatalf("Could not start a rotate stream %v", err)
//	}
//	defer rotateStream.CloseSend()
//
//	var entities []*certzpb.Entity
//	switch rotateType {
//	case CertTypeIdevid, CertTypeOdevid:
//		certificate := createCertificate(rotateType, nil, nil)
//		entities = append(entities, createEntity(entityTypeCertificate, certificate))
//	case CertTypeRaw:
//		if dutKey != nil && dutCert != nil {
//			certificate := createCertificate(rotateType, dutKey, dutCert)
//			entities = append(entities, createEntity(entityTypeCertificate, certificate))
//		}
//		if trustBundle != nil {
//			certificate := createCertificate(rotateType, nil, trustBundle)
//			entities = append(entities, createEntity(entityTypeTrust, certificate))
//		}
//	}
//
//	// Create Rotate Request
//	certzRequest := &certzpb.RotateCertificateRequest{
//		ForceOverwrite: true,
//		SslProfileId:   sslProfileId,
//		RotateRequest: &certzpb.RotateCertificateRequest_Certificates{
//			Certificates: &certzpb.UploadRequest{
//				Entities: entities,
//			},
//		},
//	}
//
//	// Send Rotate Request
//	t.Logf("Sending Certz.Rotate request on device: \n %s", prettyPrint(certzRequest))
//	err = rotateStream.Send(certzRequest)
//	if err != nil {
//		t.Fatalf("Error while uploading certz request: %v", err)
//	}
//	t.Logf("Certz.Rotate upload was successful, receiving response ...")
//	_, err = rotateStream.Recv()
//	if err != nil {
//		t.Fatalf("Error while receiving certz rotate reply: %v", err)
//	}
//
//	// Finalize Rotation
//	finalizeRotateRequest := &certzpb.RotateCertificateRequest{
//		SslProfileId: sslProfileId,
//		RotateRequest: &certzpb.RotateCertificateRequest_FinalizeRotation{
//			FinalizeRotation: &certzpb.FinalizeRequest{},
//		},
//	}
//	t.Logf("Sending Certz.Rotate FinalizeRotation request: \n %s", prettyPrint(finalizeRotateRequest))
//	err = rotateStream.Send(finalizeRotateRequest)
//	if err != nil {
//		t.Fatalf("Error while finalizing rotate request  %v", err)
//	}
//
//	// Brief sleep for finalize to get processed
//	time.Sleep(time.Second)
//}
//
//func GenTlsCert(ip string, signingCert *x509.Certificate, signingKey any, keyAlgo x509.PublicKeyAlgorithm) ([]byte, []byte, error) {
//	certSpec, err := populateCertTemplate(ip)
//	if err != nil {
//		return nil, nil, err
//	}
//	var privKey crypto.PrivateKey
//	switch keyAlgo {
//	case x509.RSA:
//		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
//		if err != nil {
//			return nil, nil, err
//		}
//	case x509.ECDSA:
//		curve := elliptic.P256()
//		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
//		if err != nil {
//			return nil, nil, err
//		}
//	default:
//		return nil, nil, fmt.Errorf("key algorithm %v is not supported", keyAlgo)
//	}
//	pubKey := privKey.(crypto.Signer).Public()
//	certBytes, err := x509.CreateCertificate(rand.Reader, certSpec, signingCert, pubKey, signingKey)
//	if err != nil {
//		return nil, nil, err
//	}
//	// PEM Encode Certificate
//	pemBlock := &pem.Block{
//		Type:  "CERTIFICATE",
//		Bytes: certBytes,
//	}
//	certPem := new(bytes.Buffer)
//	if err = pem.Encode(certPem, pemBlock); err != nil {
//		return nil, nil, err
//	}
//
//	// PEM encode private key.
//	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
//	if err != nil {
//		return nil, nil, err
//	}
//	pemBlock = &pem.Block{
//		Type:  "PRIVATE KEY",
//		Bytes: privKeyBytes,
//	}
//	privKeyPem := new(bytes.Buffer)
//	if err = pem.Encode(privKeyPem, pemBlock); err != nil {
//		return nil, nil, err
//	}
//	return certPem.Bytes(), privKeyPem.Bytes(), nil
//}
//
//func populateCertTemplate(ip string) (*x509.Certificate, error) {
//	serial, err := rand.Int(rand.Reader, big.NewInt(big.MaxBase))
//	if err != nil {
//		return nil, err
//	}
//	certSpec := &x509.Certificate{
//		SerialNumber: serial,
//		Subject: pkix.Name{
//			CommonName:   ip,
//			Organization: []string{"OpenconfigFeatureProfiles"},
//			Country:      []string{"US"},
//		},
//		IPAddresses: []net.IP{net.ParseIP(ip)},
//		NotBefore:   time.Now(),
//		NotAfter:    time.Now().AddDate(0, 0, 1),
//		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
//		KeyUsage:    x509.KeyUsageDigitalSignature,
//	}
//	return certSpec, nil
//}
