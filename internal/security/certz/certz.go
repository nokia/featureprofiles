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

package certz

import (
	"context"
	"encoding/json"
	"fmt"
	certzpb "github.com/openconfig/gnsi/certz"
	"github.com/openconfig/ondatra"
	"testing"
	"time"
)

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func AddProfile(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
	t.Logf("Performing Certz.AddProfile on device %s for profile %v", dut.Name(), sslProfileId)
	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
	if err != nil {
		t.Errorf("gNSI client error: %v", err)
	}
	_, err = gnsiC.Certz().AddProfile(context.Background(), &certzpb.AddProfileRequest{
		SslProfileId: sslProfileId,
	})
	if err != nil {
		t.Fatalf("Error adding tls profile via certz: %v", err)
	}
}

func DeleteProfile(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
	t.Logf("Performing Certz.DeleteProfile on device %s for profile %v", dut.Name(), sslProfileId)
	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
	if err != nil {
		t.Errorf("gNSI client error: %v", err)
	}
	_, err = gnsiC.Certz().DeleteProfile(context.Background(), &certzpb.DeleteProfileRequest{
		SslProfileId: sslProfileId,
	})
	if err != nil {
		t.Fatalf("Error deleting tls profile via certz: %v", err)
	}
}

func RotateIdevIdCert(t *testing.T, dut *ondatra.DUTDevice, sslProfileId string) {
	t.Logf("Performing Certz.Rotate request on device %s", dut.Name())
	gnsiC, err := dut.RawAPIs().BindingDUT().DialGNSI(context.Background())
	if err != nil {
		t.Errorf("gNSI client error: %v", err)
	}
	rotateStream, err := gnsiC.Certz().Rotate(context.Background())
	if err != nil {
		t.Fatalf("Could not start a rotate stream %v", err)
	}
	defer rotateStream.CloseSend()

	// Create Certificate Object
	certzCertificate := &certzpb.Certificate{
		Type:     certzpb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding: certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		CertificateType: &certzpb.Certificate_CertSource_{
			CertSource: certzpb.Certificate_CERT_SOURCE_IDEVID,
		},
		PrivateKeyType: &certzpb.Certificate_KeySource_{
			KeySource: certzpb.Certificate_KEY_SOURCE_IDEVID_TPM,
		},
	}

	// Create Entity Object
	certzEntity := &certzpb.Entity{
		Version:   fmt.Sprintf("v0.%v", time.Now().Unix()),
		CreatedOn: uint64(time.Now().Unix()),
		Entity: &certzpb.Entity_CertificateChain{
			CertificateChain: &certzpb.CertificateChain{
				Certificate: certzCertificate,
			},
		},
	}

	// Create Rotate Request
	certzRequest := &certzpb.RotateCertificateRequest{
		ForceOverwrite: true,
		SslProfileId:   sslProfileId,
		RotateRequest: &certzpb.RotateCertificateRequest_Certificates{
			Certificates: &certzpb.UploadRequest{
				Entities: []*certzpb.Entity{certzEntity},
			},
		},
	}

	// Send Rotate Request
	t.Logf("Sending Certz.Rotate request on device: \n %s", prettyPrint(certzRequest))
	err = rotateStream.Send(certzRequest)
	if err != nil {
		t.Fatalf("Error while uploading certz request: %v", err)
	}
	t.Logf("Certz.Rotate upload was successful, receiving response ...")
	_, err = rotateStream.Recv()
	if err != nil {
		t.Fatalf("Error while receiving certz rotate reply: %v", err)
	}

	// Finalize Rotation
	finalizeRotateRequest := &certzpb.RotateCertificateRequest{
		SslProfileId: sslProfileId,
		RotateRequest: &certzpb.RotateCertificateRequest_FinalizeRotation{
			FinalizeRotation: &certzpb.FinalizeRequest{},
		},
	}
	t.Logf("Sending Certz.Rotate FinalizeRotation request: \n %s", prettyPrint(finalizeRotateRequest))
	err = rotateStream.Send(finalizeRotateRequest)
	if err != nil {
		t.Fatalf("Error while finalizing rotate request  %v", err)
	}

}
