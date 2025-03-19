// Copyright 2025 Google LLC
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

package accountingauthenerrormulti

import (
	"context"
	"encoding/json"
	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/security/acctz"
	"github.com/openconfig/featureprofiles/internal/security/credz"
	acctzpb "github.com/openconfig/gnsi/acctz"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"testing"
	"time"
)

const (
	testServerGroup = "fp-tacacs"
	username        = "testuser"
	wrongPassword   = "wrongpassword"
)

type recordRequestResult struct {
	record *acctzpb.RecordResponse
	err    error
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func prettyPrint(i any) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	// Setup user and password.
	credz.SetupUser(t, dut, username)
	password := credz.GeneratePassword()
	credz.RotateUserPassword(t, dut, username, password, "v1.0", uint64(time.Now().Unix()))

	// Find any existing tacacs group on the dut.
	var tacacsGroup *oc.System_Aaa_ServerGroup
	for _, serverGroup := range gnmi.GetAll(t, dut, gnmi.OC().System().Aaa().ServerGroupAny().State()) {
		if serverGroup.Type == oc.AaaTypes_AAA_SERVER_TYPE_TACACS {
			tacacsGroup = serverGroup
			break
		}
	}

	// Delete any existing tacacs group & create test tacacs group with unconfigured server.
	batchConfig := &gnmi.SetBatch{}
	aaaConfig := &oc.System_Aaa{}
	authMethods := []oc.System_Aaa_Authentication_AuthenticationMethod_Union{
		oc.UnionString(testServerGroup),
	}
	for _, am := range gnmi.Get(t, dut, gnmi.OC().System().Aaa().Authentication().AuthenticationMethod().Config()) {
		if tacacsGroup != nil && am.(oc.UnionString) != oc.UnionString(tacacsGroup.GetName()) {
			authMethods = append(authMethods, am)
		}
	}
	gnmi.BatchDelete(batchConfig, gnmi.OC().System().Aaa().Authentication().AuthenticationMethod().Config())
	if tacacsGroup != nil {
		gnmi.BatchDelete(batchConfig, gnmi.OC().System().Aaa().ServerGroup(*tacacsGroup.Name).Config())
	}
	aaaConfig.GetOrCreateServerGroup(testServerGroup).SetType(oc.AaaTypes_AAA_SERVER_TYPE_TACACS)
	aaaConfig.GetOrCreateAuthentication().SetAuthenticationMethod(authMethods)
	gnmi.BatchUpdate(batchConfig, gnmi.OC().System().Aaa().Config(), aaaConfig)
	batchConfig.Set(t, dut)
}

func TestAccountzAuthenErrorMulti(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	var records []*acctzpb.RecordResponse

	// Save aaa config before start of test.
	aaaConfPath := gnmi.OC().System().Aaa().Config()
	aaaConfigBefore := gnmi.Get(t, dut, aaaConfPath)
	defer gnmi.Replace(t, dut, aaaConfPath, aaaConfigBefore)

	configureDUT(t, dut)

	// Put enough time between the test starting and any prior events so we can easily know where
	// our records start.
	time.Sleep(5 * time.Second)

	startTime := time.Now()
	record := acctz.SendFailCliLogin(t, dut, username, wrongPassword, acctzpb.AuthnDetail_AUTHN_TYPE_PASSWORD)
	// Set expected authn status to ERROR.
	record.SessionInfo.Authn.Status = acctzpb.AuthnDetail_AUTHN_STATUS_ERROR
	records = append(records, record)

	// Quick sleep to ensure all the records have been processed/ready for us.
	time.Sleep(5 * time.Second)

	// Get gNSI record subscribe client.
	requestTimestamp := &timestamppb.Timestamp{
		Seconds: 0,
		Nanos:   0,
	}
	acctzClient := dut.RawAPIs().GNSI(t).AcctzStream()
	acctzSubClient, err := acctzClient.RecordSubscribe(context.Background(), &acctzpb.RecordRequest{Timestamp: requestTimestamp})
	if err != nil {
		t.Fatalf("Failed sending accountz record request, error: %s", err)
	}
	defer acctzSubClient.CloseSend()

	r := make(chan recordRequestResult)
	var recordIdx int

	// Ignore proto fields which are set internally by the DUT (cannot be matched exactly)
	// and compare them manually later.
	popts := []cmp.Option{protocmp.Transform(),
		protocmp.IgnoreFields(&acctzpb.RecordResponse{}, "timestamp", "task_ids"),
		protocmp.IgnoreFields(&acctzpb.AuthzDetail{}, "detail"),
		protocmp.IgnoreFields(&acctzpb.SessionInfo{}, "channel_id", "tty"),
		protocmp.IgnoreFields(&acctzpb.AuthnDetail{}, "cause"),
	}

	for {
		if recordIdx >= len(records) {
			t.Log("Out of records to process...")
			break
		}

		// Read single acctz record from stream into channel.
		go func(r chan recordRequestResult) {
			var response *acctzpb.RecordResponse
			response, err = acctzSubClient.Recv()
			r <- recordRequestResult{
				record: response,
				err:    err,
			}
		}(r)

		var done bool
		var resp recordRequestResult

		// Read acctz record from channel for evaluation.
		// Timeout and exit if no records received on the channel for some time.
		select {
		case rr := <-r:
			resp = rr
		case <-time.After(10 * time.Second):
			done = true
		}

		if done {
			t.Log("Done receiving records...")
			break
		}

		if resp.err != nil {
			t.Fatalf("Failed receiving record response, error: %s", resp.err)
		}

		if !resp.record.Timestamp.AsTime().After(startTime) {
			// Skipping record if it happened before test start time.
			continue
		}

		// Verify acctz proto bits.
		if diff := cmp.Diff(resp.record, records[recordIdx], popts...); diff != "" {
			t.Errorf("got diff in -got,+want: %s", diff)
		}

		// Verify record timestamp is after request timestamp.
		timestamp := resp.record.Timestamp.AsTime()
		if !timestamp.After(requestTimestamp.AsTime()) {
			t.Errorf("Record timestamp is before record request timestamp %v, Record Details: %v", requestTimestamp.AsTime(), prettyPrint(resp.record))
		}

		// This channel check maybe should just go away entirely -- see:
		// https://github.com/openconfig/gnsi/issues/98
		// In case of Nokia this is being set to the aaa session id just to have some hopefully
		// useful info in this field to identify a "session" (even if it isn't necessarily ssh/grpc
		// directly).
		if resp.record.GetSessionInfo().GetChannelId() == "" {
			t.Errorf("Channel Id is not populated for record: %v", prettyPrint(resp.record))
		}

		// Tty only set for ssh records.
		if resp.record.GetSessionInfo().GetTty() == "" {
			t.Errorf("Should have tty allocated but not set, Record Details: %s", prettyPrint(resp.record))
		}

		// Verify authn cause is not empty
		if resp.record.GetSessionInfo().GetAuthn().GetCause() == "" {
			t.Errorf("Authn Cause is not populated for record: %v", prettyPrint(resp.record))
		}

		t.Logf("Processed Record: %s", prettyPrint(resp.record))
		recordIdx++
	}

	if recordIdx != len(records) {
		t.Fatal("Did not process all records.")
	}
}
