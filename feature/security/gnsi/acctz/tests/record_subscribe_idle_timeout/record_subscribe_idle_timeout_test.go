package record_subscribe_idle_timeout_test

import (
	"context"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/gnsi/acctz"
	"github.com/openconfig/ondatra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestAccountzRecordSubscribeIdleTimeout(t *testing.T) {
	dut := ondatra.DUT(t, "dut")

	acctzClient := dut.RawAPIs().GNSI(t).Acctz()

	acctzSubClient, err := acctzClient.RecordSubscribe(context.Background())
	if err != nil {
		t.Fatalf("failed getting accountz record subscribe client, error: %s", err)
	}

	startTime := time.Now()

	err = acctzSubClient.Send(&acctz.RecordRequest{
		Timestamp: timestamppb.New(startTime),
	})
	if err != nil {
		t.Fatalf("failed sending record request, error: %s", err)
	}

	closeToIdleTime := false
	afterIdleTime := false

	for {
		r := make(chan error)

		go func(r chan error) {
			// dont care about the record, just want to consume
			_, err = acctzSubClient.Recv()

			r <- err
		}(r)

		secsSinceStart := time.Since(startTime).Seconds()

		switch {
		case secsSinceStart >= 120:
			afterIdleTime = true
		case 120 >= secsSinceStart && secsSinceStart >= 115:
			closeToIdleTime = true
		}

		select {
		case err = <-r:
		case <-time.After(time.Second):
			if afterIdleTime {
				t.Fatal("received a record after the idle time expired")
			}

			if !closeToIdleTime {
				sleepSecs := 120 - secsSinceStart - 5

				t.Logf("sleeping %02f seconds", sleepSecs)

				time.Sleep(time.Duration(sleepSecs) * time.Second)

				closeToIdleTime = true
			}

			continue
		}

		if err == nil {
			continue
		}

		if !afterIdleTime {
			// if we get an error here it means the dut returned an error before the idle time
			// has expired, so thats bad!
			t.Fatalf("failed receiving record response, error: %s", err)
		}

		// if we get an error here thats ok because we waited until after the idle timeout
		t.Logf("got expected timeout error after idle time, error: %s", err)

		return
	}
}
