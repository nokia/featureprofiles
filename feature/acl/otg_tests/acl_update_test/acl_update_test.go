// Copyright 2023 Google LLC
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

package acl_update_test

import (
	"os"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	// gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	// "github.com/openconfig/ondatra/gnmi/oc/acl"
	"github.com/openconfig/ygot/ygot"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// Settings for configuring the baseline testbed with the test topology.
//
// The testbed consists of:
//
//	ate:port1 -> dut:port1 and
//	dut:port2 -> ate:port2
//
//	* ate:port1 -> dut:port1 subnet 192.0.2.2/30
//	* ate:port2 -> dut:port2 subnet 192.0.2.6/30
//
//	* Traffic is sent from 192.0.2.2(ate:port1) to 192.0.2.6(ate:port2).
//	  Dut Interfaces are configured as mentioned below:
//	  dut:port1 -> 192.0.2.1
//	  dut:port2 -> 192.0.2.5

const (
	ipv4PrefixLen = 30
	pps           = 100
	FrameSize     = 512
	aclNameV4     = "aclV4"
	termName      = "term1"
	EncapSrcMatch = "192.0.2.2"
	EncapDstMatch = "192.0.2.6"
	SrcAddrV4     = "198.51.100.1"
	DstAddrV4     = "203.0.113.1/32"
	flowSrcAddrV4 = "192.0.2.0/30"
	flowDstAddrV4 = "192.0.2.4/30"
	plenIPv4      = 30
	tolerance     = 50
	lossTolerance = 2
	prefix        = "0.0.0.0/0"
	nexthop       = "192.0.2.6"
)

var (
	dutSrc = attrs.Attributes{
		Desc:    "DUT to ATE source",
		IPv4:    "192.0.2.1",
		IPv4Len: plenIPv4,
	}
	ateSrc = attrs.Attributes{
		Name:    "ateSrc",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: plenIPv4,
	}
	dutDst = attrs.Attributes{
		Desc:    "DUT to ATE destination",
		IPv4:    "192.0.2.5",
		IPv4Len: plenIPv4,
	}
	ateDst = attrs.Attributes{
		Name:    "atedst",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: plenIPv4,
	}
)

// configInterfaceDUT configures the DUT interfaces.
func configInterfaceDUT(i *oc.Interface, a *attrs.Attributes, dut *ondatra.DUTDevice) *oc.Interface {
	i.Description = ygot.String(a.Desc)
	i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
	if deviations.InterfaceEnabled(dut) {
		i.Enabled = ygot.Bool(true)
	}
	s := i.GetOrCreateSubinterface(0)
	s4 := s.GetOrCreateIpv4()
	if deviations.InterfaceEnabled(dut) && !deviations.IPv4MissingEnabled(dut) {
		s4.Enabled = ygot.Bool(true)
	}
	s4a := s4.GetOrCreateAddress(a.IPv4)
	s4a.PrefixLength = ygot.Uint8(ipv4PrefixLen)
	return i
}

// configureDUT configures port1 and port2 on the DUT.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	d := gnmi.OC()
	p1 := dut.Port(t, "port1")
	i1 := &oc.Interface{Name: ygot.String(p1.Name())}
	gnmi.Replace(t, dut, d.Interface(p1.Name()).Config(), configInterfaceDUT(i1, &dutSrc, dut))
	p2 := dut.Port(t, "port2")
	i2 := &oc.Interface{Name: ygot.String(p2.Name())}
	gnmi.Replace(t, dut, d.Interface(p2.Name()).Config(), configInterfaceDUT(i2, &dutDst, dut))

	dutConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	gnmi.Replace(t, dut, dutConfPath.Type().Config(), oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE)

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, p1.Name(), deviations.DefaultNetworkInstance(dut), 0)
		fptest.AssignToNetworkInstance(t, dut, p2.Name(), deviations.DefaultNetworkInstance(dut), 0)
	}

	t.Logf("Configure DUT static-route")
	configStaticRoute(t, dut, prefix, nexthop)
}

// configACLInterface configures the ACL attachment on interface
func configACLIngressInterface(t *testing.T, dut *ondatra.DUTDevice, ifName string) {

	d1 := &oc.Root{}

	aSet := d1.GetOrCreateAcl().GetOrCreateAclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4)
	aSet.GetOrCreateAclEntry(10).GetOrCreateIpv4().SetSourceAddress(flowSrcAddrV4)
	aSet.GetOrCreateAclEntry(10).GetOrCreateActions().SetForwardingAction(oc.Acl_FORWARDING_ACTION_DROP)
	aSet.GetOrCreateAclEntry(10).GetOrCreateActions().SetForwardingAction(oc.Acl_FORWARDING_ACTION_ACCEPT)
	aSet.GetOrCreateAclEntry(20).GetOrCreateIpv4().SetDestinationAddress(flowDstAddrV4)
	aSet.GetOrCreateAclEntry(20).GetOrCreateActions().SetForwardingAction(oc.Acl_FORWARDING_ACTION_ACCEPT)
	gnmi.Replace(t, dut, gnmi.OC().Acl().AclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4).Config(), aSet)

	t.Log("Attach the filter to the ingress interface")
	iFace := d1.GetOrCreateAcl().GetOrCreateInterface(ifName)

	aclConf := gnmi.OC().Acl().Interface(ifName)
	iFace.GetOrCreateIngressAclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4)
	iFace.GetOrCreateInterfaceRef().Interface = ygot.String(ifName)
	iFace.GetOrCreateInterfaceRef().Subinterface = ygot.Uint32(0)

	gnmi.Replace(t, dut, aclConf.Config(), iFace)
	fptest.LogQuery(t, "ACL config:\n", aclConf.Config(), gnmi.Get(t, dut, aclConf.Config()))
}

// configACLInterface configures the ACL attachment on interface
func validateMatchedPackets(t *testing.T, dut *ondatra.DUTDevice, ifName string) {

	// aclCounter := gnmi.OC().Acl().Interface(ifName).IngressAclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4).AclEntry(10).MatchedPackets().State()
	aclCounter := gnmi.OC().Acl().AclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4).AclEntry(10).MatchedPackets().State()
	t.Logf("Matched Packets ingress-10 :%v", gnmi.Get(t, dut, aclCounter))

	// aclCounter2 := gnmi.OC().Acl().Interface(ifName).IngressAclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4).AclEntry(20).MatchedPackets().State()
	aclCounter2 := gnmi.OC().Acl().AclSet(aclNameV4, oc.Acl_ACL_TYPE_ACL_IPV4).AclEntry(20).MatchedPackets().State()
	t.Logf("Matched Packets ingress-20 :%v", gnmi.Get(t, dut, aclCounter2))

}

// configStaticRoute configures a static route.
func configStaticRoute(t *testing.T, dut *ondatra.DUTDevice, prefix string, nexthop string) {
	ni := oc.NetworkInstance{Name: ygot.String(deviations.DefaultNetworkInstance(dut))}
	static := ni.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
	sr := static.GetOrCreateStatic(prefix)
	nh := sr.GetOrCreateNextHop("0")
	nh.NextHop = oc.UnionString(nexthop)
	gnmi.Update(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Config(), static)
}

// configureOTG configures the traffic interfaces
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	topo := gosnappi.NewConfig()
	t.Logf("Configuring OTG port1")
	srcPort := topo.Ports().Add().SetName("port1")
	srcDev := topo.Devices().Add().SetName(ateSrc.Name)
	srcEth := srcDev.Ethernets().Add().SetName(ateSrc.Name + ".Eth").SetMac(ateSrc.MAC)
	srcEth.Connection().SetPortName(srcPort.Name())
	srcIpv4 := srcEth.Ipv4Addresses().Add().SetName(ateSrc.Name + ".IPv4")
	srcIpv4.SetAddress(ateSrc.IPv4).SetGateway(dutSrc.IPv4).SetPrefix(uint32(ateSrc.IPv4Len))
	t.Logf("Configuring OTG port2")
	dstPort := topo.Ports().Add().SetName("port2")
	dstDev := topo.Devices().Add().SetName(ateDst.Name)
	dstEth := dstDev.Ethernets().Add().SetName(ateDst.Name + ".Eth").SetMac(ateDst.MAC)
	dstEth.Connection().SetPortName(dstPort.Name())
	dstIpv4 := dstEth.Ipv4Addresses().Add().SetName(ateDst.Name + ".IPv4")
	dstIpv4.SetAddress(ateDst.IPv4).SetGateway(dutDst.IPv4).SetPrefix(uint32(ateDst.IPv4Len))
	topo.Captures().Add().SetName("grecapture").SetPortNames([]string{dstPort.Name()}).SetFormat(gosnappi.CaptureFormat.PCAP)
	t.Logf("Testtraffic:start ate Traffic config")
	flowipv4 := topo.Flows().Add().SetName("IPv4")
	flowipv4.Metrics().SetEnable(true)
	flowipv4.TxRx().Device().
		SetTxNames([]string{srcIpv4.Name()}).
		SetRxNames([]string{dstIpv4.Name()})
	flowipv4.Size().SetFixed(FrameSize)
	flowipv4.Rate().SetPps(pps)
	flowipv4.Duration().Continuous()
	e1 := flowipv4.Packet().Add().Ethernet()
	e1.Src().SetValue(srcEth.Mac())
	v4 := flowipv4.Packet().Add().Ipv4()
	v4.Src().SetValue(srcIpv4.Address())
	v4.Dst().SetValue(dstIpv4.Address())
	t.Logf("Pushing config to ATE and starting protocols...")
	ate.OTG().PushConfig(t, topo)
	t.Logf("starting protocols...")
	ate.OTG().StartProtocols(t)
	time.Sleep(30 * time.Second)
	//	otgutils.WaitForARP(t, otg, topo, "IPv4")
	pb, _ := topo.Marshal().ToProto()
	t.Log(pb.GetCaptures())
	return topo
}

// sendTraffic will send the traffic for a fixed duration
func sendTraffic(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
	t.Log("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(15 * time.Second)
	otg.StopTraffic(t)
	t.Log("Traffic stopped")
}

// captureTrafficStats Captures traffic statistics and verifies for the loss
func captureTrafficStats(t *testing.T, ate *ondatra.ATEDevice, config gosnappi.Config) {
	otg := ate.OTG()
	ap := ate.Port(t, "port1")
	t.Log("get sent packets from port1 Traffic statistics")
	aic1 := gnmi.OTG().Port(ap.ID()).Counters()
	sentPkts := gnmi.Get(t, otg, aic1.OutFrames().State())
	fptest.LogQuery(t, "ate:port1 counters", aic1.State(), gnmi.Get(t, otg, aic1.State()))
	op := ate.Port(t, "port2")
	aic2 := gnmi.OTG().Port(op.ID()).Counters()
	t.Log("get recieved packets from port2 Traffic statistics")
	rxPkts := gnmi.Get(t, otg, aic2.InFrames().State())
	fptest.LogQuery(t, "ate:port2 counters", aic2.State(), gnmi.Get(t, otg, aic2.State()))
	var lostPkts uint64
	t.Log("Verify Traffic statistics")
	if rxPkts > sentPkts {
		lostPkts = rxPkts - sentPkts
	} else {
		lostPkts = sentPkts - rxPkts
	}
	t.Logf("Packets: %d sent, %d received, %d lost", sentPkts, rxPkts, lostPkts)
	if lostPkts > tolerance {
		t.Errorf("Lost Packets are more than tolerance: %d", lostPkts)
	} else {
		t.Log("Traffic Test Passed!")
	}
	bytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(config.Ports().Items()[1].Name()))
	f, err := os.CreateTemp("", "pcap")
	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(bytes); err != nil {
		t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	}
	f.Close()
}

func TestACL(t *testing.T) {
	start := time.Now()
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)
	otg := ondatra.ATE(t, "ate")
	config := configureOTG(t, otg)

	ifName := dut.Port(t, "port1").Name()
	configACLIngressInterface(t, dut, ifName)

	t.Log("send Traffic statistics")
	sendTraffic(t, otg)
	captureTrafficStats(t, otg, config)
	validateMatchedPackets(t, dut, ifName)

	t.Logf("Time check: %s", time.Since(start))
	t.Logf("Test run time: %s", time.Since(start))
}
