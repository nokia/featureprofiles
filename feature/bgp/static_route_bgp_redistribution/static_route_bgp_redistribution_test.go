package static_route_bgp_redistribution_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	otgtelemetry "github.com/openconfig/ondatra/gnmi/otg"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

const (
	ipv4PrefixLen              = 30
	ipv6PrefixLen              = 126
	subInterfaceIndex          = 0
	mtu                        = 1500
	peerGroupName              = "PEER-GROUP"
	dutAsn                     = 64512
	atePeer1Asn                = 64511
	atePeer2Asn                = 64512
	acceptRoute                = true
	metricPropagate            = true
	policyResultNext           = true
	isV4                       = true
	shouldBePresent            = true
	replace                    = true
	redistributeStaticPolicyV4 = "route-policy-v4"
	redistributeStaticPolicyV6 = "route-policy-v6"
	policyStatementV4          = "statement-v4"
	policyStatementV6          = "statement-v6"
	trafficDuration            = 30 * time.Second
	tolerancePct               = 2
	medZero                    = 0
	medNonZero                 = 1000
	localPreference            = 100
)

var (
	dutPort1 = &attrs.Attributes{
		Name:    "dutPort1",
		MAC:     "00:12:01:01:01:01",
		IPv4:    "192.168.1.1",
		IPv6:    "2001:db8::1",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	dutPort2 = &attrs.Attributes{
		Name:    "dutPort2",
		MAC:     "00:12:02:01:01:01",
		IPv4:    "192.168.1.5",
		IPv6:    "2001:db8::5",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	dutPort3 = &attrs.Attributes{
		Name:    "dutPort3",
		MAC:     "00:12:03:01:01:01",
		IPv4:    "192.168.1.9",
		IPv6:    "2001:db8::9",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	atePort1 = &attrs.Attributes{
		Name:    "atePort1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.168.1.2",
		IPv6:    "2001:db8::2",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	atePort2 = &attrs.Attributes{
		Name:    "atePort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.168.1.6",
		IPv6:    "2001:db8::6",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	atePort3 = &attrs.Attributes{
		Name:    "atePort3",
		MAC:     "02:00:03:01:01:01",
		IPv4:    "192.168.1.10",
		IPv6:    "2001:db8::a",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
		MTU:     mtu,
	}

	dutPorts = map[string]*attrs.Attributes{
		"port1": dutPort1,
		"port2": dutPort2,
		"port3": dutPort3,
	}
)

func configureDUTPort(
	t *testing.T,
	dut *ondatra.DUTDevice,
	port *ondatra.Port,
	portAttrs *attrs.Attributes,
) {
	t.Helper()

	gnmi.Replace(
		t,
		dut,
		gnmi.OC().Interface(port.Name()).Config(),
		portAttrs.NewOCInterface(port.Name(), dut),
	)

	if deviations.ExplicitPortSpeed(dut) {
		fptest.SetPortSpeed(t, port)
	}

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, port.Name(), deviations.DefaultNetworkInstance(dut), subInterfaceIndex)
	}
}

func configureDUTStatic(
	t *testing.T,
	dut *ondatra.DUTDevice,
) {
	t.Helper()

	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
	gnmi.Delete(t, dut, staticPath.Config())

	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	networkInstanceProtocolStatic := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
	networkInstanceProtocolStatic.SetEnabled(true)

	ipv4StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("192.168.10.0/24")
	// TODO - we dont support, guessing table connection related?
	if dut.Vendor() != ondatra.NOKIA {
		ipv4StaticRoute.SetSetTag(oc.UnionString("40"))
	} else {
		configureStaticRouteTagSet(t, dut)
		attachTagSetToStaticRoute(t, dut, "192.168.10.0/24", "tag-static-v4")
	}

	ipv4StaticRouteNextHop := ipv4StaticRoute.GetOrCreateNextHop("0")
	ipv4StaticRouteNextHop.SetMetric(104)
	ipv4StaticRouteNextHop.SetNextHop(oc.UnionString("192.168.1.6"))

	ipv6StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("2024:db8:128:128::/64")
	if dut.Vendor() != ondatra.NOKIA {
		ipv6StaticRoute.SetSetTag(oc.UnionString("60"))
	} else {
		attachTagSetToStaticRoute(t, dut, "2024:db8:128:128::/64", "tag-static-v6")
	}

	ipv6StaticRouteNextHop := ipv6StaticRoute.GetOrCreateNextHop("0")
	ipv6StaticRouteNextHop.SetMetric(106)
	ipv6StaticRouteNextHop.SetNextHop(oc.UnionString("2001:DB8::6"))

	gnmi.Replace(t, dut, staticPath.Config(), networkInstanceProtocolStatic)
}

func configureDUTRoutingPolicy(
	t *testing.T,
	dut *ondatra.DUTDevice,
) {
	t.Helper()

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition("import-dut-port2-connected-subnet")

	dutOcRoot := &oc.Root{}
	connectedPolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	connectedPolicyDefinition := connectedPolicy.GetOrCreatePolicyDefinition("import-dut-port2-connected-subnet")

	// v4
	v4PrefixSet := connectedPolicy.GetOrCreateDefinedSets().GetOrCreatePrefixSet("fp-ipv4-prefix")
	v4PrefixSet.GetOrCreatePrefix("192.168.1.4/30", "30..32")

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSet("fp-ipv4-prefix").Config(), v4PrefixSet)

	ipv4PrefixPolicyStatement, err := connectedPolicyDefinition.AppendNewStatement("fp-ipv4-prefix")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatementConditionsPrefixes := ipv4PrefixPolicyStatement.GetOrCreateConditions().GetOrCreateMatchPrefixSet()
	ipv4PrefixPolicyStatementConditionsPrefixes.SetPrefixSet("fp-ipv4-prefix")

	// v6
	v6PrefixSet := connectedPolicy.GetOrCreateDefinedSets().GetOrCreatePrefixSet("fp-ipv6-prefix")
	v6PrefixSet.GetOrCreatePrefix("2001:db8::4/126", "126..128")

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSet("fp-ipv6-prefix").Config(), v6PrefixSet)

	ipv6PrefixPolicyStatement, err := connectedPolicyDefinition.AppendNewStatement("fp-ipv6-prefix")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv6PrefixPolicyStatementConditionsPrefixes := ipv6PrefixPolicyStatement.GetOrCreateConditions().GetOrCreateMatchPrefixSet()
	ipv6PrefixPolicyStatementConditionsPrefixes.SetPrefixSet("fp-ipv6-prefix")

	gnmi.Replace(t, dut, policyPath.Config(), connectedPolicyDefinition)
}

func configureDUTBGP(
	t *testing.T,
	dut *ondatra.DUTDevice,
) {
	t.Helper()

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")

	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	networkInstanceProtocolBgp := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := networkInstanceProtocolBgp.GetOrCreateBgp()

	bgpGlobal := bgp.GetOrCreateGlobal()
	bgpGlobal.RouterId = ygot.String(dutPort1.IPv4)
	bgpGlobal.As = ygot.Uint32(dutAsn)

	bgpGlobalIPv4AF := bgpGlobal.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	bgpGlobalIPv4AF.SetEnabled(true)

	bgpGlobalIPv6AF := bgpGlobal.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	bgpGlobalIPv6AF.SetEnabled(true)

	if dut.Vendor() != ondatra.NOKIA {
		bgpGlobalIPv6AF.SetSendCommunityType([]oc.E_Bgp_CommunityType{oc.Bgp_CommunityType_STANDARD})
		bgpGlobalIPv4AF.SetSendCommunityType([]oc.E_Bgp_CommunityType{oc.Bgp_CommunityType_STANDARD})
	}

	bgpPeerGroup := bgp.GetOrCreatePeerGroup(peerGroupName)
	bgpPeerGroup.SetPeerAs(dutAsn)

	// dutPort1 -> atePort1 peer (ebgp session)
	ateEBGPNeighborOne := bgp.GetOrCreateNeighbor(atePort1.IPv4)
	ateEBGPNeighborOne.PeerGroup = ygot.String(peerGroupName)
	ateEBGPNeighborOne.PeerAs = ygot.Uint32(atePeer1Asn)
	ateEBGPNeighborOne.Enabled = ygot.Bool(true)

	ateEBGPNeighborIPv4AF := ateEBGPNeighborOne.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	ateEBGPNeighborIPv4AF.SetEnabled(true)
	ateEBGPNeighborIPv4AFPolicy := ateEBGPNeighborIPv4AF.GetOrCreateApplyPolicy()
	ateEBGPNeighborIPv4AFPolicy.SetImportPolicy([]string{"import-dut-port2-connected-subnet"})
	ateEBGPNeighborIPv4AFPolicy.SetExportPolicy([]string{"import-dut-port2-connected-subnet"})

	ateEBGPNeighborTwo := bgp.GetOrCreateNeighbor(atePort1.IPv6)
	ateEBGPNeighborTwo.PeerGroup = ygot.String(peerGroupName)
	ateEBGPNeighborTwo.PeerAs = ygot.Uint32(atePeer1Asn)
	ateEBGPNeighborTwo.Enabled = ygot.Bool(true)
	ateEBGPNeighborIPv6AF := ateEBGPNeighborTwo.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	ateEBGPNeighborIPv6AF.SetEnabled(true)
	ateEBGPNeighborIPv6AFPolicy := ateEBGPNeighborIPv6AF.GetOrCreateApplyPolicy()
	ateEBGPNeighborIPv6AFPolicy.SetImportPolicy([]string{"import-dut-port2-connected-subnet"})
	ateEBGPNeighborIPv6AFPolicy.SetExportPolicy([]string{"import-dut-port2-connected-subnet"})

	// dutPort3 -> atePort3 peer (ibgp session)
	ateIBGPNeighborThree := bgp.GetOrCreateNeighbor(atePort3.IPv4)
	ateIBGPNeighborThree.PeerGroup = ygot.String(peerGroupName)
	ateIBGPNeighborThree.PeerAs = ygot.Uint32(atePeer2Asn)
	ateIBGPNeighborThree.Enabled = ygot.Bool(true)

	ateIBGPNeighborThreeIPv4AF := ateIBGPNeighborThree.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	ateIBGPNeighborThreeIPv4AF.SetEnabled(true)

	ateIBGPNeighborThreeIPv6AF := ateIBGPNeighborThree.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	ateIBGPNeighborThreeIPv6AF.SetEnabled(true)

	ateIBGPNeighborFour := bgp.GetOrCreateNeighbor(atePort3.IPv6)
	ateIBGPNeighborFour.PeerGroup = ygot.String(peerGroupName)
	ateIBGPNeighborFour.PeerAs = ygot.Uint32(atePeer2Asn)
	ateIBGPNeighborFour.Enabled = ygot.Bool(true)

	ateIBGPNeighborFourIPv4AF := ateIBGPNeighborFour.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	ateIBGPNeighborFourIPv4AF.SetEnabled(true)

	ateIBGPNeighborFourIPv6AF := ateIBGPNeighborFour.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	ateIBGPNeighborFourIPv6AF.SetEnabled(true)

	gnmi.Replace(t, dut, bgpPath.Config(), networkInstanceProtocolBgp)
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	for portName, portAttrs := range dutPorts {
		port := dut.Port(t, portName)
		configureDUTPort(t, dut, port, portAttrs)
	}

	configureDUTRoutingPolicy(t, dut)
	configureDUTStatic(t, dut)
	configureDUTBGP(t, dut)
}

func awaitBGPEstablished(t *testing.T, dut *ondatra.DUTDevice, neighbors []string) {
	for _, neighbor := range neighbors {
		gnmi.Await(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).
			Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").
			Bgp().
			Neighbor(neighbor).
			SessionState().State(), time.Second*120, oc.Bgp_Neighbor_SessionState_ESTABLISHED)
	}
}

func configureOTG(t *testing.T) gosnappi.Config {
	t.Helper()

	otgConfig := gosnappi.NewConfig()

	port1 := otgConfig.Ports().Add().SetName("port1")
	port2 := otgConfig.Ports().Add().SetName("port2")
	port3 := otgConfig.Ports().Add().SetName("port3")

	// Port3 Configuration.
	iDut3Dev := otgConfig.Devices().Add().SetName(atePort3.Name)
	iDut3Eth := iDut3Dev.Ethernets().Add().SetName(atePort3.Name + ".Eth").SetMac(atePort3.MAC)
	iDut3Eth.Connection().SetPortName(port3.Name())
	iDut3Ipv4 := iDut3Eth.Ipv4Addresses().Add().SetName(atePort3.Name + ".IPv4")
	iDut3Ipv4.SetAddress(atePort3.IPv4).SetGateway(dutPort3.IPv4).SetPrefix(uint32(atePort3.IPv4Len))
	iDut3Ipv6 := iDut3Eth.Ipv6Addresses().Add().SetName(atePort3.Name + ".IPv6")
	iDut3Ipv6.SetAddress(atePort3.IPv6).SetGateway(dutPort3.IPv6).SetPrefix(uint32(atePort3.IPv6Len))

	// Port1 Configuration.
	iDut1Dev := otgConfig.Devices().Add().SetName(atePort1.Name)
	iDut1Eth := iDut1Dev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	iDut1Eth.Connection().SetPortName(port1.Name())
	iDut1Ipv4 := iDut1Eth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	iDut1Ipv4.SetAddress(atePort1.IPv4).SetGateway(dutPort1.IPv4).SetPrefix(uint32(atePort1.IPv4Len))
	iDut1Ipv6 := iDut1Eth.Ipv6Addresses().Add().SetName(atePort1.Name + ".IPv6")
	iDut1Ipv6.SetAddress(atePort1.IPv6).SetGateway(dutPort1.IPv6).SetPrefix(uint32(atePort1.IPv6Len))

	// Port2 Configuration.
	iDut2Dev := otgConfig.Devices().Add().SetName(atePort2.Name)
	iDut2Eth := iDut2Dev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	iDut2Eth.Connection().SetPortName(port2.Name())
	iDut2Ipv4 := iDut2Eth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	iDut2Ipv4.SetAddress(atePort2.IPv4).SetGateway(dutPort2.IPv4).SetPrefix(uint32(atePort2.IPv4Len))
	iDut2Ipv6 := iDut2Eth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	iDut2Ipv6.SetAddress(atePort2.IPv6).SetGateway(dutPort2.IPv6).SetPrefix(uint32(atePort2.IPv6Len))
	// TODO -- seems like we are supposed to add loopbacks here for 192.168.10.0/24 and 192.168.20.0/24
	//  and the ipv6 subnets but dunno if its actually necessary yet since we are just having routes
	//  set as static on the dut then adv into bgp so dont think we really need them on ate for any
	//  reason

	// eBGP v4 session on Port1.
	iDut1Bgp := iDut1Dev.Bgp().SetRouterId(iDut1Ipv4.Address())
	iDut1Bgp4Peer := iDut1Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut1Ipv4.Name()).Peers().Add().SetName(atePort1.Name + ".BGP4.peer")
	iDut1Bgp4Peer.SetPeerAddress(iDut1Ipv4.Gateway()).SetAsNumber(atePeer1Asn).SetAsType(gosnappi.BgpV4PeerAsType.EBGP)
	iDut1Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(false)
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	// eBGP v6 session on Port1.
	iDut1Bgp6Peer := iDut1Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut1Ipv6.Name()).Peers().Add().SetName(atePort1.Name + ".BGP6.peer")
	iDut1Bgp6Peer.SetPeerAddress(iDut1Ipv6.Gateway()).SetAsNumber(atePeer1Asn).SetAsType(gosnappi.BgpV6PeerAsType.EBGP)
	iDut1Bgp6Peer.Capability().SetIpv4UnicastAddPath(false).SetIpv6UnicastAddPath(true)
	iDut1Bgp6Peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	// iBGP v4 session on Port3.
	iDut3Bgp := iDut3Dev.Bgp().SetRouterId(iDut3Ipv4.Address())
	iDut3Bgp4Peer := iDut3Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut3Ipv4.Name()).Peers().Add().SetName(atePort3.Name + ".BGP4.peer")
	iDut3Bgp4Peer.SetPeerAddress(iDut3Ipv4.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
	iDut3Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(false)
	iDut3Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	// iBGP v6 session on Port3.
	iDut3Bgp6Peer := iDut3Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut3Ipv6.Name()).Peers().Add().SetName(atePort3.Name + ".BGP6.peer")
	iDut3Bgp6Peer.SetPeerAddress(iDut3Ipv6.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV6PeerAsType.IBGP)
	iDut3Bgp6Peer.Capability().SetIpv4UnicastAddPath(false).SetIpv6UnicastAddPath(true)
	iDut3Bgp6Peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	return otgConfig
}

// Configure OTG traffic-flow
func configureTrafficFlow(t *testing.T, otgConfig gosnappi.Config, isV4 bool, name, flowSrcEndPoint, flowDstEndPoint, srcMac, srcIp, dstIp string) gosnappi.Config {
	t.Helper()

	// ATE Traffic Configuration.
	t.Logf("TestBGP:start ate Traffic config: %v", name)

	otgConfig.Flows().Clear()

	flow := otgConfig.Flows().Add().SetName(name)
	flow.Metrics().SetEnable(true)
	flow.TxRx().Device().
		SetTxNames([]string{flowSrcEndPoint}).
		SetRxNames([]string{flowDstEndPoint})
	flow.Size().SetFixed(1500)
	flow.Duration().FixedPackets().SetPackets(1000)
	e := flow.Packet().Add().Ethernet()
	e.Src().SetValue(srcMac)
	if isV4 {
		v4 := flow.Packet().Add().Ipv4()
		v4.Src().SetValue(srcIp)
		v4.Dst().SetValue(dstIp)
	} else {
		v6 := flow.Packet().Add().Ipv6()
		v6.Src().SetValue(srcIp)
		v6.Dst().SetValue(dstIp)
	}

	return otgConfig
}

// Sending traffic over configured flow for fixed duration
func sendTraffic(t *testing.T, otg *otg.OTG) {
	t.Logf("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)
}

// Validate traffic flow
func verifyTraffic(t *testing.T, ate *ondatra.ATEDevice, conf gosnappi.Config) {
	otg := ate.OTG()
	otgutils.LogFlowMetrics(t, otg, conf)
	for _, flow := range conf.Flows().Items() {
		recvMetric := gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).State())
		txPackets := float32(recvMetric.GetCounters().GetOutPkts())
		rxPackets := float32(recvMetric.GetCounters().GetInPkts())
		if txPackets == 0 {
			t.Fatalf("TxPkts = 0, want > 0")
		}
		lostPackets := txPackets - rxPackets
		lossPct := lostPackets * 100 / txPackets
		if lossPct > tolerancePct {
			t.Errorf("Traffic Loss Pct for Flow %s: got %v, want max %v pct failure", flow.Name(), lossPct, tolerancePct)
		} else {
			t.Logf("Traffic Test Passed! for flow %s", flow.Name())
		}
	}
}

// Configure table-connection with source as static-route and destination as bgp
func configureTableConnection(t *testing.T, dut *ondatra.DUTDevice, isV4, mPropagation bool, importPolicy string, defaultImport oc.E_RoutingPolicy_DefaultPolicyType) {

	t.Helper()

	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	addressFamily := oc.Types_ADDRESS_FAMILY_IPV4
	if !isV4 {
		addressFamily = oc.Types_ADDRESS_FAMILY_IPV6
	}

	tc := networkInstance.GetOrCreateTableConnection(
		oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
		oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
		addressFamily,
	)

	tc.SetDefaultImportPolicy(defaultImport)
	if importPolicy != "" {
		tc.SetImportPolicy([]string{importPolicy})
	}
	tc.SetDisableMetricPropagation(!mPropagation)
	gnmi.Update(t, dut, niPath.Config(), networkInstance)
}

// Populate routing-policy to redistribute static-route
func redistributeStaticRoute(t *testing.T, isV4 bool, mPropagation, policyResultNext bool, routingPolicy *oc.RoutingPolicy) *oc.RoutingPolicy {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := "redistribute-static"
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
	}

	apolicy := routingPolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)
	astmt, err := apolicy.AppendNewStatement(policyStatement)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}
	astmt.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
	astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
	if policyResultNext {
		astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_NEXT_STATEMENT
	}
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(medZero))
	if mPropagation {
		astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP))
	}

	return routingPolicy
}

// Configure routing-policy to redistribute static-route
func configureStaticRedistributionPolicy(t *testing.T, dut *ondatra.DUTDevice, isV4, acceptRoute, mPropagation bool) {

	t.Helper()

	dutOcRoot := &oc.Root{}
	rp := dutOcRoot.GetOrCreateRoutingPolicy()
	rp = redistributeStaticRoute(t, isV4, mPropagation, !policyResultNext, rp)

	redistributeStaticPolicy := redistributeStaticPolicyV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	astmt := rp.GetPolicyDefinition(redistributeStaticPolicy).GetStatement("redistribute-static")
	astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_REJECT_ROUTE
	if acceptRoute {
		astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
	}

	rpConfPath := gnmi.OC().RoutingPolicy()
	gnmi.Replace(t, dut, rpConfPath.PolicyDefinition(redistributeStaticPolicy).Config(), rp.GetOrCreatePolicyDefinition(redistributeStaticPolicy))
	gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
}

// Validate configurations for table-connections and routing-policy
func validateRedistributeStatic(t *testing.T, dut *ondatra.DUTDevice, acceptRoute, isV4, mPropagation bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := "redistribute-static"
	af := oc.Types_ADDRESS_FAMILY_IPV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy().State()
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		af = oc.Types_ADDRESS_FAMILY_IPV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy().State()
	}

	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			af).State())

		if tcState.GetSrcProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC {
			t.Fatal("source protocol not static for table connection but should be")
		}

		if tcState.GetDstProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP {
			t.Fatal("destination protocol not bgp for table connection but should be")
		}

		if tcState.GetAddressFamily() != af {
			t.Fatal("address family not as expected or table connection but should be")
		}

		if !mPropagation {
			if tcState.GetDisableMetricPropagation() {
				t.Fatal("Metric propagation disabled for table connection, expected enabled")
			}
		} else {
			if !tcState.GetDisableMetricPropagation() {
				t.Fatal("Metric propagation is enabled for table connection, expected disabled")
			}
		}

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicy {
				found = true
			}
		}

		if !found {
			t.Fatal("Expected import policy is not configured")
		}

		if acceptRoute {
			if tcState.GetDefaultImportPolicy() != oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE {
				t.Fatal("default import policy is not accept route but it should be")
			}
		} else {
			if tcState.GetDefaultImportPolicy() != oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE {
				t.Fatal("default import policy is not reject route but it should be")
			}
		}
	} else {
		var foundPDef oc.RoutingPolicy_PolicyDefinition
		policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
		for _, pDef := range policyDef {
			if pDef.GetName() == redistributeStaticPolicy {
				foundPDef = *pDef
			}
		}

		if foundPDef.GetName() != redistributeStaticPolicy {
			t.Fatal("Expected import policy is not configured")
		}

		if foundPDef.GetStatement(policyStatement).GetOrCreateConditions().GetInstallProtocolEq() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC {
			t.Fatal("Source protocol not static for redistribution policy.Expected static protocol")
		}

		if mPropagation {
			if foundPDef.GetStatement(policyStatement).GetActions().GetBgpActions().GetSetMed() != oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP) {
				t.Fatal("Expected metric propagation is not configured")
			}
		}

		found := false
		bgpPolicy := gnmi.Get(t, dut, bgpPath)
		for _, exPol := range bgpPolicy {
			if exPol == redistributeStaticPolicy {
				found = true
				t.Logf("bgp associated with routing-policy: %v", exPol)
			}
		}
		if !found {
			t.Fatal("BGP not associated with expected policy")
		}
	}
}

// Validate prefix-set routing-policy configurations
func validatePrefixSetRoutingPolicy(t *testing.T, dut *ondatra.DUTDevice, isV4 bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatementName := policyStatementV4
	prefixSetName := "prefix-set-v4"
	prefixSetMode := oc.PrefixSet_Mode_IPV4
	prefixAddress := "192.168.10.0/24"
	prefixMaskLen := "exact"
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatementName = policyStatementV6
		prefixSetName = "prefix-set-v6"
		prefixSetMode = oc.PrefixSet_Mode_IPV6
		prefixAddress = "2024:db8:128:128::/64"
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicy {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicy {
		t.Fatal("Expected import policy is not configured")
	}

	if foundPDef.GetStatement(policyStatementName).GetActions().GetPolicyResult() != oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE {
		t.Fatalf("Routing-policy result unexpectd for statement %v. It is not set to ACCEPT_ROUTE.", policyStatementName)
	}

	if foundPDef.GetStatement(policyStatementName).GetConditions().GetMatchPrefixSet().GetPrefixSet() != prefixSetName {
		t.Fatal("Routing-policy not associated with expected prefix-set")
	}

	if !deviations.SkipSetRpMatchSetOptions(dut) {
		if foundPDef.GetStatement(policyStatementName).GetConditions().GetMatchPrefixSet().GetMatchSetOptions() != oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY {
			t.Fatal("Routing-policy prefix-set match-set-option not set to ANY")
		}
	}

	var foundPSet oc.RoutingPolicy_DefinedSets_PrefixSet
	prefixSet := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSetAny().State())
	for _, pSet := range prefixSet {
		if pSet.GetName() == prefixSetName {
			foundPSet = *pSet
		}
	}

	if foundPSet.GetName() != prefixSetName {
		t.Fatal("Expected prefix-set is not configured")
	}

	if !deviations.SkipPrefixSetMode(dut) {
		if foundPSet.GetMode() != prefixSetMode {
			t.Fatal("Expected prefix-set mode is not configured")
		}
	}

	if foundPSet.GetPrefix(prefixAddress, prefixMaskLen).GetIpPrefix() != prefixAddress {
		t.Fatal("Expected prefix not configured in prefix-set")
	}
}

// 1.27.1 setup function
func redistributeIPv4Static(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, !metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, acceptRoute, !metricPropagate)
	}
}

// 1.27.1 validation function
func validateRedistributeIPv4Static(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, isV4, !metricPropagate)
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, true)
}

// 1.27.2 setup function
func redistributeIPv4StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, acceptRoute, metricPropagate)
	}
}

// 1.27.2 validation function
func validateRedistributeIPv4StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, isV4, metricPropagate)
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 104, true)
}

// 1.27.3 setup function
func redistributeIPv6Static(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, !metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		configureStaticRedistributionPolicy(t, dut, !isV4, acceptRoute, !metricPropagate)
	}
}

// 1.27.3 validation function
func validateRedistributeIPv6Static(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, !isV4, !metricPropagate)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, true)
}

// 1.27.4 setup function
func redistributeIPv6StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		configureStaticRedistributionPolicy(t, dut, !isV4, acceptRoute, metricPropagate)
	}
}

// 1.27.4 validation function
func validateRedistributeIPv6StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, !isV4, metricPropagate)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 106, true)
}

// 1.27.5 setup function
func redistributeIPv4IPv6StaticDefaultRejectPolicy(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, !metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE)
		configureTableConnection(t, dut, !isV4, !metricPropagate, "", oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE)
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, !acceptRoute, !metricPropagate)
		configureStaticRedistributionPolicy(t, dut, !isV4, !acceptRoute, !metricPropagate)
	}
}

// 1.27.5 validation function
func validateRedistributeIPv4IPv6DefaultRejectPolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, !acceptRoute, isV4, !metricPropagate)
	validateRedistributeStatic(t, dut, !acceptRoute, !isV4, !metricPropagate)
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, false)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, false)
}

// 1.27.6 setup function
func redistributeIPv4PrefixRoutePolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)

	otgConfig := configureOTG(t)
	otgConfig = configureTrafficFlow(t, otgConfig, isV4, "StaticRoutesV4Flow", atePort1.Name+".IPv4", atePort2.Name+".IPv4", atePort1.MAC, atePort1.IPv4, "192.168.10.0")
	ate.OTG().PushConfig(t, otgConfig)
	ate.OTG().StartProtocols(t)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	v4PrefixSet := redistributePolicy.GetOrCreateDefinedSets().GetOrCreatePrefixSet("prefix-set-v4")
	v4PrefixSet.GetOrCreatePrefix("192.168.10.0/24", "exact")
	if !deviations.SkipPrefixSetMode(dut) {
		v4PrefixSet.SetMode(oc.PrefixSet_Mode_IPV4)
	}

	v4PrefixSet.GetOrCreatePrefix("192.168.20.0/24", "exact")
	if !deviations.SkipPrefixSetMode(dut) {
		v4PrefixSet.SetMode(oc.PrefixSet_Mode_IPV4)
	}

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSet("prefix-set-v4").Config(), v4PrefixSet)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)

	ipv4PrefixPolicyStatementConditionsPrefixes := ipv4PrefixPolicyStatement.GetOrCreateConditions().GetOrCreateMatchPrefixSet()
	ipv4PrefixPolicyStatementConditionsPrefixes.SetPrefixSet("prefix-set-v4")
	if !deviations.SkipSetRpMatchSetOptions(dut) {
		ipv4PrefixPolicyStatementConditionsPrefixes.SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)
	}

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}

	sendTraffic(t, ate.OTG())
	verifyTraffic(t, ate, otgConfig)
}

// 1.27.6 validation function
func validateRedistributeIPv4PrefixRoutePolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, isV4, metricPropagate)
	validatePrefixSetRoutingPolicy(t, dut, isV4)
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 104, true)
}

// 1.27.7 and 1.27.16 setup function
func redistributeStaticRoutePolicyWithASN(t *testing.T, dut *ondatra.DUTDevice, isV4 bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()

	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)
	prefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatement)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	prefixPolicyStatementAction := prefixPolicyStatement.GetOrCreateActions()
	prefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	prefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().Asn = ygot.Uint32(64512)
	if isV4 {
		prefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().Asn = ygot.Uint32(65499)
		prefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().SetRepeatN(3)
	}

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicy, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	}
}

// 1.27.8 and 1.27.17 setup function
func redistributeStaticRoutePolicyWithMED(t *testing.T, dut *ondatra.DUTDevice, isV4 bool, medValue uint32) {
	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()

	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	prefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatement)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	prefixPolicyStatementAction := prefixPolicyStatement.GetOrCreateActions()
	prefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	prefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(medValue))

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicy, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	}
}

// 1.27.9 and 1.27.18 setup function
func redistributeStaticRoutePolicyWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice, isV4 bool, localPreferenceValue uint32) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()

	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	prefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatement)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	prefixPolicyStatementAction := prefixPolicyStatement.GetOrCreateActions()
	prefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	prefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(localPreferenceValue)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicy, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	}
}

// 1.27.10 and 1.27.19 setup function
func redistributeStaticRoutePolicyWithCommunitySet(t *testing.T, dut *ondatra.DUTDevice, isV4 bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	communitySetName := "community-set-v4"
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()

	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
		communitySetName = "community-set-v6"
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)
	communityPath := gnmi.OC().RoutingPolicy().DefinedSets().BgpDefinedSets().CommunitySet(communitySetName)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	communitySet := dutOcRoot.GetOrCreateRoutingPolicy()
	communitySetPolicyDefinition := communitySet.GetOrCreateDefinedSets().GetOrCreateBgpDefinedSets().GetOrCreateCommunitySet(communitySetName)
	communitySetPolicyDefinition.SetCommunityMember([]oc.RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySet_CommunityMember_Union{oc.UnionString("64512:100")})

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
	gnmi.Replace(t, dut, communityPath.Config(), communitySetPolicyDefinition)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	prefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatement)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	prefixPolicyStatementAction := prefixPolicyStatement.GetOrCreateActions()
	prefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	prefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().SetOptions(oc.BgpPolicy_BgpSetCommunityOptionType_ADD)
	prefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().GetOrCreateReference().SetCommunitySetRef(communitySetName)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicy, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	}
}

// 1.27.12, 1.27.13, 1.27.20 and 1.27.21 setup function
func redistributeStaticRoutePolicyWithTagSet(t *testing.T, dut *ondatra.DUTDevice, isV4 bool, tagSetValue uint32) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	tagSetName := "tag-set-v4"
	policyStatement := policyStatementV4
	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		tagSetName = "tag-set-v6"
		policyStatement = policyStatementV6
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)
	tagSetPath := gnmi.OC().RoutingPolicy().DefinedSets().TagSet(tagSetName)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, !metricPropagate, policyResultNext, redistributePolicy)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
		configureRoutingPolicyTagSet(t, dut, isV4, tagSetValue)
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	} else {
		tagSet := dutOcRoot.GetOrCreateRoutingPolicy()
		tagSetPolicyDefinition := tagSet.GetOrCreateDefinedSets().GetOrCreateTagSet(tagSetName)
		tagSetPolicyDefinition.SetTagValue([]oc.RoutingPolicy_DefinedSets_TagSet_TagValue_Union{oc.UnionString(fmt.Sprintf("%v", tagSetValue))})
		gnmi.Replace(t, dut, tagSetPath.Config(), tagSetPolicyDefinition)

		prefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatement)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}

		prefixPolicyStatementCondition := prefixPolicyStatement.GetOrCreateConditions()
		if !deviations.SkipSetRpMatchSetOptions(dut) {
			prefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)
		}
		prefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetTagSet(tagSetName)
		prefixPolicyStatementAction := prefixPolicyStatement.GetOrCreateActions()
		prefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		configureTableConnection(t, dut, isV4, !metricPropagate, redistributeStaticPolicy, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	}
}

// 1.27.14 setup function
func redistributeIPv4NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)
	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")

	otgConfig := configureOTG(t)
	otgConfig = configureTrafficFlow(t, otgConfig, isV4, "StaticDropRoutesV4Flow", atePort3.Name+".IPv4", atePort2.Name+".IPv4", atePort3.MAC, atePort3.IPv4, "192.168.20.0")
	ate.OTG().PushConfig(t, otgConfig)
	ate.OTG().StartProtocols(t)

	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	networkInstanceProtocolStatic := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
	networkInstanceProtocolStatic.SetEnabled(true)
	ipv4StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("192.168.20.0/24")
	if dut.Vendor() != ondatra.NOKIA {
		ipv4StaticRoute.SetSetTag(oc.UnionString("40"))
	} else {
		configureStaticRouteTagSet(t, dut)
		attachTagSetToStaticRoute(t, dut, "192.168.20.0/24", "tag-static-v4")
	}
	ipv4StaticRouteNextHop := ipv4StaticRoute.GetOrCreateNextHop("0")
	ipv4StaticRouteNextHop.SetNextHop(oc.LocalRouting_LOCAL_DEFINED_NEXT_HOP_DROP)
	gnmi.Update(t, dut, staticPath.Config(), networkInstanceProtocolStatic)

	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, isV4, !metricPropagate, policyResultNext, redistributePolicy)

		statementV4, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		statementV4.GetOrCreateActions().GetOrCreateBgpActions().SetSetNextHop(oc.UnionString("192.168.1.9"))
		statementV4.GetOrCreateActions().SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	} else {
		ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}

		ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
		ipv4PrefixPolicyStatementAction.GetOrCreateBgpActions().SetSetNextHop(oc.UnionString("192.168.1.9"))
		ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		configureTableConnection(t, dut, isV4, !metricPropagate, redistributeStaticPolicyV4, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	}

	// Sending traffic to network via dut having static-route to drop it.
	// Traffic must be dropped by the dut irrespective of the bgp advertised-route
	// having updated next-hop, considering existing static-route is preferred over bgp.
	// Commenting traffic validation for now
	/*
		sendTraffic(t, ate.OTG())
		verifyTraffic(t, ate, otgConfig)
	*/
}

// 1.27.22 setup function
func redistributeIPv6NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)
	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")

	otgConfig := configureOTG(t)
	otgConfig = configureTrafficFlow(t, otgConfig, !isV4, "StaticDropRoutesV6Flow", atePort3.Name+".IPv6", atePort2.Name+".IPv6", atePort3.MAC, atePort3.IPv6, "2024:db8:64:64::")
	ate.OTG().PushConfig(t, otgConfig)
	ate.OTG().StartProtocols(t)

	dutOcRoot := &oc.Root{}

	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	networkInstanceProtocolStatic := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
	networkInstanceProtocolStatic.SetEnabled(true)
	ipv6StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("2024:db8:64:64::/64")
	if dut.Vendor() != ondatra.NOKIA {
		ipv6StaticRoute.SetSetTag(oc.UnionString("60"))
	} else {
		configureStaticRouteTagSet(t, dut)
		attachTagSetToStaticRoute(t, dut, "2024:db8:64:64::/64", "tag-static-v6")
	}
	ipv6StaticRouteNextHop := ipv6StaticRoute.GetOrCreateNextHop("0")
	ipv6StaticRouteNextHop.SetNextHop(oc.LocalRouting_LOCAL_DEFINED_NEXT_HOP_DROP)
	gnmi.Update(t, dut, staticPath.Config(), networkInstanceProtocolStatic)

	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, !isV4, !metricPropagate, policyResultNext, redistributePolicy)

		statementV6, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		statementV6.GetOrCreateActions().GetOrCreateBgpActions().SetSetNextHop(oc.UnionString("2001:DB8::9"))
		statementV6.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE

		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	} else {
		ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}

		ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
		ipv6PrefixPolicyStatementAction.GetOrCreateBgpActions().SetSetNextHop(oc.UnionString("2001:DB8::9"))
		ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		configureTableConnection(t, dut, !isV4, !metricPropagate, redistributeStaticPolicyV6, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	}

	// Sending traffic to network via dut having static-route to drop it.
	// Traffic must be dropped by the dut irrespective of the bgp advertised-route
	// having updated next-hop, considering existing static-route is preferred over bgp.
	// Commenting traffic validation for now
	/*
		sendTraffic(t, ate.OTG())
		verifyTraffic(t, ate, otgConfig)
	*/
}

// 1.27.15 setup function
func redistributeIPv6StaticRoutePolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)

	otgConfig := configureOTG(t)
	otgConfig = configureTrafficFlow(t, otgConfig, !isV4, "StaticRoutesV6Flow", atePort1.Name+".IPv6", atePort2.Name+".IPv6", atePort1.MAC, atePort1.IPv6, "2024:db8:128:128::")
	ate.OTG().PushConfig(t, otgConfig)
	ate.OTG().StartProtocols(t)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	v6PrefixSet := redistributePolicy.GetOrCreateDefinedSets().GetOrCreatePrefixSet("prefix-set-v6")
	v6PrefixSet.GetOrCreatePrefix("2024:db8:128:128::/64", "exact")
	if !deviations.SkipPrefixSetMode(dut) {
		v6PrefixSet.SetMode(oc.PrefixSet_Mode_IPV6)
	}

	v6PrefixSet.GetOrCreatePrefix("2024:db8:64:64::/64", "exact")
	if !deviations.SkipPrefixSetMode(dut) {
		v6PrefixSet.SetMode(oc.PrefixSet_Mode_IPV6)
	}

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSet("prefix-set-v6").Config(), v6PrefixSet)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRoute(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)

	ipv6PrefixPolicyStatementConditionsPrefixes := ipv6PrefixPolicyStatement.GetOrCreateConditions().GetOrCreateMatchPrefixSet()
	ipv6PrefixPolicyStatementConditionsPrefixes.SetPrefixSet("prefix-set-v6")
	if !deviations.SkipSetRpMatchSetOptions(dut) {
		ipv6PrefixPolicyStatementConditionsPrefixes.SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)
	}

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6, oc.RoutingPolicy_DefaultPolicyType_ACCEPT_ROUTE)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}

	sendTraffic(t, ate.OTG())
	verifyTraffic(t, ate, otgConfig)
}

// 1.27.15 validation function
func validateRedistributeIPv6RoutePolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeStatic(t, dut, acceptRoute, !isV4, metricPropagate)
	validatePrefixSetRoutingPolicy(t, dut, !isV4)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 106, true)
}

// 1.27.7 and 1.27.16 validation function
func validatePrefixASN(t *testing.T, ate *ondatra.ATEDevice, isV4 bool, bgpPeerName, subnet string, wantASPath []uint32) {

	time.Sleep(5 * time.Second)
	foundPrefix := false
	if isV4 {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				gotASPath := prefix.AsPath[len(prefix.AsPath)-1].GetAsNumbers()
				t.Logf("Prefix %v learned with ASN : %v", prefix.GetAddress(), gotASPath)
				if !reflect.DeepEqual(gotASPath, wantASPath) {
					t.Fatalf("Prefix %v with unexpected ASN : %v, expected: %v", prefix.GetAddress(), gotASPath, wantASPath)
				}
			}
		}
	} else {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				gotASPath := prefix.AsPath[len(prefix.AsPath)-1].GetAsNumbers()
				t.Logf("Prefix %v learned with ASN : %v", prefix.GetAddress(), gotASPath)
				if !reflect.DeepEqual(gotASPath, wantASPath) {
					t.Fatalf("Prefix %v with unexpected ASN : %v, expected: %v", prefix.GetAddress(), gotASPath, wantASPath)
				}
			}
		}
	}
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}
}

// 1.27.9 and 1.27.18 validation function
func validatePrefixLocalPreference(t *testing.T, ate *ondatra.ATEDevice, isV4 bool, bgpPeerName, subnet string, wantLocalPreference uint32) {
	time.Sleep(10 * time.Second)
	foundPrefix := false
	if isV4 {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				gotLocalPreference := prefix.GetLocalPreference()
				t.Logf("LC: Prefix %v learned with localPreference : %v", prefix.GetAddress(), gotLocalPreference)
				if gotLocalPreference != wantLocalPreference {
					t.Fatalf("Prefix %v with unexpected local-preference : %v, expected: %v", subnet, gotLocalPreference, wantLocalPreference)
				}
			}
		}
	} else {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				gotLocalPreference := prefix.GetLocalPreference()
				t.Logf("LC: Prefix %v learned with localPreference : %v", prefix.GetAddress(), gotLocalPreference)
				if gotLocalPreference != wantLocalPreference {
					t.Fatalf("Prefix %v with unexpected local-preference : %v, expected: %v", subnet, gotLocalPreference, wantLocalPreference)
				}
			}
		}
	}
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}
}

// 1.27.10 and 1.27.19 validation function
func validatePrefixCommunitySet(t *testing.T, ate *ondatra.ATEDevice, isV4 bool, bgpPeerName, subnet, wantCommunitySet string) {
	time.Sleep(5 * time.Second)
	foundPrefix := false

	if isV4 {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				var gotCommunitySet string
				for _, community := range prefix.Community {
					gotCommunityNumber := community.GetCustomAsNumber()
					gotCommunityValue := community.GetCustomAsValue()
					gotCommunitySet = fmt.Sprint(gotCommunityNumber) + ":" + fmt.Sprint(gotCommunityValue)
				}
				t.Logf("LC: Prefix %v learned with CommunitySet : %v", prefix.GetAddress(), gotCommunitySet)
				if gotCommunitySet != wantCommunitySet {
					t.Fatalf("Prefix learnt with unexpected Community: %v, expected: %v", gotCommunitySet, wantCommunitySet)
				}
			}
		}
	} else {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				foundPrefix = true
				var gotCommunitySet string
				for _, community := range prefix.Community {
					gotCommunityNumber := community.GetCustomAsNumber()
					gotCommunityValue := community.GetCustomAsValue()
					gotCommunitySet = fmt.Sprint(gotCommunityNumber) + ":" + fmt.Sprint(gotCommunityValue)
				}
				t.Logf("LC: Prefix %v learned with CommunitySet : %v", prefix.GetAddress(), gotCommunitySet)
				if gotCommunitySet != wantCommunitySet {
					t.Fatalf("Prefix learnt with unexpected Community: %v, expected: %v", gotCommunitySet, wantCommunitySet)
				}
			}
		}
	}

	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}
}

// 1.27.12, 1.27.13, 1.27.20 and 1.27.21 validation function
func validateRedistributeRouteWithTagSet(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, isV4, shouldBePresent bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	af := oc.Types_ADDRESS_FAMILY_IPV4
	tagSet := "tag-set-v4"
	policyStatement := policyStatementV4
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		af = oc.Types_ADDRESS_FAMILY_IPV6
		tagSet = "tag-set-v6"
		policyStatement = policyStatementV6
	}

	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			af).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicy {
				found = true
			}
		}

		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicy {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicy {
		t.Fatal("Expected import policy is not configured")
	}
	if dut.Vendor() != ondatra.NOKIA {
		if foundPDef.GetStatement(policyStatement).GetConditions().GetOrCreateMatchTagSet().GetTagSet() != tagSet {
			t.Fatal("Expected tag-set is not configured")
		}
		if foundPDef.GetStatement(policyStatement).GetConditions().GetOrCreateMatchTagSet().GetMatchSetOptions() != oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY {
			t.Fatal("Expected match-set-option for tag-set is not configured")
		}
	}

	if isV4 {
		validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, shouldBePresent)
	} else {
		validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, shouldBePresent)
	}
}

// 1.27.14 and 1.27.22 validation function
func validateRedistributeNullStaticRoute(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, isV4 bool) {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	addressFamily := oc.Types_ADDRESS_FAMILY_IPV4
	nextHop := "192.168.1.9"
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
		addressFamily = oc.Types_ADDRESS_FAMILY_IPV6
		nextHop = "2001:db8::9"
	}

	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			addressFamily).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicy {
				found = true
			}
		}

		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicy {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicy {
		t.Fatal("Expected import policy is not configured")
	}

	if foundPDef.GetStatement(policyStatement).GetActions().GetBgpActions().GetSetNextHop() != oc.UnionString(nextHop) {
		t.Fatal("Expected next-hop is not configured")
	}

	if isV4 {
		validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.20.0", 0, shouldBePresent)
	} else {
		validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:64:64::", 0, shouldBePresent)
	}
}

// Used by multiple IPv4 test validations for route presence and MED value
func validateLearnedIPv4Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {
	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv4Prefix
	time.Sleep(5 * time.Second)

	_, ok := gnmi.WatchAll(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv4Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	found := false
	if ok {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
				found = true
				t.Logf("Learnt prefix in otg : %v with next-hop %v", prefix.GetAddress(), prefix.GetNextHopIpv4Address())
				if !shouldBePresent {
					t.Fatal("Redistributed IPv4 prefix present in otg but should not be")
				}
			}
		}
	}

	if shouldBePresent && !ok && !found {
		t.Fatal("Did not see redistributed IPv4 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	t.Logf("Got MED %v", actualMED)
	if actualMED != expectedMED {
		t.Fatalf("ate learned redistributed prefix with med set to %d, expected %d", actualMED, expectedMED)
	}
}

// Used by multiple IPv6 test validations for route presence and MED value
func validateLearnedIPv6Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {

	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv6Prefix
	time.Sleep(5 * time.Second)

	_, ok := gnmi.WatchAll(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv6Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	found := false
	if ok {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
				found = true
				t.Logf("Learnt IPv6 prefix in otg : %v with next-hop %v", prefix.GetAddress(), prefix.GetNextHopIpv6Address())
				if !shouldBePresent {
					t.Fatal("Redistributed IPv6 prefix present in otg but should not be")
				}
			}
		}
	}

	if shouldBePresent && !ok && !found {
		t.Fatal("Did not see redistributed IPv6 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	t.Logf("Got MED %v", actualMED)
	if actualMED != expectedMED {
		t.Fatalf("ate learned redistributed prefix %v with med set to %d, expected %d", subnet, actualMED, expectedMED)
	}
}

func TestBGPStaticRouteRedistribution(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	configureDUT(t, dut)
	otgConfig := configureOTG(t)
	otg.PushConfig(t, otgConfig)
	otg.StartProtocols(t)

	awaitBGPEstablished(t, dut, []string{atePort1.IPv4, atePort3.IPv4})

	type testCase struct {
		name     string
		setup    func()
		validate func()
	}

	testCases := []testCase{
		// 1.27.1
		{
			name:     "1.27.1 redistribute-ipv4-static-routes-with-metric-propagation-disabled",
			setup:    func() { redistributeIPv4Static(t, dut) },
			validate: func() { validateRedistributeIPv4Static(t, dut, ate) },
		},
		// 1.27.2
		{
			name:     "1.27.2 redistribute-ipv4-static-routes-with-metric-propagation-enabled",
			setup:    func() { redistributeIPv4StaticWithMetricPropagation(t, dut) },
			validate: func() { validateRedistributeIPv4StaticWithMetricPropagation(t, dut, ate) },
		},
		// 1.27.3
		{
			name:     "1.27.3 redistribute-ipv6-static-routes-with-metric-propagation-disabled",
			setup:    func() { redistributeIPv6Static(t, dut) },
			validate: func() { validateRedistributeIPv6Static(t, dut, ate) },
		},
		// 1.27.4
		{
			name:     "1.27.4 redistribute-ipv6-static-routes-with-metric-propagation-enabled",
			setup:    func() { redistributeIPv6StaticWithMetricPropagation(t, dut) },
			validate: func() { validateRedistributeIPv6StaticWithMetricPropagation(t, dut, ate) },
		},
		// 1.27.5
		{
			name:     "1.27.5 redistribute-ipv4-ipv6-default-reject-policy",
			setup:    func() { redistributeIPv4IPv6StaticDefaultRejectPolicy(t, dut) },
			validate: func() { validateRedistributeIPv4IPv6DefaultRejectPolicy(t, dut, ate) },
		},
		// 1.27.6
		{
			name:     "1.27.6 redistribute-ipv4-prefix-route-policy",
			setup:    func() { redistributeIPv4PrefixRoutePolicy(t, dut, ate) },
			validate: func() { validateRedistributeIPv4PrefixRoutePolicy(t, dut, ate) },
		},
		// 1.27.7
		{
			name:  "1.27.7 redistribute-ipv4-route-policy-as-prepend",
			setup: func() { redistributeStaticRoutePolicyWithASN(t, dut, isV4) },
			validate: func() {
				validatePrefixASN(t, ate, isV4, atePort1.Name+".BGP4.peer", "192.168.10.0", []uint32{64512, 65499, 65499, 65499})
			},
		},
		// 1.27.8
		{
			name:  "1.27.8 redistribute-ipv4-route-policy-med",
			setup: func() { redistributeStaticRoutePolicyWithMED(t, dut, isV4, medNonZero) },
			validate: func() {
				validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", medNonZero, shouldBePresent)
			},
		},
		// 1.27.9
		{
			name:  "1.27.9 redistribute-ipv4-route-policy-local-preference",
			setup: func() { redistributeStaticRoutePolicyWithLocalPreference(t, dut, isV4, localPreference) },
			validate: func() {
				validatePrefixLocalPreference(t, ate, isV4, atePort3.Name+".BGP4.peer", "192.168.10.0", localPreference)
			},
		},
		// 1.27.10
		{
			name:  "1.27.10 redistribute-ipv4-route-policy-community-set",
			setup: func() { redistributeStaticRoutePolicyWithCommunitySet(t, dut, isV4) },
			validate: func() {
				validatePrefixCommunitySet(t, ate, isV4, atePort3.Name+".BGP4.peer", "192.168.10.0", "64512:100")
			},
		},
		// 1.27.12
		{
			name:     "1.27.12 redistribute-ipv4-route-policy-unmatched-tag",
			setup:    func() { redistributeStaticRoutePolicyWithTagSet(t, dut, isV4, 100) },
			validate: func() { validateRedistributeRouteWithTagSet(t, dut, ate, isV4, !shouldBePresent) },
		},
		// 1.27.13
		{
			name:     "1.27.13 redistribute-ipv4-route-policy-matched-set",
			setup:    func() { redistributeStaticRoutePolicyWithTagSet(t, dut, isV4, 40) },
			validate: func() { validateRedistributeRouteWithTagSet(t, dut, ate, isV4, shouldBePresent) },
		},
		// 1.27.14
		{
			name:     "1.27.14 redistribute-ipv4-route-policy-nexthop",
			setup:    func() { redistributeIPv4NullStaticRoute(t, dut, ate) },
			validate: func() { validateRedistributeNullStaticRoute(t, dut, ate, isV4) },
		},
		// 1.27.15
		{
			name:     "1.27.15 redistribute-ipv6-route-policy",
			setup:    func() { redistributeIPv6StaticRoutePolicy(t, dut, ate) },
			validate: func() { validateRedistributeIPv6RoutePolicy(t, dut, ate) },
		},
		// 1.27.16
		{
			name:  "1.27.16 redistribute-ipv6-route-policy-as-prepend",
			setup: func() { redistributeStaticRoutePolicyWithASN(t, dut, !isV4) },
			validate: func() {
				validatePrefixASN(t, ate, !isV4, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", []uint32{64512, 64512})
			},
		},
		// 1.27.17
		{
			name:  "1.27.17 redistribute-ipv6-route-policy-med",
			setup: func() { redistributeStaticRoutePolicyWithMED(t, dut, !isV4, medNonZero) },
			validate: func() {
				validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", medNonZero, shouldBePresent)
			},
		},
		// 1.27.18
		{
			name:  "1.27.18 redistribute-ipv6-route-policy-local-preference",
			setup: func() { redistributeStaticRoutePolicyWithLocalPreference(t, dut, !isV4, localPreference) },
			validate: func() {
				validatePrefixLocalPreference(t, ate, !isV4, atePort3.Name+".BGP6.peer", "2024:db8:128:128::", localPreference)
			},
		},
		// 1.27.19
		{
			name:  "1.27.19 redistribute-ipv6-route-policy-community-set",
			setup: func() { redistributeStaticRoutePolicyWithCommunitySet(t, dut, !isV4) },
			validate: func() {
				validatePrefixCommunitySet(t, ate, !isV4, atePort3.Name+".BGP6.peer", "2024:db8:128:128::", "64512:100")
			},
		},
		// 1.27.20
		{
			name:     "1.27.20 redistribute-ipv6-route-policy-unmatched-tag",
			setup:    func() { redistributeStaticRoutePolicyWithTagSet(t, dut, !isV4, 100) },
			validate: func() { validateRedistributeRouteWithTagSet(t, dut, ate, !isV4, !shouldBePresent) },
		},
		// 1.27.21
		{
			name:     "1.27.21 redistribute-ipv6-route-policy-matched-set",
			setup:    func() { redistributeStaticRoutePolicyWithTagSet(t, dut, !isV4, 60) },
			validate: func() { validateRedistributeRouteWithTagSet(t, dut, ate, !isV4, shouldBePresent) },
		},
		// 1.27.22
		{
			name:     "1.27.22 redistribute-ipv6-route-policy-nexthop",
			setup:    func() { redistributeIPv6NullStaticRoute(t, dut, ate) },
			validate: func() { validateRedistributeNullStaticRoute(t, dut, ate, !isV4) },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			tc.validate()
		})
	}
}

// Function using native-yang to attach tag-set to static-route
func attachTagSetToStaticRoute(t *testing.T, dut *ondatra.DUTDevice, prefix, tagPolicy string) {

	tagValue, err := json.Marshal(tagPolicy)
	if err != nil {
		t.Fatalf("Error with json Marshal: %v", err)
	}

	gpbSetRequest := &gpb.SetRequest{
		Prefix: &gpb.Path{
			Origin: "native",
		},
		Update: []*gpb.Update{
			{
				Path: &gpb.Path{
					Elem: []*gpb.PathElem{
						{Name: "network-instance", Key: map[string]string{"name": "DEFAULT"}},
						{Name: "static-routes"},
						{Name: "route", Key: map[string]string{"prefix": prefix}},
						{Name: "tag-set"},
					},
				},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: tagValue,
					},
				},
			},
		},
	}

	gnmiClient := dut.RawAPIs().GNMI(t)
	if _, err := gnmiClient.Set(context.Background(), gpbSetRequest); err != nil {
		t.Fatalf("Unexpected error updating SRL static-route tag-set: %v", err)
	}

}

// Function using native-yang to configure tag-set used by static-route
func configureStaticRouteTagSet(t *testing.T, dut *ondatra.DUTDevice) {

	var routingPolicyTagSetValueV4 = []any{
		map[string]any{
			"tag-value": []any{
				40,
			},
		},
	}
	tagValueV4, err := json.Marshal(routingPolicyTagSetValueV4)
	if err != nil {
		t.Fatalf("Error with json Marshal: %v", err)
	}
	var routingPolicyTagSetValueV6 = []any{
		map[string]any{
			"tag-value": []any{
				60,
			},
		},
	}
	tagValueV6, err := json.Marshal(routingPolicyTagSetValueV6)
	if err != nil {
		t.Fatalf("Error with json Marshal: %v", err)
	}

	gpbSetRequest := &gpb.SetRequest{
		Prefix: &gpb.Path{
			Origin: "native",
		},
		Update: []*gpb.Update{
			{
				Path: &gpb.Path{
					Elem: []*gpb.PathElem{
						{Name: "routing-policy"},
						{Name: "tag-set", Key: map[string]string{"name": "tag-static-v4"}},
					},
				},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: tagValueV4,
					},
				},
			},
			{
				Path: &gpb.Path{
					Elem: []*gpb.PathElem{
						{Name: "routing-policy"},
						{Name: "tag-set", Key: map[string]string{"name": "tag-static-v6"}},
					},
				},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: tagValueV6,
					},
				},
			},
		},
	}

	gnmiClient := dut.RawAPIs().GNMI(t)
	if _, err := gnmiClient.Set(context.Background(), gpbSetRequest); err != nil {
		t.Fatalf("Unexpected error updating SRL routing-policy tag-set for static-route: %v", err)
	}
}

// Function using native-yang to configure tag-set with routing-policy
func configureRoutingPolicyTagSet(t *testing.T, dut *ondatra.DUTDevice, isV4 bool, tValue uint32) {

	tName := "tag-set-v4"
	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := policyStatementV4
	if !isV4 {
		tName = "tag-set-v6"
		redistributeStaticPolicy = redistributeStaticPolicyV6
		policyStatement = policyStatementV6
	}

	var routingPolicyTagSet = []any{
		map[string]any{
			"match": map[string]any{
				"internal-tags": map[string]any{
					"tag-set": []string{tName},
				},
			},
			"action": map[string]any{
				"policy-result": "accept",
			},
		},
	}
	tagSetStatement, err := json.Marshal(routingPolicyTagSet)
	if err != nil {
		t.Fatalf("Error with json Marshal: %v", err)
	}
	var routingPolicyTagSetValue = []any{
		map[string]any{
			"tag-value": []any{
				tValue,
			},
		},
	}
	tagValue, err := json.Marshal(routingPolicyTagSetValue)
	if err != nil {
		t.Fatalf("Error with json Marshal: %v", err)
	}

	gpbTagSetReplace := &gpb.SetRequest{
		Prefix: &gpb.Path{
			Origin: "native",
		},
		Replace: []*gpb.Update{
			{
				Path: &gpb.Path{
					Elem: []*gpb.PathElem{
						{Name: "routing-policy"},
						{Name: "tag-set", Key: map[string]string{"name": tName}},
					},
				},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: tagValue,
					},
				},
			},
		},
	}

	gpbPolicyUpdate := &gpb.SetRequest{
		Prefix: &gpb.Path{
			Origin: "native",
		},
		Update: []*gpb.Update{
			{
				Path: &gpb.Path{
					Elem: []*gpb.PathElem{
						{Name: "routing-policy"},
						{Name: "policy", Key: map[string]string{"name": redistributeStaticPolicy}},
						{Name: "statement", Key: map[string]string{"name": policyStatement}},
					},
				},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: tagSetStatement,
					},
				},
			},
		},
	}

	gnmiClient := dut.RawAPIs().GNMI(t)
	if _, err := gnmiClient.Set(context.Background(), gpbTagSetReplace); err != nil {
		t.Fatalf("Unexpected error updating SRL routing-policy tag-set: %v", err)
	}
	if _, err := gnmiClient.Set(context.Background(), gpbPolicyUpdate); err != nil {
		t.Fatalf("Unexpected error updating SRL routing-policy tag-set: %v", err)
	}
}