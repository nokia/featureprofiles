package static_route_bgp_redistribution_test

import (
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygot/ygot"
	"testing"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

const (
	ipv4PrefixLen     = 30
	ipv6PrefixLen     = 126
	subInterfaceIndex = 0
	mtu               = 1500
	peerGroupName     = "PEER-GROUP"
	dutAsn            = 64512
	atePeer1Asn       = 64511
	atePeer2Asn       = 64512
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
		MAC:     "00:12:03:01:01:01",
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
		IPv6:    "2001:db8::10",
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

	// nuke the current static bits
	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
	gnmi.Delete(t, dut, staticPath.Config())

	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	networkInstanceProtocolStatic := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
	networkInstanceProtocolStatic.SetEnabled(true)

	ipv4StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("192.168.10.0/24")
	// TODO - we dont support, guessing table connection related?
	//ipv4StaticRoute.SetSetTag(oc.UnionString("40"))

	ipv4StaticRouteNextHop := ipv4StaticRoute.GetOrCreateNextHop("0")
	ipv4StaticRouteNextHop.SetMetric(104)
	ipv4StaticRouteNextHop.SetNextHop(oc.UnionString("192.168.1.6"))

	ipv6StaticRoute := networkInstanceProtocolStatic.GetOrCreateStatic("2024:db8:128:128::/64")
	//ipv6StaticRoute.SetSetTag(oc.UnionString("60"))

	ipv6StaticRouteNextHop := ipv6StaticRoute.GetOrCreateNextHop("0")
	ipv6StaticRouteNextHop.SetMetric(106)
	ipv6StaticRouteNextHop.SetNextHop(oc.UnionString("2001:DB8::5"))

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
	// TODO - do we have a deviation already for not supporting this? seems like "no" from a quick
	//  search. do we even need one? can/should we just omit and if other vendors require it they
	//  can add it?
	//bgpGlobalIPv4AF.SetSendCommunityType([]oc.E_Bgp_CommunityType{oc.Bgp_CommunityType_STANDARD})

	bgpGlobalIPv6AF := bgpGlobal.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	bgpGlobalIPv6AF.SetEnabled(true)
	//bgpGlobalIPv6AF.SetSendCommunityType([]oc.E_Bgp_CommunityType{oc.Bgp_CommunityType_STANDARD})

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

	ateEBGPNeighborIPv6AF := ateEBGPNeighborOne.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	ateEBGPNeighborIPv6AF.SetEnabled(true)
	ateEBGPNeighborIPv6AFPolicy := ateEBGPNeighborIPv6AF.GetOrCreateApplyPolicy()
	ateEBGPNeighborIPv6AFPolicy.SetImportPolicy([]string{"import-dut-port2-connected-subnet"})
	ateEBGPNeighborIPv6AFPolicy.SetExportPolicy([]string{"import-dut-port2-connected-subnet"})

	// dutPort3 -> atePort3 peer (ibgp session)
	ateIBGPNeighborTwo := bgp.GetOrCreateNeighbor(atePort3.IPv4)
	ateIBGPNeighborTwo.PeerGroup = ygot.String(peerGroupName)
	ateIBGPNeighborTwo.PeerAs = ygot.Uint32(atePeer2Asn)
	ateIBGPNeighborTwo.Enabled = ygot.Bool(true)

	ateIBGPNeighborIPv4AF := ateIBGPNeighborTwo.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	ateIBGPNeighborIPv4AF.SetEnabled(true)

	ateIBGPNeighborIPv6AF := ateIBGPNeighborTwo.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	ateIBGPNeighborIPv6AF.SetEnabled(true)

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

func configureOTG(t *testing.T, otg *otg.OTG) {
	t.Helper()

	otgConfig := gosnappi.NewConfig()

	port1 := otgConfig.Ports().Add().SetName("port1")
	port2 := otgConfig.Ports().Add().SetName("port2")
	port3 := otgConfig.Ports().Add().SetName("port3")

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

	// Port3 Configuration.
	iDut3Dev := otgConfig.Devices().Add().SetName(atePort3.Name)
	iDut3Eth := iDut3Dev.Ethernets().Add().SetName(atePort3.Name + ".Eth").SetMac(atePort3.MAC)
	iDut3Eth.Connection().SetPortName(port3.Name())
	iDut3Ipv4 := iDut3Eth.Ipv4Addresses().Add().SetName(atePort3.Name + ".IPv4")
	iDut3Ipv4.SetAddress(atePort3.IPv4).SetGateway(dutPort3.IPv4).SetPrefix(uint32(atePort3.IPv4Len))
	iDut3Ipv6 := iDut3Eth.Ipv6Addresses().Add().SetName(atePort3.Name + ".IPv6")
	iDut3Ipv6.SetAddress(atePort3.IPv6).SetGateway(dutPort3.IPv6).SetPrefix(uint32(atePort3.IPv6Len))

	// eBGP v4 session on Port1.
	iDut1Bgp := iDut1Dev.Bgp().SetRouterId(iDut1Ipv4.Address())
	iDut1Bgp4Peer := iDut1Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut1Ipv4.Name()).Peers().Add().SetName(atePort1.Name + ".BGP4.peer")
	iDut1Bgp4Peer.SetPeerAddress(iDut1Ipv4.Gateway()).SetAsNumber(atePeer1Asn).SetAsType(gosnappi.BgpV4PeerAsType.EBGP)
	iDut1Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
	// eBGP v6 session on Port1.
	iDut1Bgp6Peer := iDut1Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut1Ipv6.Name()).Peers().Add().SetName(atePort1.Name + ".BGP6.peer")
	iDut1Bgp6Peer.SetPeerAddress(iDut1Ipv6.Gateway()).SetAsNumber(atePeer1Asn).SetAsType(gosnappi.BgpV6PeerAsType.EBGP)
	iDut1Bgp6Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut1Bgp6Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

	// iBGP v4 session on Port3.
	iDut3Bgp := iDut3Dev.Bgp().SetRouterId(iDut3Ipv4.Address())
	iDut3Bgp4Peer := iDut3Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut3Ipv4.Name()).Peers().Add().SetName(atePort3.Name + ".BGP4.peer")
	iDut3Bgp4Peer.SetPeerAddress(iDut3Ipv4.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
	iDut3Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut3Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)
	// iBGP v6 session on Port3.
	iDut3Bgp6Peer := iDut3Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut3Ipv6.Name()).Peers().Add().SetName(atePort3.Name + ".BGP6.peer")
	iDut3Bgp6Peer.SetPeerAddress(iDut3Ipv6.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV6PeerAsType.IBGP)
	iDut3Bgp6Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut3Bgp6Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

	otg.PushConfig(t, otgConfig)
	otg.StartProtocols(t)
}

func TestBGPStaticRouteRedistribution(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	configureDUT(t, dut)
	configureOTG(t, otg)
}
