package static_route_bgp_redistribution_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
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

type testCase struct {
	name     string
	setup    func(t *testing.T, dut *ondatra.DUTDevice)
	validate func(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice)
	cleanup  func(t *testing.T, dut *ondatra.DUTDevice)
}

const (
	ipv4PrefixLen            = 30
	ipv6PrefixLen            = 126
	subInterfaceIndex        = 0
	mtu                      = 1500
	peerGroupName            = "PEER-GROUP"
	dutAsn                   = 64512
	atePeer1Asn              = 64511
	atePeer2Asn              = 64512
	acceptRoute              = true
	metricPropagate          = true
	isV4                     = true
	redistributeStaticPolicy = "fp-redistribute-static-policy"
	replace                  = true
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

	testCases = []testCase{
		// 1.27-1
		{
			name:     "redistribute-ipv4-static-routes-with-metric-propagation-disabled",
			setup:    redistributeIPv4Static,
			validate: validateRedistributeIPv4Static,
			cleanup:  nil,
		},
		// 1.27-2
		{
			name:     "redistribute-ipv4-static-routes-with-metric-propagation-enabled",
			setup:    redistributeIPv4StaticWithMetricPropagation,
			validate: validateRedistributeIPv4StaticWithMetricPropagation,
			cleanup:  nil,
		},
		// 1.27-3
		{
			name:     "redistribute-ipv6-static-routes-with-metric-propagation-disabled",
			setup:    redistributeIPv6Static,
			validate: validateRedistributeIPv6Static,
			cleanup:  nil,
		},
		// 1.27-4
		{
			name:     "redistribute-ipv6-static-routes-with-metric-propagation-enabled",
			setup:    redistributeIPv6StaticWithMetricPropagation,
			validate: validateRedistributeIPv6StaticWithMetricPropagation,
			cleanup:  nil,
		},
		// 1.27-5
		{
			name:     "redistribute-ipv4-ipv6-default-reject-policy",
			setup:    redistributeIPv4IPv6StaticDefaultRejectPolicy,
			validate: validateRedistributeIPv4IPv6DefaultRejectPolicy,
			cleanup:  nil,
		},
		// 1.27-6
		{
			name:     "redistribute-ipv4-ipv6-route-policy",
			setup:    redistributeIPv4StaticRoutePolicy,
			validate: validateRedistributeIPv4RoutePolicy,
			cleanup:  nil,
		},
		// 1.27-7
		{
			name:     "redistribute-ipv4-route-policy-asn",
			setup:    redistributeIPv4StaticRoutePolicyWithASN,
			validate: validateIPv4RouteWithASN,
			cleanup:  nil,
		},
		// 1.27-8
		{
			name:     "redistribute-ipv4-route-policy-med",
			setup:    redistributeIPv4StaticRoutePolicyWithMED,
			validate: validateIPv4RouteWithMED,
			cleanup:  nil,
		},
		// 1.27-9
		{
			name:     "redistribute-ipv4-route-policy-local-preference",
			setup:    redistributeIPv4StaticRoutePolicyWithLocalPreference,
			validate: validateIPv4RouteWithLocalPreference,
			cleanup:  nil,
		},
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

	ateIBGPNeighborIPv4AF := ateIBGPNeighborThree.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	ateIBGPNeighborIPv4AF.SetEnabled(true)

	ateIBGPNeighborIPv6AF := ateIBGPNeighborThree.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
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

func awaitBGPEstablished(t *testing.T, dut *ondatra.DUTDevice, neighbors []string) {
	for _, neighbor := range neighbors {
		gnmi.Await(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).
			Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").
			Bgp().
			Neighbor(neighbor).
			SessionState().State(), time.Second*120, oc.Bgp_Neighbor_SessionState_ESTABLISHED)
	}
}

func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {
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
	// TODO -- seems like we are supposed to add loopbacks here for 192.168.10.0/24 and 192.168.20.0/24
	//  and the ipv6 subnets but dunno if its actually necessary yet since we are just having routes
	//  set as static on the dut then adv into bgp so dont think we really need them on ate for any
	//  reason

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

	return otgConfig
}

func redistributeStatic(t *testing.T, dut *ondatra.DUTDevice, isV4, acceptRoute, mPropagation bool) {
	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))

	dutOcRoot := &oc.Root{}
	networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	af := oc.Types_ADDRESS_FAMILY_IPV4
	if !isV4 {
		af = oc.Types_ADDRESS_FAMILY_IPV6
	}

	tc := networkInstance.GetOrCreateTableConnection(
		oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
		oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
		af,
	)

	tc.SetImportPolicy([]string{"REJECT_ROUTE"})
	if acceptRoute {
		tc.SetImportPolicy([]string{"ACCEPT_ROUTE"})
	}
	tc.SetDisableMetricPropagation(!mPropagation)

	gnmi.Update(t, dut, niPath.Config(), networkInstance)
}

func redistributeNokiaStatic(t *testing.T, dut *ondatra.DUTDevice, isV4, acceptRoute, mPropagation, replace bool) {
	dutOcRoot := &oc.Root{}
	rp := dutOcRoot.GetOrCreateRoutingPolicy()

	apolicy := rp.GetOrCreatePolicyDefinition(redistributeStaticPolicy)
	astmt, _ := apolicy.AppendNewStatement("10")
	astmt.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
	astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_REJECT_ROUTE
	if acceptRoute {
		astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
	}
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(0))
	if mPropagation {
		astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP))
	}

	rpConfPath := gnmi.OC().RoutingPolicy()
	gnmi.Replace(t, dut, rpConfPath.PolicyDefinition(redistributeStaticPolicy).Config(), apolicy)

	bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
	if !isV4 {
		bgpPath = gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
	}
	if replace {
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	} else {
		gnmi.Update(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
	}
}

func redistributeIPv4Static(t *testing.T, dut *ondatra.DUTDevice) {
	// TODO -- guess we need a deviation for table connections; doing this for now to be lazy --
	//  there are a lot of these in here, just commenting here for simplicity
	if dut.Vendor() != ondatra.NOKIA {
		redistributeStatic(t, dut, isV4, acceptRoute, !metricPropagate)
	} else {
		redistributeNokiaStatic(t, dut, isV4, acceptRoute, !metricPropagate, replace)
	}
}

func validateRedistributeIPv4Static(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4).State())

		if tcState.GetSrcProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC {
			t.Fatal("source protocol not static for table connection but should be")
		}

		if tcState.GetDstProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP {
			t.Fatal("destination protocol not bgp for table connection but should be")
		}

		if tcState.GetAddressFamily() != oc.Types_ADDRESS_FAMILY_IPV4 {
			t.Fatal("address family not ipv4 for table connection but should be")
		}

		if tcState.GetDisableMetricPropagation() {
			t.Fatal("metric propagation not disabled for table connection but should be")
		}
	}

	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, true)
}

func redistributeIPv4StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		redistributeStatic(t, dut, isV4, acceptRoute, metricPropagate)
	} else {
		redistributeNokiaStatic(t, dut, isV4, acceptRoute, metricPropagate, replace)
	}
}

func validateRedistributeIPv4StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4).State())

		//just checking that metric propagation got enabled since the first test case already covers
		//the rest of the settings we care about
		if tcState.GetDisableMetricPropagation() {
			t.Fatal("metric propagation not disabled for table connection but should be")
		}
	}

	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 104, true)
}

func redistributeIPv6Static(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		redistributeStatic(t, dut, !isV4, acceptRoute, !metricPropagate)
	} else {
		redistributeNokiaStatic(t, dut, !isV4, acceptRoute, !metricPropagate, replace)
	}
}

func validateRedistributeIPv6Static(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		if tcState.GetSrcProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC {
			t.Fatal("source protocol not static for table connection but should be")
		}

		if tcState.GetDstProtocol() != oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP {
			t.Fatal("destination protocol not bgp for table connection but should be")
		}

		if tcState.GetAddressFamily() != oc.Types_ADDRESS_FAMILY_IPV6 {
			t.Fatal("address family not ipv6 for table connection but should be")
		}

		if tcState.GetDisableMetricPropagation() {
			t.Fatal("metric propagation not disabled for table connection but should be")
		}
	}

	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, true)
}

func redistributeIPv6StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		redistributeStatic(t, dut, !isV4, acceptRoute, metricPropagate)
	} else {
		redistributeNokiaStatic(t, dut, !isV4, acceptRoute, metricPropagate, replace)
	}
}

func validateRedistributeIPv6StaticWithMetricPropagation(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		//just checking that metric propagation got enabled since the first test case already covers
		//the rest of the settings we care about
		if tcState.GetDisableMetricPropagation() {
			t.Fatal("metric propagation not disabled for table connection but should be")
		}
	}

	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 106, true)
}

func redistributeIPv4IPv6StaticDefaultRejectPolicy(t *testing.T, dut *ondatra.DUTDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		redistributeStatic(t, dut, isV4, !acceptRoute, metricPropagate)
		redistributeStatic(t, dut, !isV4, !acceptRoute, metricPropagate)
	} else {
		redistributeNokiaStatic(t, dut, isV4, !acceptRoute, metricPropagate, replace)
		redistributeNokiaStatic(t, dut, !isV4, !acceptRoute, metricPropagate, !replace)
	}
}

func validateRedistributeIPv4IPv6DefaultRejectPolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		// just checking that metric propagation got enabled since the first test case already covers
		// the rest of the settings we care about, which in this case is the updated policy
		if tcState.GetDefaultImportPolicy() != oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE {
			t.Fatal("default import policy is not reject route but it should be")
		}
	} else {
		redistributeNokiaStatic(t, dut, !isV4, !acceptRoute, metricPropagate, replace)
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, false)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, false)
}

func redistributeIPv4StaticRoutePolicy(t *testing.T, dut *ondatra.DUTDevice) {
	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	// policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition("import-dut-port2-connected-subnet")
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	v4PrefixSet := redistributePolicy.GetOrCreateDefinedSets().GetOrCreatePrefixSet("prefix-set-v4")
	// TODO test says use "exact" is that literally ok? in the other case we have like 30..32 which
	//  makes sense of course, do they just mean 32..32 or just 32 or something?
	v4PrefixSet.GetOrCreatePrefix("192.168.10.0/30", "exact")
	// v4PrefixSet.SetMode(oc.PrefixSet_Mode_IPV4)

	v4PrefixSet.GetOrCreatePrefix("192.168.20.0/24", "exact")
	// v4PrefixSet.SetMode(oc.PrefixSet_Mode_IPV4)

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().DefinedSets().PrefixSet("prefix-set-v4").Config(), v4PrefixSet)

	if dut.Vendor() == ondatra.NOKIA {
		redistributeStatic, err := redistributePolicyDefinition.AppendNewStatement("redistribute-static")
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		redistributeStatic.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
		redistributeStatic.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP))
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement("statement-v4")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)

	ipv4PrefixPolicyStatementConditionsPrefixes := ipv4PrefixPolicyStatement.GetOrCreateConditions().GetOrCreateMatchPrefixSet()
	ipv4PrefixPolicyStatementConditionsPrefixes.SetPrefixSet("prefix-set-v4")
	// ipv4PrefixPolicyStatementConditionsPrefixes.SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

		tc := networkInstance.GetOrCreateTableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4,
		)
		tc.SetImportPolicy([]string{"REJECT_ROUTE"})
		tc.SetDisableMetricPropagation(true)
		tc.SetImportPolicy([]string{redistributeStaticPolicy})

		gnmi.Update(t, dut, niPath.Config(), networkInstance)
	} else {

		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
		// redistributeNokiaStatic(t, dut, isV4, !acceptRoute, metricPropagate)
	}
}

func redistributeIPv4StaticRoutePolicyWithASN(t *testing.T, dut *ondatra.DUTDevice) {
	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributeStatic, err := redistributePolicyDefinition.AppendNewStatement("redistribute-static")
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		redistributeStatic.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
		redistributeStatic.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP))
		redistributeStatic.GetOrCreateActions().BgpActions.GetOrCreateSetAsPathPrepend().Asn = ygot.Uint32(65499)
		redistributeStatic.GetOrCreateActions().BgpActions.GetOrCreateSetAsPathPrepend().SetRepeatN(3)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement("statement-v4")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().Asn = ygot.Uint32(65499)
	ipv4PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().SetRepeatN(3)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

		tc := networkInstance.GetOrCreateTableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4,
		)
		tc.SetImportPolicy([]string{"REJECT_ROUTE"})
		tc.SetDisableMetricPropagation(true)
		tc.SetImportPolicy([]string{redistributeStaticPolicy})

		gnmi.Update(t, dut, niPath.Config(), networkInstance)
	} else {

		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
		// redistributeNokiaStatic(t, dut, isV4, !acceptRoute, metricPropagate)
	}
}

func redistributeIPv4StaticRoutePolicyWithMED(t *testing.T, dut *ondatra.DUTDevice) {
	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributeStatic, err := redistributePolicyDefinition.AppendNewStatement("redistribute-static")
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		redistributeStatic.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
		redistributeStatic.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(1000))
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement("statement-v4")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(1000))

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

		tc := networkInstance.GetOrCreateTableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4,
		)
		tc.SetImportPolicy([]string{"REJECT_ROUTE"})
		tc.SetDisableMetricPropagation(true)
		tc.SetImportPolicy([]string{redistributeStaticPolicy})

		gnmi.Update(t, dut, niPath.Config(), networkInstance)
	} else {

		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
		// redistributeNokiaStatic(t, dut, isV4, !acceptRoute, metricPropagate)
	}
}

func redistributeIPv4StaticRoutePolicyWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice) {
	niPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicy)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)

	if dut.Vendor() == ondatra.NOKIA {
		redistributeStatic, err := redistributePolicyDefinition.AppendNewStatement("redistribute-static")
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}
		redistributeStatic.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
		redistributeStatic.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
		redistributeStatic.GetOrCreateActions().GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(100)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement("statement-v4")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(100)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

		tc := networkInstance.GetOrCreateTableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4,
		)
		tc.SetImportPolicy([]string{"REJECT_ROUTE"})
		tc.SetDisableMetricPropagation(true)
		tc.SetImportPolicy([]string{redistributeStaticPolicy})

		gnmi.Update(t, dut, niPath.Config(), networkInstance)
	} else {

		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicy})
		// redistributeNokiaStatic(t, dut, isV4, !acceptRoute, metricPropagate)
	}
}

func validateRedistributeIPv4RoutePolicy(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		// just checking that metric propagation got enabled since the first test case already covers
		// the rest of the settings we care about, which in this case is the updated policy
		if tcState.GetDefaultImportPolicy() != oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE {
			t.Fatal("default import policy is not reject route but it should be")
		}

		importPolicies := tcState.GetImportPolicy()
		if len(importPolicies) == 0 || len(importPolicies) > 1 {
			t.Fatal("import policies len is not one, but it should be")
		}

		// we replaced this container so there should only be our import policy anyway
		if importPolicies[0] != redistributeStaticPolicy {
			t.Fatal("expected import policy is not configured")
		}
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, true)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, true)
}

func validateIPv4RouteWithMED(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 1000, true)
}

func validateIPv4RouteWithASN(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv4PrefixASN(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", []uint32{64512, 65499, 65499, 65499})
}

func validateIPv4RouteWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv4PrefixLocalPreference(t, ate, atePort3.Name+".BGP4.peer", "192.168.10.0", 100)
}

func validateIPv4PrefixASN(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, wantASPath []uint32) {

	// t.Logf("LC: Sleeping 1min for Pause")
	// time.Sleep(1 * time.Minute)
	time.Sleep(10 * time.Second)
	foundPrefix := false
	prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
	for _, prefix := range prefixes {
		if prefix.GetAddress() == subnet {
			foundPrefix = true
			gotASPath := prefix.AsPath[len(prefix.AsPath)-1].GetAsNumbers()
			t.Logf("LC: Prefix %v learned with ASN : %v", prefix.GetAddress(), gotASPath)
			if !reflect.DeepEqual(gotASPath, wantASPath) {
				t.Fatalf("Prefix %v with unexpected ASN : %v, expected: %v", prefix.GetAddress(), gotASPath, wantASPath)
			}
		}
	}
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}

}

func validateIPv4PrefixLocalPreference(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, wantLocalPreference uint32) {

	// t.Logf("LC: Sleeping 1min for Pause")
	// time.Sleep(1 * time.Minute)
	time.Sleep(10 * time.Second)
	foundPrefix := false
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
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}

}

func validateLearnedIPv4Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {
	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv4Prefix
	// t.Logf("LC: Sleeping 1min for Pause")
	// time.Sleep(1 * time.Minute)
	time.Sleep(10 * time.Second)

	_, ok := gnmi.WatchAll(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv4Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	if ok {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv4PrefixAny().State())
		for _, prefix := range prefixes {
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
			}
		}
	}

	if !shouldBePresent {
		if ok {
			t.Fatal("redistributed v4 prefix present in otg but should not be")
		}

		return
	}
	if !ok {
		t.Fatal("did not see redistributed v4 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	t.Logf("LC: Got MED : %v", actualMED)
	if actualMED != expectedMED {
		t.Fatalf("ate learned redistributed prefix with med set to %d, expected %d", actualMED, expectedMED)
	}
}

func validateLearnedIPv6Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {
	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv6Prefix
	// t.Logf("LC: IPv6 Sleeping 1min for Pause")
	// time.Sleep(1 * time.Minute)
	time.Sleep(10 * time.Second)

	_, ok := gnmi.WatchAll(t,
		ate.OTG(),
		gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State(),
		time.Minute,
		func(v *ygnmi.Value[*otgtelemetry.BgpPeer_UnicastIpv6Prefix]) bool {
			_, present := v.Val()
			return present
		}).Await(t)

	if ok {
		prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
		for _, prefix := range prefixes {
			t.Logf("LC: Found subnet %v with MED %v", prefix.GetAddress(), prefix.GetMultiExitDiscriminator())
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
			}
		}
	}

	if !shouldBePresent {
		if ok {
			t.Fatal("redistributed v6 prefix present in otg but should not be")
		}

		return
	}
	if !ok {
		t.Fatal("did not see redistributed v4 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	if actualMED != expectedMED {
		t.Fatalf("ate learned redistributed prefix %v with med set to %d, expected %d", subnet, actualMED, expectedMED)
	}
}

func TestBGPStaticRouteRedistribution(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	configureDUT(t, dut)
	configureOTG(t, otg)

	awaitBGPEstablished(t, dut, []string{atePort1.IPv4, atePort3.IPv4})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t, dut)
			tc.validate(t, dut, ate)

			if tc.cleanup != nil {
				tc.cleanup(t, dut)
			}
		})
	}
}
