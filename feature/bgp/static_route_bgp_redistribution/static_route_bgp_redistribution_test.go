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

type testCase struct {
	name     string
	setup    func(t *testing.T, dut *ondatra.DUTDevice)
	validate func(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice)
	cleanup  func(t *testing.T, dut *ondatra.DUTDevice)
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
	replace                    = true
	redistributeStaticPolicyV4 = "route-policy-v4"
	redistributeStaticPolicyV6 = "route-policy-v6"
	policyStatementV4          = "statement-v4"
	policyStatementV6          = "statement-v6"
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
			name:     "redistribute-ipv4-route-policy",
			setup:    redistributeIPv4StaticRoutePolicy,
			validate: validateRedistributeIPv4Default,
			cleanup:  nil,
		},
		// 1.27-7
		{
			name:     "redistribute-ipv4-route-policy-as-prepend",
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
		// 1.27-10
		{
			name:     "redistribute-ipv4-route-policy-community-set",
			setup:    redistributeIPv4StaticRoutePolicyWithCommunitySet,
			validate: validateIPv4RouteWithCommunitySet,
			cleanup:  nil,
		},
		// 1.27-12
		{
			name:     "redistribute-ipv4-route-policy-unmatched-tag",
			setup:    redistributeIPv4StaticRoutePolicyWithUnmatchedTagSet,
			validate: validateIPv4RouteWithTagSetReject,
			cleanup:  nil,
		},
		// 1.27-13
		{
			name:     "redistribute-ipv4-route-policy-matched-set",
			setup:    redistributeIPv4StaticRoutePolicyWithMatchedTagSet,
			validate: validateIPv4RouteWithTagSetAccept,
			cleanup:  nil,
		},
		// 1.27-14
		{
			name:     "redistribute-ipv4-route-policy-nexthop",
			setup:    redistributeIPv4NullStaticRoute,
			validate: validateRedistributeIPv4NullStaticRoute,
			cleanup:  nil,
		},
		// 1.27-15
		{
			name:     "redistribute-ipv6-route-policy",
			setup:    redistributeIPv6StaticRoutePolicy,
			validate: validateRedistributeIPv6Default,
			cleanup:  nil,
		},
		// 1.27-16
		{
			name:     "redistribute-ipv6-route-policy-as-prepend",
			setup:    redistributeIPv6StaticRoutePolicyWithASN,
			validate: validateIPv6RouteWithASN,
			cleanup:  nil,
		},
		// 1.27-17
		{
			name:     "redistribute-ipv6-route-policy-med",
			setup:    redistributeIPv6StaticRoutePolicyWithMED,
			validate: validateIPv6RouteWithMED,
			cleanup:  nil,
		},
		// 1.27-18
		{
			name:     "redistribute-ipv6-route-policy-local-preference",
			setup:    redistributeIPv6StaticRoutePolicyWithLocalPreference,
			validate: validateIPv6RouteWithLocalPreference,
			cleanup:  nil,
		},
		// 1.27-19
		{
			name:     "redistribute-ipv6-route-policy-community-set",
			setup:    redistributeIPv6StaticRoutePolicyWithCommunitySet,
			validate: validateIPv6RouteWithCommunitySet,
			cleanup:  nil,
		},
		// 1.27-20
		{
			name:     "redistribute-ipv6-route-policy-unmatched-tag",
			setup:    redistributeIPv6StaticRoutePolicyWithUnmatchedTagSet,
			validate: validateIPv6RouteWithTagSetReject,
			cleanup:  nil,
		},
		// 1.27-21
		{
			name:     "redistribute-ipv6-route-policy-matched-set",
			setup:    redistributeIPv6StaticRoutePolicyWithMatchedTagSet,
			validate: validateIPv6RouteWithTagSetAccept,
			cleanup:  nil,
		},
		// 1.27-22
		{
			name:     "redistribute-ipv6-route-policy-nexthop",
			setup:    redistributeIPv6NullStaticRoute,
			validate: validateRedistributeIPv6NullStaticRoute,
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

func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {
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
	iDut1Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut1Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	// eBGP v6 session on Port1.
	iDut1Bgp6Peer := iDut1Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut1Ipv6.Name()).Peers().Add().SetName(atePort1.Name + ".BGP6.peer")
	iDut1Bgp6Peer.SetPeerAddress(iDut1Ipv6.Gateway()).SetAsNumber(atePeer1Asn).SetAsType(gosnappi.BgpV6PeerAsType.EBGP)
	iDut1Bgp6Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut1Bgp6Peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	// iBGP v4 session on Port3.
	iDut3Bgp := iDut3Dev.Bgp().SetRouterId(iDut3Ipv4.Address())
	iDut3Bgp4Peer := iDut3Bgp.Ipv4Interfaces().Add().SetIpv4Name(iDut3Ipv4.Name()).Peers().Add().SetName(atePort3.Name + ".BGP4.peer")
	iDut3Bgp4Peer.SetPeerAddress(iDut3Ipv4.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
	iDut3Bgp4Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut3Bgp4Peer.LearnedInformationFilter().SetUnicastIpv4Prefix(true)
	// iBGP v6 session on Port3.
	iDut3Bgp6Peer := iDut3Bgp.Ipv6Interfaces().Add().SetIpv6Name(iDut3Ipv6.Name()).Peers().Add().SetName(atePort3.Name + ".BGP6.peer")
	iDut3Bgp6Peer.SetPeerAddress(iDut3Ipv6.Gateway()).SetAsNumber(atePeer2Asn).SetAsType(gosnappi.BgpV6PeerAsType.IBGP)
	iDut3Bgp6Peer.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
	iDut3Bgp6Peer.LearnedInformationFilter().SetUnicastIpv6Prefix(true)

	// ATE Traffic Configuration.
	t.Logf("TestBGP:start ate Traffic config")

	otgConfig.Flows().Clear()

	// Traffic to 192.168.10.0
	flowIpv4 := otgConfig.Flows().Add().SetName("StaticRoutesV4Flow")
	flowIpv4.Metrics().SetEnable(true)
	flowIpv4.TxRx().Device().
		SetTxNames([]string{iDut1Ipv4.Name()}).
		SetRxNames([]string{iDut2Ipv4.Name()})
	flowIpv4.Size().SetFixed(512)
	flowIpv4.Duration().FixedPackets().SetPackets(1000)
	e1 := flowIpv4.Packet().Add().Ethernet()
	e1.Src().SetValue(iDut1Eth.Mac())
	v4 := flowIpv4.Packet().Add().Ipv4()
	v4.Src().SetValue(iDut1Ipv4.Address())
	v4.Dst().SetValues([]string{"192.168.10.0"})

	// Traffic to 192.168.20.0
	dropFlowIpv4 := otgConfig.Flows().Add().SetName("StaticDropRouteV4Flow")
	dropFlowIpv4.Metrics().SetEnable(true)
	dropFlowIpv4.TxRx().Device().
		SetTxNames([]string{iDut3Ipv4.Name()}).
		SetRxNames([]string{iDut2Ipv4.Name()})
	dropFlowIpv4.Size().SetFixed(512)
	dropFlowIpv4.Duration().FixedPackets().SetPackets(1000)
	de1 := dropFlowIpv4.Packet().Add().Ethernet()
	de1.Src().SetValue(iDut3Eth.Mac())
	dv4 := dropFlowIpv4.Packet().Add().Ipv4()
	dv4.Src().SetValue(iDut3Ipv4.Address())
	dv4.Dst().SetValues([]string{"192.168.20.0"})

	// Traffic to 2024:db8:128:128::
	flowIpv6 := otgConfig.Flows().Add().SetName("StaticRoutesV6Flow")
	flowIpv6.Metrics().SetEnable(true)
	flowIpv6.TxRx().Device().
		SetTxNames([]string{iDut1Ipv6.Name()}).
		SetRxNames([]string{iDut2Ipv6.Name()})
	flowIpv6.Size().SetFixed(512)
	flowIpv6.Duration().FixedPackets().SetPackets(1000)
	e2 := flowIpv6.Packet().Add().Ethernet()
	e2.Src().SetValue(iDut1Eth.Mac())
	v6 := flowIpv6.Packet().Add().Ipv6()
	v6.Src().SetValue(iDut1Ipv6.Address())
	v6.Dst().SetValues([]string{"2024:db8:128:128::"})

	// Traffic to 2024:db8:128:128::
	dropFlowIpv6 := otgConfig.Flows().Add().SetName("StaticDropRouteV6Flow")
	dropFlowIpv6.Metrics().SetEnable(true)
	dropFlowIpv6.TxRx().Device().
		SetTxNames([]string{iDut3Ipv6.Name()}).
		SetRxNames([]string{iDut2Ipv6.Name()})
	dropFlowIpv6.Size().SetFixed(512)
	dropFlowIpv6.Duration().FixedPackets().SetPackets(1000)
	de2 := dropFlowIpv6.Packet().Add().Ethernet()
	de2.Src().SetValue(iDut3Eth.Mac())
	dv6 := dropFlowIpv6.Packet().Add().Ipv6()
	dv6.Src().SetValue(iDut3Ipv6.Address())
	dv6.Dst().SetValues([]string{"2024:db8:64:64::"})

	otg.PushConfig(t, otgConfig)
	otg.StartProtocols(t)

	return otgConfig
}

func configureTableConnection(t *testing.T, dut *ondatra.DUTDevice, isV4, mPropagation bool, importPolicy string) {
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

	tc.SetImportPolicy([]string{importPolicy})
	tc.SetDisableMetricPropagation(!mPropagation)
	gnmi.Update(t, dut, niPath.Config(), networkInstance)
}

func redistributeStaticRouteNokia(t *testing.T, isV4 bool, mPropagation, policyResultNext bool, routingPolicy *oc.RoutingPolicy) *oc.RoutingPolicy {

	redistributeStaticPolicy := redistributeStaticPolicyV4
	policyStatement := "redistribute-static"
	if !isV4 {
		redistributeStaticPolicy = redistributeStaticPolicyV6
	}

	apolicy := routingPolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicy)
	astmt, _ := apolicy.AppendNewStatement(policyStatement)
	astmt.GetOrCreateConditions().SetInstallProtocolEq(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC)
	astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE
	if policyResultNext {
		astmt.GetOrCreateActions().PolicyResult = oc.RoutingPolicy_PolicyResultType_NEXT_STATEMENT
	}
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetRouteOrigin(oc.E_BgpPolicy_BgpOriginAttrType(oc.BgpPolicy_BgpOriginAttrType_IGP))
	astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(0))
	if mPropagation {
		astmt.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.E_BgpActions_SetMed(oc.BgpActions_SetMed_IGP))
	}

	return routingPolicy
}

func configureStaticRedistributionPolicy(t *testing.T, dut *ondatra.DUTDevice, isV4, acceptRoute, mPropagation, replace bool) {
	dutOcRoot := &oc.Root{}
	rp := dutOcRoot.GetOrCreateRoutingPolicy()
	rp = redistributeStaticRouteNokia(t, isV4, mPropagation, !policyResultNext, rp)

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
		configureTableConnection(t, dut, isV4, !metricPropagate, "ACCEPT_ROUTE")
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, acceptRoute, !metricPropagate, replace)
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
		configureTableConnection(t, dut, isV4, metricPropagate, "ACCEPT_ROUTE")
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, acceptRoute, metricPropagate, replace)
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
		configureTableConnection(t, dut, !isV4, !metricPropagate, "ACCEPT_ROUTE")
	} else {
		configureStaticRedistributionPolicy(t, dut, !isV4, acceptRoute, !metricPropagate, replace)
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
		configureTableConnection(t, dut, !isV4, metricPropagate, "ACCEPT_ROUTE")
	} else {
		configureStaticRedistributionPolicy(t, dut, !isV4, acceptRoute, metricPropagate, replace)
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
		configureTableConnection(t, dut, isV4, metricPropagate, "REJECT_ROUTE")
		configureTableConnection(t, dut, !isV4, metricPropagate, "REJECT_ROUTE")
	} else {
		configureStaticRedistributionPolicy(t, dut, isV4, !acceptRoute, metricPropagate, replace)
		configureStaticRedistributionPolicy(t, dut, !isV4, !acceptRoute, metricPropagate, !replace)
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
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, false)
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, false)
}

func validateRedistributeIPv4Default(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4).State())

		// just checking that metric propagation got enabled since the first test case already covers
		// the rest of the settings we care about, which in this case is the updated policy
		if tcState.GetDefaultImportPolicy() != oc.RoutingPolicy_DefaultPolicyType_REJECT_ROUTE {
			t.Fatal("default import policy is not reject route but it should be")
		}
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 104, true)
}

func validateRedistributeIPv6Default(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
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
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 106, true)
}

func redistributeIPv4StaticRoutePolicy(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)

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
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
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
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}
}

func redistributeIPv6StaticRoutePolicy(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)

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
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
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
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}
}

func redistributeIPv4StaticRoutePolicyWithASN(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
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
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}
}

func redistributeIPv6StaticRoutePolicyWithASN(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement("statement-v6")
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv6PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetAsPathPrepend().Asn = ygot.Uint32(64512)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}
}

func redistributeIPv4StaticRoutePolicyWithMED(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(1000))

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}
}

func redistributeIPv6StaticRoutePolicyWithMED(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv6PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetSetMed(oc.UnionUint32(1000))

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}
}

func redistributeIPv4StaticRoutePolicyWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(100)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4)
		/*
			networkInstance := dutOcRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

			tc := networkInstance.GetOrCreateTableConnection(
				oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
				oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
				oc.Types_ADDRESS_FAMILY_IPV4,
			)
			tc.SetImportPolicy([]string{"ACCEPT_ROUTE"})
			tc.SetDisableMetricPropagation(true)
			tc.SetImportPolicy([]string{redistributeStaticPolicyV4})

			gnmi.Update(t, dut, niPath.Config(), networkInstance)
		*/
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}
}

func redistributeIPv6StaticRoutePolicyWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv6PrefixPolicyStatement.GetOrCreateActions().GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(100)

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}
}

func redistributeIPv4StaticRoutePolicyWithCommunitySet(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)
	communityPath := gnmi.OC().RoutingPolicy().DefinedSets().BgpDefinedSets().CommunitySet("community-set-v4")

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	communitySet := dutOcRoot.GetOrCreateRoutingPolicy()
	communitySetPolicyDefinition := communitySet.GetOrCreateDefinedSets().GetOrCreateBgpDefinedSets().GetOrCreateCommunitySet("community-set-v4")
	communitySetPolicyDefinition.SetCommunityMember([]oc.RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySet_CommunityMember_Union{oc.UnionString("64512:100")})

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
	gnmi.Replace(t, dut, communityPath.Config(), communitySetPolicyDefinition)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
	ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv4PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().SetOptions(oc.BgpPolicy_BgpSetCommunityOptionType_ADD)
	ipv4PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().GetOrCreateReference().SetCommunitySetRef("community-set-v4")

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, isV4, metricPropagate, redistributeStaticPolicyV4)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	}
}

func redistributeIPv6StaticRoutePolicyWithCommunitySet(t *testing.T, dut *ondatra.DUTDevice) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)
	communityPath := gnmi.OC().RoutingPolicy().DefinedSets().BgpDefinedSets().CommunitySet("community-set-v6")

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	communitySet := dutOcRoot.GetOrCreateRoutingPolicy()
	communitySetPolicyDefinition := communitySet.GetOrCreateDefinedSets().GetOrCreateBgpDefinedSets().GetOrCreateCommunitySet("community-set-v6")
	communitySetPolicyDefinition.SetCommunityMember([]oc.RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySet_CommunityMember_Union{oc.UnionString("64512:100")})

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
	gnmi.Replace(t, dut, communityPath.Config(), communitySetPolicyDefinition)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, metricPropagate, policyResultNext, redistributePolicy)
	}

	ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
	if err != nil {
		t.Fatalf("failed creating new policy statement, err: %s", err)
	}

	ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
	ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
	ipv6PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().SetOptions(oc.BgpPolicy_BgpSetCommunityOptionType_ADD)
	ipv6PrefixPolicyStatementAction.GetOrCreateBgpActions().GetOrCreateSetCommunity().GetOrCreateReference().SetCommunitySetRef("community-set-v6")

	gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

	if dut.Vendor() != ondatra.NOKIA {
		configureTableConnection(t, dut, !isV4, metricPropagate, redistributeStaticPolicyV6)
	} else {
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort3.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	}
}

func redistributeIPv4StaticRoutePolicyWithUnmatchedTagSet(t *testing.T, dut *ondatra.DUTDevice) {
	redistributeIPv4StaticRoutePolicyWithTagSet(t, dut, 100)
}

func redistributeIPv4StaticRoutePolicyWithMatchedTagSet(t *testing.T, dut *ondatra.DUTDevice) {
	redistributeIPv4StaticRoutePolicyWithTagSet(t, dut, 40)
}

func redistributeIPv6StaticRoutePolicyWithUnmatchedTagSet(t *testing.T, dut *ondatra.DUTDevice) {
	redistributeIPv6StaticRoutePolicyWithTagSet(t, dut, 100)
}

func redistributeIPv6StaticRoutePolicyWithMatchedTagSet(t *testing.T, dut *ondatra.DUTDevice) {
	redistributeIPv6StaticRoutePolicyWithTagSet(t, dut, 60)
}

func redistributeIPv4StaticRoutePolicyWithTagSet(t *testing.T, dut *ondatra.DUTDevice, tagSetValue uint32) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)
	tagSetPath := gnmi.OC().RoutingPolicy().DefinedSets().TagSet("tag-set-v4")

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV4)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, !metricPropagate, policyResultNext, redistributePolicy)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
		configureRoutingPolicyTagSet(t, dut, isV4, tagSetValue)
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV4})
	} else {
		tagSet := dutOcRoot.GetOrCreateRoutingPolicy()
		tagSetPolicyDefinition := tagSet.GetOrCreateDefinedSets().GetOrCreateTagSet("tag-set-v4")
		tagSetPolicyDefinition.SetTagValue([]oc.RoutingPolicy_DefinedSets_TagSet_TagValue_Union{oc.UnionString(fmt.Sprintf("%v", tagSetValue))})
		gnmi.Replace(t, dut, tagSetPath.Config(), tagSetPolicyDefinition)

		ipv4PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV4)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}

		ipv4PrefixPolicyStatementCondition := ipv4PrefixPolicyStatement.GetOrCreateConditions()
		if !deviations.SkipSetRpMatchSetOptions(dut) {
			ipv4PrefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)
		}
		ipv4PrefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetTagSet("tag-set-v4")
		ipv4PrefixPolicyStatementAction := ipv4PrefixPolicyStatement.GetOrCreateActions()
		ipv4PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		configureTableConnection(t, dut, isV4, !metricPropagate, redistributeStaticPolicyV4)
	}
}

func redistributeIPv6StaticRoutePolicyWithTagSet(t *testing.T, dut *ondatra.DUTDevice, tagSetValue uint32) {
	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)
	tagSetPath := gnmi.OC().RoutingPolicy().DefinedSets().TagSet("tag-set-v6")

	dutOcRoot := &oc.Root{}
	redistributePolicy := dutOcRoot.GetOrCreateRoutingPolicy()
	redistributePolicyDefinition := redistributePolicy.GetOrCreatePolicyDefinition(redistributeStaticPolicyV6)

	if dut.Vendor() == ondatra.NOKIA {
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, !metricPropagate, policyResultNext, redistributePolicy)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)
		configureRoutingPolicyTagSet(t, dut, !isV4, tagSetValue)
		bgpPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().Neighbor(atePort1.IPv6).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).ApplyPolicy().ExportPolicy()
		gnmi.Replace(t, dut, bgpPath.Config(), []string{redistributeStaticPolicyV6})
	} else {
		tagSet := dutOcRoot.GetOrCreateRoutingPolicy()
		tagSetPolicyDefinition := tagSet.GetOrCreateDefinedSets().GetOrCreateTagSet("tag-set-v6")
		tagSetPolicyDefinition.SetTagValue([]oc.RoutingPolicy_DefinedSets_TagSet_TagValue_Union{oc.UnionString(fmt.Sprintf("%v", tagSetValue))})
		gnmi.Replace(t, dut, tagSetPath.Config(), tagSetPolicyDefinition)

		ipv6PrefixPolicyStatement, err := redistributePolicyDefinition.AppendNewStatement(policyStatementV6)
		if err != nil {
			t.Fatalf("failed creating new policy statement, err: %s", err)
		}

		ipv6PrefixPolicyStatementCondition := ipv6PrefixPolicyStatement.GetOrCreateConditions()
		if !deviations.SkipSetRpMatchSetOptions(dut) {
			ipv6PrefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetMatchSetOptions(oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY)
		}
		ipv6PrefixPolicyStatementCondition.GetOrCreateMatchTagSet().SetTagSet("tag-set-v6")
		ipv6PrefixPolicyStatementAction := ipv6PrefixPolicyStatement.GetOrCreateActions()
		ipv6PrefixPolicyStatementAction.SetPolicyResult(oc.RoutingPolicy_PolicyResultType_ACCEPT_ROUTE)
		gnmi.Replace(t, dut, policyPath.Config(), redistributePolicyDefinition)

		configureTableConnection(t, dut, !isV4, !metricPropagate, redistributeStaticPolicyV6)
	}
}

func redistributeIPv4NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice) {

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV4)
	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
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
		redistributePolicy = redistributeStaticRouteNokia(t, isV4, !metricPropagate, policyResultNext, redistributePolicy)

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

		configureTableConnection(t, dut, isV4, !metricPropagate, redistributeStaticPolicyV4)
	}
}

func redistributeIPv6NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice) {

	policyPath := gnmi.OC().RoutingPolicy().PolicyDefinition(redistributeStaticPolicyV6)
	staticPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static")
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
		redistributePolicy = redistributeStaticRouteNokia(t, !isV4, !metricPropagate, policyResultNext, redistributePolicy)

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

		configureTableConnection(t, dut, !isV4, !metricPropagate, redistributeStaticPolicyV6)
	}
}

func validateIPv4RouteWithTagSetReject(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeIPv4RouteWithTagSet(t, dut, ate, false)
}
func validateIPv4RouteWithTagSetAccept(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeIPv4RouteWithTagSet(t, dut, ate, true)
}

func validateIPv6RouteWithTagSetReject(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeIPv6RouteWithTagSet(t, dut, ate, false)
}
func validateIPv6RouteWithTagSetAccept(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateRedistributeIPv6RouteWithTagSet(t, dut, ate, true)
}

func validateIPv4RouteWithMED(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 1000, true)
}

func validateIPv6RouteWithMED(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 1000, true)
}

func validateIPv4RouteWithASN(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv4PrefixASN(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", []uint32{64512, 65499, 65499, 65499})
}

func validateIPv6RouteWithASN(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv6PrefixASN(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", []uint32{64512, 64512})
}

func validateIPv4RouteWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv4PrefixLocalPreference(t, ate, atePort3.Name+".BGP4.peer", "192.168.10.0", 100)
}

func validateIPv6RouteWithLocalPreference(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv6PrefixLocalPreference(t, ate, atePort3.Name+".BGP6.peer", "2024:db8:128:128::", 100)
}

func validateIPv4RouteWithCommunitySet(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv4PrefixCommunitySet(t, ate, atePort3.Name+".BGP4.peer", "192.168.10.0", "64512:100")
}

func validateIPv6RouteWithCommunitySet(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	validateIPv6PrefixCommunitySet(t, ate, atePort3.Name+".BGP6.peer", "2024:db8:128:128::", "64512:100")
}

func validateRedistributeIPv4RouteWithTagSet(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, shouldBePresent bool) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicyV4 {
				found = true
			}
		}
		if len(importPolicies) == 0 || len(importPolicies) > 1 {
			t.Fatal("import policies len is not one, but it should be")
		}

		// we replaced this container so there should only be our import policy anyway
		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicyV4 {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicyV4 {
		t.Fatal("Expected import policy is not configured")
	}
	if dut.Vendor() != ondatra.NOKIA {
		if foundPDef.GetStatement(policyStatementV4).GetConditions().GetOrCreateMatchTagSet().GetTagSet() != "tag-set-v4" {
			t.Fatal("Expected tag-set is not configured")
		}
		if foundPDef.GetStatement(policyStatementV4).GetConditions().GetOrCreateMatchTagSet().GetMatchSetOptions() != oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY {
			t.Fatal("Expected match-set-option for tag-set is not configured")
		}
	}

	if shouldBePresent {
		validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, true)
	} else {
		validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, false)
	}
}

func validateRedistributeIPv6RouteWithTagSet(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice, shouldBePresent bool) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicyV6 {
				found = true
			}
		}
		if len(importPolicies) == 0 || len(importPolicies) > 1 {
			t.Fatal("import policies len is not one, but it should be")
		}

		// we replaced this container so there should only be our import policy anyway
		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicyV6 {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicyV6 {
		t.Fatal("Expected import policy is not configured")
	}
	if dut.Vendor() != ondatra.NOKIA {
		if foundPDef.GetStatement(policyStatementV6).GetConditions().GetOrCreateMatchTagSet().GetTagSet() != "tag-set-v6" {
			t.Fatal("Expected tag-set is not configured")
		}
		if foundPDef.GetStatement(policyStatementV6).GetConditions().GetOrCreateMatchTagSet().GetMatchSetOptions() != oc.RoutingPolicy_MatchSetOptionsRestrictedType_ANY {
			t.Fatal("Expected match-set-option for tag-set is not configured")
		}
	}

	if shouldBePresent {
		validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, true)
	} else {
		validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:128:128::", 0, false)
	}
}

func validateRedistributeIPv4NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV4).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicyV4 {
				found = true
			}
		}

		if len(importPolicies) == 0 || len(importPolicies) > 1 {
			t.Fatal("import policies len is not one, but it should be")
		}

		// we replaced this container so there should only be our import policy anyway
		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicyV4 {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicyV4 {
		t.Fatal("Expected import policy is not configured")
	}

	if foundPDef.GetStatement(policyStatementV4).GetActions().GetBgpActions().GetSetNextHop() != oc.UnionString("192.168.1.9") {
		t.Fatal("Expected next-hop is not configured")
	}

	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.20.0", 0, true)
}

func validateRedistributeIPv6NullStaticRoute(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {
	time.Sleep(10 * time.Second)
	if dut.Vendor() != ondatra.NOKIA {
		tcState := gnmi.Get(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).TableConnection(
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
			oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP,
			oc.Types_ADDRESS_FAMILY_IPV6).State())

		importPolicies := tcState.GetImportPolicy()
		found := false
		for _, iPolicy := range importPolicies {
			if iPolicy == redistributeStaticPolicyV6 {
				found = true
			}
		}

		if len(importPolicies) == 0 || len(importPolicies) > 1 {
			t.Fatal("import policies len is not one, but it should be")
		}

		// we replaced this container so there should only be our import policy anyway
		if !found {
			t.Fatal("expected import policy is not configured")
		}
	}

	var foundPDef oc.RoutingPolicy_PolicyDefinition
	policyDef := gnmi.GetAll(t, dut, gnmi.OC().RoutingPolicy().PolicyDefinitionAny().State())
	for _, pDef := range policyDef {
		if pDef.GetName() == redistributeStaticPolicyV6 {
			foundPDef = *pDef
		}
	}

	if foundPDef.GetName() != redistributeStaticPolicyV6 {
		t.Fatal("Expected import policy is not configured")
	}

	validateLearnedIPv6Prefix(t, ate, atePort1.Name+".BGP6.peer", "2024:db8:64:64::", 0, true)

	if foundPDef.GetStatement(policyStatementV6).GetActions().GetBgpActions().GetSetNextHop() != oc.UnionString("2001:db8::9") {
		t.Fatal("Expected next-hop is not configured")
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
		if importPolicies[0] != redistributeStaticPolicyV4 {
			t.Fatal("expected import policy is not configured")
		}
	}

	// we should no longer see these prefixes on either peering session
	validateLearnedIPv4Prefix(t, ate, atePort1.Name+".BGP4.peer", "192.168.10.0", 0, true)
}

func validateIPv4PrefixASN(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, wantASPath []uint32) {

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

func validateIPv6PrefixASN(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, wantASPath []uint32) {

	time.Sleep(10 * time.Second)
	foundPrefix := false
	prefixes := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().BgpPeer(bgpPeerName).UnicastIpv6PrefixAny().State())
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

func validateIPv6PrefixLocalPreference(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, wantLocalPreference uint32) {

	time.Sleep(10 * time.Second)
	foundPrefix := false
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
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}

}

func validateIPv4PrefixCommunitySet(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet, wantCommunitySet string) {

	time.Sleep(10 * time.Second)
	foundPrefix := false
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
				t.Fatalf("Prefix %v with unexpected Community: %v, expected: %v", prefix.GetAddress(), gotCommunitySet, wantCommunitySet)
			}
		}
	}
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}

}

func validateIPv6PrefixCommunitySet(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet, wantCommunitySet string) {

	time.Sleep(10 * time.Second)
	foundPrefix := false
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
				t.Fatalf("Prefix %v with unexpected Community: %v, expected: %v", prefix.GetAddress(), gotCommunitySet, wantCommunitySet)
			}
		}
	}
	if !foundPrefix {
		t.Fatalf("Prefix %v not present in OTG", subnet)
	}

}

func validateLearnedIPv4Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {
	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv4Prefix
	time.Sleep(10 * time.Second)

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
			t.Logf("LC: Found prefix in otg : %v with next-hop %v", prefix.GetAddress(), prefix.GetNextHopIpv4Address())
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
				found = true
				if !shouldBePresent {
					t.Fatal("redistributed v4 prefix present in otg but should not be")
				}
			}
		}
	}

	if shouldBePresent && !ok && !found {
		t.Fatal("did not see redistributed v4 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	nextHop := learnedRedistributedPrefix.GetNextHopIpv4Address()
	t.Logf("LC: Got MED and Next-Hop: %v, %v", actualMED, nextHop)
	if actualMED != expectedMED {
		t.Fatalf("ate learned redistributed prefix with med set to %d, expected %d", actualMED, expectedMED)
	}
}

func validateLearnedIPv6Prefix(t *testing.T, ate *ondatra.ATEDevice, bgpPeerName, subnet string, expectedMED uint32, shouldBePresent bool) {

	var learnedRedistributedPrefix *otgtelemetry.BgpPeer_UnicastIpv6Prefix
	time.Sleep(10 * time.Second)

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
			t.Logf("LC: Found prefix in otg : %v with next-hop %v", prefix.GetAddress(), prefix.GetNextHopIpv4Address())
			if prefix.GetAddress() == subnet {
				learnedRedistributedPrefix = prefix
				found = true
				if !shouldBePresent {
					t.Fatal("redistributed v6 prefix present in otg but should not be")
				}
			}
		}
	}

	if shouldBePresent && !ok && !found {
		t.Fatal("did not see redistributed v4 prefix in otg in time")
	}

	actualMED := learnedRedistributedPrefix.GetMultiExitDiscriminator()
	nextHop := learnedRedistributedPrefix.GetNextHopIpv4Address()
	t.Logf("LC: Got MED and Next-Hop: %v, %v", actualMED, nextHop)
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
