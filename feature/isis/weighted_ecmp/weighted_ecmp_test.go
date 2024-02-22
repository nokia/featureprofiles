package weighted_ecmp_test

import (
	"fmt"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/netutil"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

const (
	ipv4PrefixLen     = 30
	ipv6PrefixLen     = 126
	subInterfaceIndex = 0
	isisName          = "DEFAULT"
	asNumber          = 65535
)

var (
	dutIPv4Loopback = "192.0.255.1"
	dutIPv6Loopback = "2001:db8:255::1"

	ateLoopback0Mac  = "00:12:00:00:00:00"
	ateLoopback1Mac  = "00:12:00:00:00:01"
	ateIPv4Loopback0 = "192.0.255.100"
	ateIPv4Loopback1 = "192.0.255.101"
	ateIPv6Loopback0 = "2001:db8:255::100"
	ateIPv6Loopback1 = "2001:db8:255::101"

	flowCount = 100
	flowMbps  = 100

	dutLAG1 = &attrs.Attributes{
		Name:    "dutLAG1",
		MAC:     "00:12:01:01:01:01",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::1",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	dutLAG2 = &attrs.Attributes{
		Name:    "dutLAG2",
		MAC:     "00:12:02:01:01:01",
		IPv4:    "192.0.2.5",
		IPv6:    "2001:db8::5",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	dutLAG3 = &attrs.Attributes{
		Name:    "dutLAG3",
		MAC:     "00:12:03:01:01:01",
		IPv4:    "192.0.2.9",
		IPv6:    "2001:db8::9",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	dutLAG4 = &attrs.Attributes{
		Name:    "dutLAG4",
		MAC:     "00:12:04:01:01:01",
		IPv4:    "192.0.2.13",
		IPv6:    "2001:db8::13",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	ateLAG1 = &attrs.Attributes{
		Name:    "ateLAG1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8::2",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	ateLAG2 = &attrs.Attributes{
		Name:    "ateLAG2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv6:    "2001:db8::6",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	ateLAG3 = &attrs.Attributes{
		Name:    "ateLAG3",
		MAC:     "02:00:03:01:01:01",
		IPv4:    "192.0.2.10",
		IPv6:    "2001:db8::10",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}

	ateLAG4 = &attrs.Attributes{
		Name:    "ateLAG4",
		MAC:     "02:00:04:01:01:01",
		IPv4:    "192.0.2.14",
		IPv6:    "2001:db8::14",
		IPv4Len: ipv4PrefixLen,
		IPv6Len: ipv6PrefixLen,
	}
)

func getNextLoopbackInterfaceName(t *testing.T, dut *ondatra.DUTDevice) string {
	t.Helper()

	var existingLoopbackNames []string

	allInterfaces := gnmi.GetAll(t, dut, gnmi.OC().InterfaceAny().State())
	for _, intf := range allInterfaces {
		if intf.GetType() != oc.IETFInterfaces_InterfaceType_softwareLoopback {
			continue
		}

		existingLoopbackNames = append(existingLoopbackNames, intf.GetName())
	}

	var idx int

	for {
		proposedName := netutil.LoopbackInterface(t, dut, idx)

		var found bool

		for _, existingName := range existingLoopbackNames {
			if proposedName == existingName {
				found = true

				break
			}
		}

		if !found {
			return proposedName
		}

		idx++
	}
}

func configureDUTLoopbacks(t *testing.T, dut *ondatra.DUTDevice) {
	newLoopbackName := getNextLoopbackInterfaceName(t, dut)

	ocRoot := &oc.Root{}

	loopbackIntf := ocRoot.GetOrCreateInterface(newLoopbackName)
	loopbackIntf.SetType(oc.IETFInterfaces_InterfaceType_softwareLoopback)
	loopbackIntf.SetDescription("fptesting")
	loopbackIntf.SetEnabled(true)

	loopbackSubIntf := loopbackIntf.GetOrCreateSubinterface(subInterfaceIndex)

	loopbackSubIntfIpv4 := loopbackSubIntf.GetOrCreateIpv4()
	loopbackSubIntfIpv4Addr := loopbackSubIntfIpv4.GetOrCreateAddress(dutIPv4Loopback)
	loopbackSubIntfIpv4Addr.SetPrefixLength(32)

	loopbackSubIntfIpv6 := loopbackSubIntf.GetOrCreateIpv6()
	loopbackSubIntfIpv6Addr := loopbackSubIntfIpv6.GetOrCreateAddress(dutIPv6Loopback)
	loopbackSubIntfIpv6Addr.SetPrefixLength(128)

	if deviations.InterfaceEnabled(dut) {
		loopbackSubIntfIpv4.SetEnabled(true)
		loopbackSubIntfIpv6.SetEnabled(true)
	}

	gnmi.Replace(t, dut, gnmi.OC().Interface(newLoopbackName).Config(), loopbackIntf)

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(
			t, dut, newLoopbackName, deviations.DefaultNetworkInstance(dut), subInterfaceIndex,
		)
	}
}

func configureDUTBundle(
	t *testing.T, dut *ondatra.DUTDevice, lag *attrs.Attributes, bundleMembers []*ondatra.Port,
) string {
	bundleID := netutil.NextAggregateInterface(t, dut)

	gnmiOCRoot := gnmi.OC()
	ocRoot := &oc.Root{}

	if deviations.AggregateAtomicUpdate(dut) {
		bundle := ocRoot.GetOrCreateInterface(bundleID)
		bundle.GetOrCreateAggregation()
		bundle.Type = oc.IETFInterfaces_InterfaceType_ieee8023adLag

		for _, port := range bundleMembers {
			intf := ocRoot.GetOrCreateInterface(port.Name())
			intf.GetOrCreateEthernet().AggregateId = ygot.String(bundleID)
			intf.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd

			if deviations.InterfaceEnabled(dut) {
				intf.Enabled = ygot.Bool(true)
			}

			if deviations.ExplicitPortSpeed(dut) {
				intf.Ethernet.SetPortSpeed(fptest.GetIfSpeed(t, port))
			}
		}

		gnmi.Update(
			t,
			dut,
			gnmiOCRoot.Config(),
			ocRoot,
		)
	}

	lacp := &oc.Lacp_Interface{
		Name:     ygot.String(bundleID),
		LacpMode: oc.Lacp_LacpActivityType_UNSET,
	}
	lacpPath := gnmiOCRoot.Lacp().Interface(bundleID)
	gnmi.Replace(t, dut, lacpPath.Config(), lacp)

	agg := &oc.Interface{
		Name: ygot.String(bundleID),
		Type: oc.IETFInterfaces_InterfaceType_ieee8023adLag,
	}
	agg.Description = ygot.String(fmt.Sprintf("dutLag-%s", bundleID))
	if deviations.InterfaceEnabled(dut) {
		agg.Enabled = ygot.Bool(true)
	}

	subInterface := agg.GetOrCreateSubinterface(subInterfaceIndex)
	v4SubInterface := subInterface.GetOrCreateIpv4()
	if deviations.InterfaceEnabled(dut) {
		v4SubInterface.Enabled = ygot.Bool(true)
	}
	v4Address := v4SubInterface.GetOrCreateAddress(lag.IPv4)
	v4Address.PrefixLength = ygot.Uint8(ipv4PrefixLen)

	v6SubInterface := subInterface.GetOrCreateIpv6()
	if deviations.InterfaceEnabled(dut) {
		v6SubInterface.Enabled = ygot.Bool(true)
	}
	v6Address := v6SubInterface.GetOrCreateAddress(lag.IPv6)
	v6Address.PrefixLength = ygot.Uint8(ipv6PrefixLen)

	intfAgg := agg.GetOrCreateAggregation()
	intfAgg.LagType = oc.IfAggregate_AggregationType_STATIC

	aggPath := gnmiOCRoot.Interface(bundleID)
	gnmi.Replace(t, dut, aggPath.Config(), agg)

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(
			t, dut, bundleID, deviations.DefaultNetworkInstance(dut), subInterfaceIndex,
		)
	}

	// if we didnt setup the ports in the lag before
	if !deviations.AggregateAtomicUpdate(dut) {
		for _, port := range bundleMembers {
			intf := &oc.Interface{Name: ygot.String(port.Name())}
			intf.GetOrCreateEthernet().AggregateId = ygot.String(bundleID)
			intf.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd

			if deviations.InterfaceEnabled(dut) {
				intf.Enabled = ygot.Bool(true)
			}

			if deviations.ExplicitPortSpeed(dut) {
				fptest.SetPortSpeed(t, port)
			}

			intfPath := gnmiOCRoot.Interface(port.Name())

			gnmi.Replace(t, dut, intfPath.Config(), intf)
		}
	}

	return bundleID
}

func configureDUTBundles(t *testing.T, dut *ondatra.DUTDevice, allDutPorts []*ondatra.Port, bundleMemberCount int) []string {
	lagOneDutBundleMembers := allDutPorts[0:bundleMemberCount]
	lagTwoDutBundleMembers := allDutPorts[bundleMemberCount : 2*bundleMemberCount]
	lagThreeDutBundleMembers := allDutPorts[2*bundleMemberCount : (2*bundleMemberCount)+bundleMemberCount]
	lagFourDutBundleMembers := allDutPorts[3*bundleMemberCount : (3*bundleMemberCount)+bundleMemberCount]

	var allDutBundleMembers []*ondatra.Port
	allDutBundleMembers = append(allDutBundleMembers, lagOneDutBundleMembers...)
	allDutBundleMembers = append(allDutBundleMembers, lagTwoDutBundleMembers...)
	allDutBundleMembers = append(allDutBundleMembers, lagThreeDutBundleMembers...)
	allDutBundleMembers = append(allDutBundleMembers, lagFourDutBundleMembers...)

	return []string{
		configureDUTBundle(t, dut, dutLAG1, lagOneDutBundleMembers),
		configureDUTBundle(t, dut, dutLAG2, lagTwoDutBundleMembers),
		configureDUTBundle(t, dut, dutLAG3, lagThreeDutBundleMembers),
		configureDUTBundle(t, dut, dutLAG4, lagFourDutBundleMembers),
	}
}

func configureDUTISIS(t *testing.T, dut *ondatra.DUTDevice, bundleIDs []string) {
	ocRoot := &oc.Root{}

	networkInstance := ocRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

	isisProtocol := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_ISIS, isisName)
	isisProtocol.Enabled = ygot.Bool(true)

	isis := isisProtocol.GetOrCreateIsis()

	isisGlobal := isis.GetOrCreateGlobal()
	isisGlobal.SetMaxEcmpPaths(4) // just really need it to be "3" but... 4 feels nicer
	if deviations.ISISInstanceEnabledRequired(dut) {
		isisGlobal.Instance = ygot.String(isisName)
	}
	isisGlobal.Net = []string{"49.0001.1920.0000.2001.00"}
	isisGlobal.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV4, oc.IsisTypes_SAFI_TYPE_UNICAST).Enabled = ygot.Bool(true)
	isisGlobal.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV6, oc.IsisTypes_SAFI_TYPE_UNICAST).Enabled = ygot.Bool(true)
	isisGlobal.LevelCapability = oc.Isis_LevelType_LEVEL_2

	// TODO do we actually not support this? was told we *do*?; seems like not in oc so we need
	//  deviation for this i guess so we can do it in native
	//isisGlobal.SetWeightedEcmp(true)

	level := isis.GetOrCreateLevel(2)
	level.MetricStyle = oc.Isis_MetricStyle_WIDE_METRIC
	// Configure ISIS enabled flag at level
	if deviations.ISISLevelEnabled(dut) {
		level.Enabled = ygot.Bool(true)
	}

	for _, interfaceName := range bundleIDs {
		intf := isis.GetOrCreateInterface(interfaceName)

		// TODO see above comment on wecmp bits
		//intf.GetOrCreateWeightedEcmp().SetLoadBalancingWeight(oc.WeightedEcmp_LoadBalancingWeight_auto)

		intf.CircuitType = oc.Isis_CircuitType_POINT_TO_POINT
		intf.Enabled = ygot.Bool(true)
		// Configure ISIS level at global mode if true else at interface mode
		if deviations.ISISInterfaceLevel1DisableRequired(dut) {
			intf.GetOrCreateLevel(1).Enabled = ygot.Bool(false)
		} else {
			intf.GetOrCreateLevel(2).Enabled = ygot.Bool(true)
		}

		// Configure ISIS enable flag at interface level
		intf.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV4, oc.IsisTypes_SAFI_TYPE_UNICAST).Enabled = ygot.Bool(true)
		intf.GetOrCreateAf(oc.IsisTypes_AFI_TYPE_IPV6, oc.IsisTypes_SAFI_TYPE_UNICAST).Enabled = ygot.Bool(true)
		if deviations.ISISInterfaceAfiUnsupported(dut) {
			intf.Af = nil
		}

		intfRef := intf.GetOrCreateInterfaceRef()
		intfRef.SetInterface(interfaceName)
		intfRef.SetSubinterface(subInterfaceIndex)
	}

	gnmi.Update(t, dut, gnmi.OC().Config(), ocRoot)
}

func configureDUTBGP(t *testing.T, dut *ondatra.DUTDevice) {
	ocRoot := &oc.Root{}

	networkInstance := ocRoot.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))

	bgpProtocol := networkInstance.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := bgpProtocol.GetOrCreateBgp()

	global := bgp.GetOrCreateGlobal()
	global.RouterId = ygot.String(dutLAG1.IPv4)
	global.As = ygot.Uint32(asNumber)
	global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(true)
	global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST).Enabled = ygot.Bool(true)

	// Note: we have to define the peer group even if we aren't setting any policy because it's
	// invalid OC for the neighbor to be part of a peer group that doesn't exist.
	bgpPeerGroup := bgp.GetOrCreatePeerGroup("peerGroup")
	bgpPeerGroup.PeerAs = ygot.Uint32(asNumber)

	// "a" side neighbor (to ate lag1/loopback0)
	atePeerLoopback0 := bgp.GetOrCreateNeighbor(ateIPv4Loopback0)
	atePeerLoopback0.SetPeerGroup("peerGroup")
	atePeerLoopback0.SetEnabled(true)
	atePeerLoopback0.SetPeerAs(asNumber)
	atePeerLoopback0Transport := atePeerLoopback0.GetOrCreateTransport()
	atePeerLoopback0Transport.SetLocalAddress(dutIPv4Loopback)
	atePeerLoopback0V4 := atePeerLoopback0.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	atePeerLoopback0V4.SetEnabled(true)
	atePeerLoopback0V6 := atePeerLoopback0.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	atePeerLoopback0V6.SetEnabled(true)

	// "b" side neighbor (over lags2/3/4)
	atePeerLoopback1 := bgp.GetOrCreateNeighbor(ateIPv4Loopback1)
	atePeerLoopback1.SetPeerGroup("peerGroup")
	atePeerLoopback1.SetEnabled(true)
	atePeerLoopback1.SetPeerAs(asNumber)
	atePeerLoopback1Transport := atePeerLoopback1.GetOrCreateTransport()
	atePeerLoopback1Transport.SetLocalAddress(dutIPv4Loopback)
	atePeerLoopback1V4 := atePeerLoopback0.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	atePeerLoopback1V4.SetEnabled(true)
	atePeerLoopback1V6 := atePeerLoopback0.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	atePeerLoopback1V6.SetEnabled(true)

	gnmi.Update(t, dut, gnmi.OC().Config(), ocRoot)
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice, allDutPorts []*ondatra.Port, bundleMemberCount int) {
	configureDUTLoopbacks(t, dut)
	bundleIDs := configureDUTBundles(t, dut, allDutPorts, bundleMemberCount)
	configureDUTISIS(t, dut, bundleIDs)
	configureDUTBGP(t, dut)
}

func configureATELoopbacks(otgConfig gosnappi.Config) {
	loopback0Dev := otgConfig.Devices().Add().SetName("lo0-dev")
	loopback0Dev.Ethernets().Add().SetName("lo0-dev.Eth").SetMac(ateLoopback0Mac).Connection().SetLagName(ateLAG1.Name)
	loopback0 := loopback0Dev.Ipv4Loopbacks().Add().SetName("lo0-ipv4")
	loopback0.SetEthName("lo0-dev.Eth")
	loopback0.SetAddress(ateIPv4Loopback0)
	loopback10 := loopback0Dev.Ipv6Loopbacks().Add().SetName("lo0-ipv6")
	loopback10.SetAddress(ateIPv6Loopback0)
	loopback10.SetEthName("lo0-dev.Eth")

	loopback1Dev := otgConfig.Devices().Add().SetName("lo1-dev")
	loopback1Dev.Ethernets().Add().SetName("lo1-dev.Eth").SetMac(ateLoopback1Mac).Connection().SetLagName(ateLAG1.Name)
	loopback1 := loopback1Dev.Ipv4Loopbacks().Add().SetName("lo1-ipv4")
	loopback1.SetEthName("lo1-dev.Eth")
	loopback1.SetAddress(ateIPv4Loopback1)
	loopback11 := loopback1Dev.Ipv6Loopbacks().Add().SetName("lo1-ipv6")
	loopback11.SetEthName("lo1-dev.Eth")
	loopback11.SetAddress(ateIPv6Loopback1)
}

func configureATEBundle(
	otgConfig gosnappi.Config,
	ateLag *attrs.Attributes,
	dutLag *attrs.Attributes,
	bundleMembers []*ondatra.Port,
	bundleID uint32,
) {
	agg := otgConfig.Lags().Add().SetName(ateLag.Name)
	agg.Protocol().Static().SetLagId(bundleID)

	for idx, port := range bundleMembers {
		_ = otgConfig.Ports().Add().SetName(port.ID())
		agg.Ports().
			Add().
			SetPortName(port.ID()).
			Ethernet().
			// wont have more than 8 members, so no need to be fancy
			SetMac(fmt.Sprintf("%s0%d", ateLag.MAC[:len(ateLag.MAC)-2], idx+2)).
			SetName("LAG-" + port.ID())
	}

	aggDev := otgConfig.Devices().Add().SetName(agg.Name() + ".dev")
	aggEth := aggDev.Ethernets().
		Add().
		SetName(fmt.Sprintf("%s.Eth", ateLag.Name)).
		SetMac(ateLag.MAC)
	aggEth.Connection().SetLagName(agg.Name())

	aggEth.Ipv4Addresses().Add().SetName(fmt.Sprintf("%s.IPv4", ateLag.Name)).
		SetAddress(ateLag.IPv4).
		SetGateway(dutLag.IPv4).
		SetPrefix(ipv4PrefixLen)

	aggEth.Ipv6Addresses().Add().SetName(fmt.Sprintf("%s.IPv6", ateLag.Name)).
		SetAddress(ateLag.IPv6).
		SetGateway(dutLag.IPv6).
		SetPrefix(ipv6PrefixLen)
}

func configureATEBundles(
	otgConfig gosnappi.Config,
	allAtePorts []*ondatra.Port,
	bundleMemberCount int,
) gosnappi.Config {
	configureATEBundle(
		otgConfig,
		ateLAG1,
		dutLAG1,
		allAtePorts[0:bundleMemberCount],
		1,
	)
	configureATEBundle(
		otgConfig,
		ateLAG2,
		dutLAG2,
		allAtePorts[bundleMemberCount:2*bundleMemberCount],
		2,
	)
	configureATEBundle(
		otgConfig,
		ateLAG3,
		dutLAG3,
		allAtePorts[2*bundleMemberCount:(2*bundleMemberCount)+bundleMemberCount],
		3,
	)
	configureATEBundle(
		otgConfig,
		ateLAG4,
		dutLAG4,
		allAtePorts[3*bundleMemberCount:(3*bundleMemberCount)+bundleMemberCount],
		4,
	)

	portNames := make([]string, len(allAtePorts))
	for idx, port := range allAtePorts {
		portNames[idx] = port.ID()
	}

	layer1 := otgConfig.Layer1().Add().
		SetName("layerOne").
		SetPortNames(portNames)

	// set the l1 speed for the otg config based on speed setting in testbed, fallthrough case is
	// do nothing which defaults to 10g
	switch allAtePorts[0].Speed() {
	case ondatra.Speed1Gb:
		layer1.SetSpeed(gosnappi.Layer1Speed.SPEED_1_GBPS)
	case ondatra.Speed10Gb:
		layer1.SetSpeed(gosnappi.Layer1Speed.SPEED_10_GBPS)
	case ondatra.Speed100Gb:
		layer1.SetSpeed(gosnappi.Layer1Speed.SPEED_100_GBPS)
	case ondatra.Speed400Gb:
		layer1.SetSpeed(gosnappi.Layer1Speed.SPEED_400_GBPS)
	default:
	}

	return otgConfig
}

func configureATEISIS(otgConfig gosnappi.Config) {
	for idx, dev := range otgConfig.Devices().Items() {
		if !strings.HasPrefix(dev.Name(), "ateLAG") {
			// skip the non lag interfaces (loopbacks)
			continue
		}

		devIsis := dev.Isis().SetSystemId(fmt.Sprintf("64000000000%d", idx+1)).SetName(fmt.Sprintf("%s-isis", dev.Name()))

		devIsis.Basic().SetHostname(devIsis.Name()).SetLearnedLspFilter(true)

		devIsis.Advanced().
			SetAreaAddresses([]string{strings.Replace("49.0002", ".", "", -1)})

		devIsisInt := devIsis.Interfaces().
			Add().
			SetEthName(dev.Ethernets().Items()[0].Name()).
			SetName(fmt.Sprintf("%s-isis", dev.Name())).
			SetNetworkType(gosnappi.IsisInterfaceNetworkType.POINT_TO_POINT).
			SetLevelType(gosnappi.IsisInterfaceLevelType.LEVEL_2).
			SetMetric(10)

		devIsisInt.Advanced().
			SetAutoAdjustMtu(true).SetAutoAdjustArea(true).SetAutoAdjustSupportedProtocols(true)

		if strings.HasPrefix(dev.Name(), ateLAG1.Name) {
			// advertise our lo0 out lag1
			lo0V4 := devIsis.V4Routes().Add().SetName("isis-lag1-lo0-v4")
			lo0V4.Addresses().Add().SetAddress(ateIPv4Loopback0).SetPrefix(32)

			lo0V6 := devIsis.V6Routes().Add().SetName("isis-lag1-lo0-v6")
			lo0V6.Addresses().Add().SetAddress(ateIPv6Loopback0).SetPrefix(128)
		} else {
			// otherwise advertise lo0 out all the other lags
			lo0V4 := devIsis.V4Routes().Add().SetName(fmt.Sprintf("isis-%s-lo1-v4", dev.Name()))
			lo0V4.Addresses().Add().SetAddress(ateIPv4Loopback1).SetPrefix(32)

			lo0V6 := devIsis.V6Routes().Add().SetName(fmt.Sprintf("isis-%s-lo1-v6", dev.Name()))
			lo0V6.Addresses().Add().SetAddress(ateIPv6Loopback1).SetPrefix(128)
		}
	}
}

func configureATEBGP(
	otgConfig gosnappi.Config,
) {
	for _, dev := range otgConfig.Devices().Items() {
		fmt.Println("NAME ->", dev.Name())
		if dev.Name() == "lo0-dev" {
			// "a" side peering to dut (so lag1->dut basically, "b" being the lag2/3/4->dut side)
			ateToDutBGP1 := dev.Bgp().SetRouterId(ateIPv4Loopback0)
			ateToDutBGPPeer1 := ateToDutBGP1.Ipv4Interfaces().Add().SetIpv4Name("lo0-ipv4").Peers().Add().SetName("bgp-lag1.BGP4.peer")
			ateToDutBGPPeer1.SetPeerAddress(dutIPv4Loopback).SetAsNumber(asNumber).SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
			ateToDutBGPPeer1.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
			ateToDutBGPPeer1.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

			ateToDutBGPPeer1Route := ateToDutBGPPeer1.V4Routes().Add().SetName("a-side-prefix")
			ateToDutBGPPeer1Route.SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4)
			ateToDutBGPPeer1Route.SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
			ateToDutBGPPeer1Route.SetNextHopIpv4Address(dev.Ipv4Loopbacks().Items()[0].Address())
			ateToDutBGPPeer1Route.Addresses().Add().SetAddress("100.0.1.0").SetPrefix(24)
			// TODO -- this part looks "ok" but not sure cuz cant test yet (keysight issue)... do
			//  we need to make an actual loopback w/ this address or is just advertising it ok?
		} else if dev.Name() == "lo1-dev" {
			ateToDutBGP2 := dev.Bgp().SetRouterId(ateIPv4Loopback1)
			ateToDutBGPPeer2 := ateToDutBGP2.Ipv4Interfaces().Add().SetIpv4Name("lo1-ipv4").Peers().Add().SetName("bgp-lag2.BGP4.peer")
			ateToDutBGPPeer2.SetPeerAddress(dutIPv4Loopback).SetAsNumber(asNumber).SetAsType(gosnappi.BgpV4PeerAsType.IBGP)
			ateToDutBGPPeer2.Capability().SetIpv4UnicastAddPath(true).SetIpv6UnicastAddPath(true)
			ateToDutBGPPeer2.LearnedInformationFilter().SetUnicastIpv4Prefix(true).SetUnicastIpv6Prefix(true)

			ateToDutBGPPeer2Route := ateToDutBGPPeer2.V4Routes().Add().SetName("b-side-prefix")
			ateToDutBGPPeer2Route.SetNextHopAddressType(gosnappi.BgpV4RouteRangeNextHopAddressType.IPV4)
			ateToDutBGPPeer2Route.SetNextHopMode(gosnappi.BgpV4RouteRangeNextHopMode.MANUAL)
			ateToDutBGPPeer2Route.SetNextHopIpv4Address(dev.Ipv4Loopbacks().Items()[0].Address())
			ateToDutBGPPeer2Route.Addresses().Add().SetAddress("100.0.2.0").SetPrefix(24)
		}
	}
}

func configureATE(
	allAtePorts []*ondatra.Port,
	bundleMemberCount int,
) gosnappi.Config {
	otgConfig := gosnappi.NewConfig()

	configureATELoopbacks(otgConfig)
	configureATEBundles(otgConfig, allAtePorts, bundleMemberCount)
	configureATEISIS(otgConfig)
	configureATEBGP(otgConfig)

	return otgConfig
}

func createFlows(otgConfig gosnappi.Config) {
	// TODO placeholder till doin v6 stuff
	ipv := "IPv4"

	var rxNames []string
	for _, rxLag := range []*attrs.Attributes{ateLAG2, ateLAG3, ateLAG4} {
		rxNames = append(rxNames, rxLag.Name+".BGP4.peer.rr4") // TODO naem this sane, just copy/pasta for now :)
	}

	for flowID := 0; flowID < flowCount; flowID++ {
		flow := gosnappi.NewFlow().SetName(fmt.Sprintf("flow-%d", flowID))
		flow.Metrics().SetEnable(true)
		flow.TxRx().Device().
			SetTxNames([]string{fmt.Sprintf("%s.%s", ateLAG1.Name, ipv)}).
			SetRxNames(rxNames)
		flow.Size().SetFixed(1_000)
		flow.Rate().SetMbps(uint64(flowMbps))

		// TODO do for v6 too duh

		// test calls
		v4 := flow.Packet().Add().Ipv4()
		v4.Src().SetValue("100.0.1.1")
		v4.Dst().SetValue("100.0.2.1")

		otgConfig.Flows().Append(flow)
	}
}

// sortPorts sorts the ports by the testbed port ID.
func sortPorts(ports []*ondatra.Port) []*ondatra.Port {
	sort.SliceStable(ports, func(i, j int) bool {
		return ports[i].ID() < ports[j].ID()
	})
	return ports
}

func verifyDUTBGPEstablished(t *testing.T, dut *ondatra.DUTDevice) {
	dni := deviations.DefaultNetworkInstance(dut)
	nSessionState := gnmi.OC().NetworkInstance(dni).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().NeighborAny().SessionState().State()
	watch := gnmi.WatchAll(t, dut, nSessionState, 2*time.Minute, func(val *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]) bool {
		state, ok := val.Val()
		if !ok || state != oc.Bgp_Neighbor_SessionState_ESTABLISHED {
			return false
		}
		return true
	})
	if val, ok := watch.Await(t); !ok {
		t.Fatalf("BGP sessions not established: got %v", val)
	}
	t.Log("DUT BGP sessions established")
}

func TestEqualDistribution(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()

	allDutPorts := sortPorts(dut.Ports())
	allAtePorts := sortPorts(ate.Ports())

	if len(allDutPorts) < 4 {
		t.Fatalf("testbed requires at least four dut ports, but only has %d", len(allDutPorts))
	}

	if len(allAtePorts) < 4 {
		t.Fatalf("testbed requires at least four ate ports, but only has %d", len(allAtePorts))
	}

	bundleMemberCount := 1
	if len(allDutPorts) >= 8 && len(allAtePorts) >= 8 {
		bundleMemberCount = 2
	}

	configureDUT(t, dut, allDutPorts, bundleMemberCount)

	otgConfig := configureATE(allAtePorts, bundleMemberCount)

	otg.PushConfig(t, otgConfig)
	otg.StartProtocols(t)

	verifyDUTBGPEstablished(t, dut)

	otg.StartTraffic(t)
	// TODO they want 20gb but do we care if we can just check that its weighted the right way?
	//  seems easier and more useful/realistic to just do a minute or w/e of flow and then check
	//  results
	time.Sleep(time.Minute)
	otg.StopTraffic(t)

	otg.StopProtocols(t)

	otgutils.LogFlowMetrics(t, otg, otgConfig)
}

func TestUnequalDistribution(t *testing.T) {
	// TODO of course
}
