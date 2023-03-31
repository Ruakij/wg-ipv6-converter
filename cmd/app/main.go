package main

import (
	"fmt"
	"net"
	"os"
	"time"

	envChecks "git.ruekov.eu/ruakij/routingtabletowg/lib/environmentchecks"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var envRequired = []string{
	"INTERFACE",
}
var envDefaults = map[string]string{
	"IPV6_PREFIX": "fd00::",
}

func main() {
	// Environment-vars
	err := envChecks.HandleRequired(envRequired)
	if(err != nil){
		logger.Error.Fatal(err)
	}
	envChecks.HandleDefaults(envDefaults)

    // Get the network interface object
	iface := os.Getenv("INTERFACE")
    netInterface, err := netlink.LinkByName(iface)
    if err != nil {
        logger.Error.Fatal(err)
        return
    }

    // Get the IPv4 address of the interface	
    addrs, err := netlink.AddrList(netInterface, netlink.FAMILY_V4)
    if err != nil {
        logger.Error.Fatal(err)
    }
	if(len(addrs) == 0){
		logger.Error.Fatal("Interface doesnt have IPv4-Adresses")
	}
    ipv4Addr := addrs[0].IP.String()

    // Convert the IPv4 address to an IPv6 address
    ipv6Prefix := "fd20::"
    ipv6Suffix := fmt.Sprintf("%02x%02x", ipv4Addr[12], ipv4Addr[13])
    ipv6AddrStr := ipv6Prefix + ipv6Suffix + "/112"

    // Add the IPv6 address to the interface
    ipv6Addr, err := netlink.ParseAddr(ipv6AddrStr)
    if err != nil {
        logger.Error.Fatal(err)
    }
    err = netlink.AddrAdd(netInterface, ipv6Addr)
    if err != nil {
        logger.Error.Fatal(err)
    }

    // Create a WireGuard client
    client, err := wgctrl.New()
    if err != nil {
        logger.Error.Fatal(err)
    }
    defer client.Close()

    // Loop indefinitely
    for {
        // Get the WireGuard peers on the interface
        wgDevice, err := client.Device(iface)
        if err != nil {
            logger.Error.Fatalf("getting WireGuard device from interface '%s' failed: %s", iface, err)
        }

		var wgConfig wgtypes.Config
        wgConfig.Peers = make([]wgtypes.PeerConfig, len(wgDevice.Peers))

        for _, peer := range wgDevice.Peers {
            // Create slice with initial size of 2xAllowedIPs as the max we expect
            var allowedIPs = make([]net.IPNet, len(peer.AllowedIPs)*2)
            // Copy in all old entries
            copy(allowedIPs, peer.AllowedIPs)

            // Loop through the allowed-ips and add the ones starting with 100.100
            for _, allowedIP := range peer.AllowedIPs {
                if allowedIP.String()[:7] == "100.100" {
                    // Convert the IPv4 allowed-ip to an IPv6 address
                    ipv6Suffix := fmt.Sprintf("%02x%02x", allowedIP.IP[2], allowedIP.IP[3])
                    ipv6Address := ipv6Prefix + ipv6Suffix + "/128"
                    ipv6, err := netlink.ParseAddr(ipv6Address)
                    if err != nil {
                        logger.Warn.Printf("Couldnt parse IPv6 address %s of peer %s: %s", ipv6Address, peer.PublicKey, err)
                        continue
                    }

                    // Add the IPv6 allowed-ip to the peer
                    allowedIPs = append(allowedIPs, *ipv6.IPNet)
                }
            }

            wgConfig.Peers = append(wgConfig.Peers, wgtypes.PeerConfig{AllowedIPs: allowedIPs})
        }

        err = client.ConfigureDevice(iface, wgConfig)
		if(err != nil){
			logger.Error.Fatalf("Error configuring wg-device '%s': %s", iface, err)
		}

        // Sleep for 300 seconds before running the loop again
        time.Sleep(time.Second * 300)
    }
}
