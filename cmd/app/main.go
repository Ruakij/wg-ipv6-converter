package main

import (
	"fmt"
	"net"
	"os"
	"time"

	envChecks "git.ruekov.eu/ruakij/routingtabletowg/lib/environmentchecks"
    "git.ruekov.eu/ruakij/routingtabletowg/lib/wgchecks/netchecks"
    
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
        switch {
        case os.IsExist(err):
            logger.Warn.Println("Address is already set on interface")
        default:
            logger.Error.Fatalf("Failed to set address on interface: %v", err)
        }
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
        wgConfig.Peers = make([]wgtypes.PeerConfig, 0, len(wgDevice.Peers))

        for _, peer := range wgDevice.Peers {
            // Create slice for 1 expected addition
            var addAllowedIPs = make([]net.IPNet, 0, 1)

            // Loop through the allowed-ips and add the ones starting with 100.100
            for _, allowedIP := range peer.AllowedIPs {
                if allowedIP.String()[:7] == "100.100" {
                    // Convert the IPv4 allowed-ip to an IPv6 address
                    ipv6Suffix := fmt.Sprintf("%02x%02x", allowedIP.IP[2], allowedIP.IP[3])
                    ipv6Address := ipv6Prefix + ipv6Suffix + "/128"
                    ipv6, err := netlink.ParseIPNet(ipv6Address)
                    if err != nil {
                        logger.Warn.Printf("Couldnt parse IPv6 address %s of peer %s: %s", ipv6Address, peer.PublicKey, err)
                        continue
                    }
                    
                    // Check if already set
                    if i, _ := netchecks.IPNetIndexByIPNet(&peer.AllowedIPs, ipv6); i != -1 {
                        continue
                    }

                    // Add the IPv6 allowed-ip to the peer
                    addAllowedIPs = append(addAllowedIPs, *ipv6)
                }
            }

            if(len(addAllowedIPs) > 0){
                // Create peer-config
                peerConfig := wgtypes.PeerConfig{
                    PublicKey: peer.PublicKey,
                    AllowedIPs: append(peer.AllowedIPs, addAllowedIPs...),
                }

                // Add entry
                wgConfig.Peers = append(wgConfig.Peers, peerConfig)
            }
        }

        if(len(wgConfig.Peers) == 0){
            logger.Info.Println("No changes, skipping")
        } else {
            err = client.ConfigureDevice(iface, wgConfig)
            if(err != nil){
                logger.Error.Fatalf("Error configuring wg-device '%s': %s", iface, err)
            }
        }
        
        // Sleep for 300 seconds before running the loop again
        time.Sleep(time.Second * 300)
    }
}
