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
    "IPV6_FORMAT": "fc12::%02x%02x:%02x%02x/%s",
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
    }

    ipv6Format := os.Getenv("IPV6_FORMAT")
    ipv6TestStr := *convertIPv4ToIPv6(&ipv6Format, &net.IPNet{IP: net.IPv4(1,1,1,1), Mask: net.CIDRMask(24, net.IPv4len)})
    _, err = netlink.ParseIPNet(ipv6TestStr)
    if err != nil {
        logger.Error.Fatalf("IPV6_FORMAT is invalid: %s", err)
    }

    // Get the IPv4 address of the interface
    addrs, err := netlink.AddrList(netInterface, netlink.FAMILY_V4)
    if err != nil {
        logger.Error.Fatal(err)
    }
    if(len(addrs) == 0){
        logger.Error.Fatal("Interface doesnt have IPv4-Adresses")
    }

    // Add the IPv6 address to the interface
    ipv6Str := *convertIPv4ToIPv6(&ipv6Format, addrs[0].IPNet)
    ipv6, err := netlink.ParseAddr(ipv6Str)
    if err != nil {
        logger.Error.Fatal(err)
    }
    err = netlink.AddrAdd(netInterface, ipv6)
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
                if allowedIP.String()[:len(filterPrefix)] == filterPrefix {
                    // Convert the IPv4 allowed-ip to an IPv6 address
                    ipv6Str := *convertIPv4ToIPv6(&ipv6Format, &net.IPNet{IP: allowedIP.IP, Mask: allowedIP.Mask})
                    ipv6, err := netlink.ParseIPNet(ipv6Str)
                    if err != nil {
                        logger.Warn.Printf("Couldnt parse IPv6 address %s of peer %s: %s", ipv6Str, peer.PublicKey, err)
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

func convertIPv4ToIPv6(ipv6Format *string, ipv4 *net.IPNet) (*string) {
    CIDR, _ := ipv4.Mask.Size()
    // Run format
    ipv6Str := fmt.Sprintf(*ipv6Format, (*ipv4).IP[0], (*ipv4).IP[1], (*ipv4).IP[2], (*ipv4).IP[4], 128-CIDR)
    return &ipv6Str
}
