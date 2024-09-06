package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Read config file and generate mDNS forwarding maps
	receiveIfArg := flag.String("receiveInterface", "", "Interface to receive mDNS packets")
	sendIfArg := flag.String("sendInterfaces", "", "Comma-separated list of interfaces to send mDNS packets")

	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	flag.Parse()

	if len(*receiveIfArg) == 0 || len(*sendIfArg) == 0 {
		fmt.Println("Usage: main.go -receiveIfArg <interface> -sendIfArg <interface1,interface2,...>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Split the comma-separated list into individual interfaces
	sendIfs := strings.Split(*sendIfArg, ",")

	// Get a handle on the receivng network interface
	receiver, err := pcap.OpenLive(*receiveIfArg, 65536, true, time.Second)
	log.Printf("Receiving mDNS packets on interface: %v", *receiveIfArg)
	if err != nil {
		log.Fatalf("Could not find network interface: %v", *receiveIfArg)
	}

	// Get a handle on the sending network interfaces
	senders := []*pcap.Handle{}
	for _, sendIf := range sendIfs {
		sender, err := pcap.OpenLive(sendIf, 65536, true, time.Second)
		if err != nil {
			log.Fatalf("Could not find network interface: %v", sendIf)
		}
		senders = append(senders, sender)
		log.Printf("Sending mDNS packets on interface: %v", sendIf)
	}

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	// Get a handle on the network interface

	// // Get the local MAC address, to filter out Bonjour packet generated locally
	// intf, err := net.InterfaceByName(cfg.NetInterface)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// brMACAddress := intf.HardwareAddr

	// Filter mDNS traffic
	filter := "dst net (224.0.0.251 or ff02::fb) and udp dst port 5353"
	err = receiver.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(receiver, decoder)
	bonjourPackets := parsePacketsLazily(source)

	// Process Bonjours packets
	for bonjourPacket := range bonjourPackets {
		//fmt.Println(bonjourPacket.packet.Dump())

		// Assuming bonjourPacket and packet are already defined and initialized
		applicationLayer := bonjourPacket.packet.ApplicationLayer()
		if applicationLayer != nil {

			// Decode the payload as DNS
			packet := gopacket.NewPacket(applicationLayer.Payload(), layers.LayerTypeDNS, gopacket.Default)
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				fmt.Println("DNS Packet:")
				fmt.Printf("ID: %d\n", dns.ID)
				fmt.Printf("Questions: %d\n", dns.QDCount)
				fmt.Printf("Answers: %d\n", dns.ANCount)
				for _, question := range dns.Questions {
					fmt.Printf("Question: %s\n", string(question.Name))
				}

				// Filter out AAAA records from Answers, Authorities, and Additionals
				dns.Answers = filterOutLinkLocalAAAAAndPTR(dns.Answers)
				dns.Authorities = filterOutLinkLocalAAAAAndPTR(dns.Authorities)
				dns.Additionals = filterOutLinkLocalAAAAAndPTR(dns.Additionals)

				// Filter out records with Type = Unknown from Answers, Authorities, and Additionals
				dns.Answers = filterOutUnknownType(dns.Answers)
				dns.Authorities = filterOutUnknownType(dns.Authorities)
				dns.Additionals = filterOutUnknownType(dns.Additionals)

				for _, answer := range dns.Answers {
					switch answer.Type {
					case layers.DNSTypeSRV:
						fmt.Printf("SRV Answer: %s %s %d %d %d %s\n", string(answer.Name), answer.Type, answer.SRV.Priority, answer.SRV.Weight, answer.SRV.Port, string(answer.SRV.Name))
					case layers.DNSTypeTXT:
						fmt.Printf("TXT Answer: %s %s %s\n", string(answer.Name), answer.Type, answer.TXTs)
					case layers.DNSTypeA, layers.DNSTypeAAAA:
						fmt.Printf("IP Answer: %s %s %s\n", string(answer.Name), answer.Type, answer.IP)
					case layers.DNSTypePTR:
						fmt.Printf("PTR Answer: %s %s %s\n", string(answer.Name), answer.Type, answer.PTR)
					default:
						fmt.Printf("Answer: %s %s %s %s %s\n", string(answer.Name), answer.Type, answer.IP, answer.PTR, answer.Class)
					}
				}

				for _, authority := range dns.Authorities {
					switch authority.Type {
					case layers.DNSTypeSRV:
						fmt.Printf("SRV Authority: %s %s %d %d %d %s\n", string(authority.Name), authority.Type, authority.SRV.Priority, authority.SRV.Weight, authority.SRV.Port, string(authority.SRV.Name))
					case layers.DNSTypeTXT:
						fmt.Printf("TXT Authority: %s %s %s\n", string(authority.Name), authority.Type, authority.TXTs)
					case layers.DNSTypeA, layers.DNSTypeAAAA:
						fmt.Printf("IP Authority: %s %s %s\n", string(authority.Name), authority.Type, authority.IP)
					case layers.DNSTypePTR:
						fmt.Printf("PTR Authority: %s %s %s\n", string(authority.Name), authority.Type, authority.PTR)
					default:
						fmt.Printf("Authority: %s %s %s %s\n", string(authority.Name), authority.Type, authority.IP, authority.Class)
					}
				}

				for _, additional := range dns.Additionals {
					switch additional.Type {
					case layers.DNSTypeSRV:
						fmt.Printf("SRV Additional: %s %s %d %d %d %s\n", string(additional.Name), additional.Type, additional.SRV.Priority, additional.SRV.Weight, additional.SRV.Port, string(additional.SRV.Name))
					case layers.DNSTypeTXT:
						fmt.Printf("TXT Additional: %s %s %s\n", string(additional.Name), additional.Type, additional.TXTs)
					case layers.DNSTypeA, layers.DNSTypeAAAA:
						fmt.Printf("IP Additional: %s %s %s\n", string(additional.Name), additional.Type, additional.IP)
					case layers.DNSTypePTR:
						fmt.Printf("PTR Additional: %s %s %s\n", string(additional.Name), additional.Type, additional.PTR)
					default:
						fmt.Printf("Additional: %s %s %s %s\n", string(additional.Name), additional.Type, additional.IP, additional.Class)
					}
				}

			} else {
				fmt.Println("No DNS layer found")
			}
			bonjourPacket.packet = packet
		} else {
			fmt.Println("No application layer found")
		}
		for _, sender := range senders {
			go sendBonjourPacket(sender, &bonjourPacket, *bonjourPacket.srcMAC)
		}

	}
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

// Helper function to filter out AAAA and PTR records with link-local IPv6 addresses
func filterOutLinkLocalAAAAAndPTR(records []layers.DNSResourceRecord) []layers.DNSResourceRecord {
	filteredRecords := []layers.DNSResourceRecord{}
	for _, record := range records {
		if record.Type == layers.DNSTypeAAAA && isLinkLocalIPv6(record.IP) {
			continue
		}
		if record.Type == layers.DNSTypePTR && strings.HasSuffix(string(record.Name), "0.8.E.F.ip6.arpa") {
			continue
		}
		filteredRecords = append(filteredRecords, record)
	}
	return filteredRecords
}

// Helper function to filter out records with Type = Unknown
func filterOutUnknownType(records []layers.DNSResourceRecord) []layers.DNSResourceRecord {
	filteredRecords := []layers.DNSResourceRecord{}
	for _, record := range records {
		if record.Type.String() != "Unknown" {
			filteredRecords = append(filteredRecords, record)
		}
	}
	return filteredRecords
}

// Helper function to check if an IP is a link-local IPv6 address
func isLinkLocalIPv6(ip net.IP) bool {
	return ip.To16() != nil && ip.IsLinkLocalUnicast()
}
