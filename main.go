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
		fmt.Println("Usage: main.go -receiveInterface <interface> -sendInterfaces <interface1,interface2,...>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Split the comma-separated list into individual interfaces
	sendIfs := strings.Split(*sendIfArg, ",")

	// Get a handle on the receiving network interface
	receiver, err := pcap.OpenLive(*receiveIfArg, 65536, true, time.Second)
	if err != nil {
		log.Fatalf("Encountered a problem while opening interface: %v. %v", *receiveIfArg, err)
	}

	// Get the MAC address of the receiving interface
	recvIface, err := net.InterfaceByName(*receiveIfArg)
	if err != nil {
		log.Fatalf("Could not get interface by name: %v", *receiveIfArg)
	}
	recvMAC := recvIface.HardwareAddr

	log.Printf("Receiving mDNS packets on interface: %v with MAC address: %v", recvIface, recvIface.HardwareAddr)

	// Get a handle on the sending network interfaces
	senders := make(map[*pcap.Handle]net.HardwareAddr)
	for _, sendIf := range sendIfs {
		sender, err := pcap.OpenLive(sendIf, 65536, true, time.Second)
		if err != nil {
			log.Fatalf("Could not find network interface: %v", sendIf)
		}

		// Get the MAC address of the sending interface
		iface, err := net.InterfaceByName(sendIf)
		if err != nil {
			log.Fatalf("Could not get interface by name: %v", sendIf)
		}

		log.Printf("Sending mDNS packets on interface: %v with MAC address: %v", sendIf, iface.HardwareAddr)
		senders[sender] = iface.HardwareAddr
	}

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	// Filter mDNS traffic
	filter := fmt.Sprintf("dst net (224.0.0.251 or ff02::fb) and udp dst port 5353 and not ether src %s", recvMAC)
	err = receiver.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(receiver, decoder)

	// Process packets
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true}

	for readPacket := range source.Packets() {
		applicationLayer := readPacket.ApplicationLayer()
		if applicationLayer != nil {

			// Decode the payload as DNS
			newPacket := gopacket.NewPacket(applicationLayer.Payload(), layers.LayerTypeDNS, gopacket.Default)
			if dnsLayer := newPacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)

				// Filter out link-local questions
				dns.Questions = filterOutLinkLocalQuestions(dns.Questions)

				// Filter out AAAA records from Answers, Authorities, and Additionals
				dns.Answers = filterOutLinkLocalAAAAAndPTR(dns.Answers)
				dns.Authorities = filterOutLinkLocalAAAAAndPTR(dns.Authorities)
				dns.Additionals = filterOutLinkLocalAAAAAndPTR(dns.Additionals)

				// Filter out records with Type = Uknown from Answers, Authorities, and Additionals
				dns.Answers = filterOutUnknownType(dns.Answers)
				dns.Authorities = filterOutUnknownType(dns.Authorities)
				dns.Additionals = filterOutUnknownType(dns.Additionals)

				// Create a new Ethernet layer with the source MAC address of the received packet
				ethLayer := readPacket.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

				// Get the IP layer from the received packet.
				var ipLayer gopacket.Layer
				if ethLayer.EthernetType == layers.EthernetTypeIPv6 {
					ipLayer = readPacket.Layer(layers.LayerTypeIPv6)
				} else {
					ipLayer = readPacket.Layer(layers.LayerTypeIPv4)
				}

				// Get the UDP layer from the received packet
				udpLayer := readPacket.Layer(layers.LayerTypeUDP)

				// Serialize the packet with the new Ethernet layer
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

				if ipLayer != nil && udpLayer != nil {
					// Set the network layer for checksum computation
					if networkLayer, ok := ipLayer.(gopacket.NetworkLayer); ok {
						udpLayer.(*layers.UDP).SetNetworkLayerForChecksum(networkLayer)
					}

					err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer.(gopacket.SerializableLayer), udpLayer.(gopacket.SerializableLayer), newPacket.ApplicationLayer().(gopacket.SerializableLayer))
					if err != nil {
						log.Fatalf("Failed to serialize packet: %v", err)
					}

					// Build a new packet suitable for sending.
					packetToSend := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

					// Send the packet on all the sending interfaces
					for sender, senderMacAddr := range senders {
						// Modify the Ethernet layer's source MAC address
						if ethLayer != nil {
							ethLayer.SrcMAC = senderMacAddr
						}

						buf := gopacket.NewSerializeBuffer()
						gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, packetToSend)
						sender.WritePacketData(buf.Bytes())
					}
				} else {
					log.Println("IP layer or UDP layer not found in the packet")
				}
			} else {
				fmt.Println("No DNS layer found")
			}
		} else {
			fmt.Println("No application layer found")
		}

	}
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

// Helper function to filter out link-local questions
func filterOutLinkLocalQuestions(questions []layers.DNSQuestion) []layers.DNSQuestion {
	filteredQuestions := []layers.DNSQuestion{}
	for _, question := range questions {
		if strings.Contains(string(question.Name), "fe80") {
			log.Printf("Discarding question with link-local IPv6 address: %v", string(question.Name))
			continue
		}
		filteredQuestions = append(filteredQuestions, question)
	}
	return filteredQuestions
}

// Helper function to filter out AAAA and PTR records with link-local IPv6 addresses
func filterOutLinkLocalAAAAAndPTR(records []layers.DNSResourceRecord) []layers.DNSResourceRecord {
	filteredRecords := []layers.DNSResourceRecord{}
	for _, record := range records {
		if record.Type == layers.DNSTypeAAAA && isLinkLocalIPv6(record.IP) {
			log.Printf("Discarding AAAA record with link-local IPv6 address: %v", record.IP)
			continue
		}
		if record.Type == layers.DNSTypePTR && strings.HasSuffix(string(record.Name), "0.8.E.F.ip6.arpa") {
			log.Printf("Discarding PTR record with link-local IPv6 address: %v", string(record.Name))
			continue
		}
		if record.Type == layers.DNSTypePTR && strings.Contains(string(record.PTR), "@fe80") {
			log.Printf("Discarding PTR record with link-local IPv6 address: %v", string(record.PTR))
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
		if record.Type.String() == "Unknown" {
			log.Printf("Discarding record with unknown type: %v", string(record.Data))
			continue
		}
		filteredRecords = append(filteredRecords, record)
	}
	return filteredRecords
}

// Helper function to check if an IP is a link-local IPv6 address
func isLinkLocalIPv6(ip net.IP) bool {
	return ip.To16() != nil && ip.IsLinkLocalUnicast()
}
