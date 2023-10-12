#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define max_size 100000

/*=============For ICMP==============*/
#define time_exceeded 11
#define destination_unreachable 3
#define echo_request 8
#define echo_reply_code 0
#define echo_reply_type 0
/*===================================*/

/*Values from Wikipedia. To check later*/
/*=========For IPv4 and ARP==========*/
#define ipv4 0x0800
#define arp 0x0806
#define arp_request 1
#define arp_reply 2
/*===================================*/

/*route table info*/
struct route_table_entry *rtable;
int rtable_len;
struct arp_entry *arp_cache;
int arp_cache_size = 0;
/*dim of a packet*/
size_t len;

/*
 *	The structure "elements" is used in order to make it easy
 *	for me to queue and enqueue packets and also to send them
 */
struct elements {
	char buf[MAX_PACKET_LEN];
	int len;
};

/*Queue that will store the unsent packages until we find the destination*/
struct queue *packet_queue = NULL;

int compar(const void *a, const void *b)
{
	struct route_table_entry *r1 = (struct route_table_entry *) a;
	struct route_table_entry *r2 = (struct route_table_entry *) b;

	if (r1->prefix < r2->prefix) {
		return 1;
	} else if (r1->prefix > r2->prefix)
		return -1;
	else if (r1->mask < r2->mask)
		return 1;
	else if (r1->mask > r2->mask)
		return -1;
	return 0;
}

void sort_rtable()
{
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compar);
}

/*Find the next hop using LPM alg, using binary search*/
struct route_table_entry* next_hop(uint32_t ip)
{
	int start = 0;
	int end = rtable_len - 1;
	int index;

	while (start <= end) {
	 	int mid = (start + end) / 2;

	 	if(rtable[mid].prefix == (ip & rtable[mid].mask)) {
			index = mid - 1;
			while (index >= mid - 8) {
				if (rtable[index].prefix == (ip & rtable[index].mask)){
					return &(rtable[index]);
				}
				index--;
			}
			return &(rtable[mid]);
			//break;
		}
	 	else if (rtable[mid].prefix > (ip & rtable[mid].mask))
	 		start = mid + 1;
	 	else
			end = mid - 1;
	}

	//for (int i = 0; i < rtable_len; i++) {
	//	if (rtable[i].prefix == (ip & rtable[i].mask)) {
	//		printf("Indexul din cautare liniara: %d\n", i);
	//		return &(rtable[i]);
	//	}
			
	//}

	/*something wrong has happend*/
	return NULL;
}

struct arp_entry* search_in_arp_cache (uint32_t ip_to_compare) {

	for (int i = 0; i < arp_cache_size; i++) {
		/*If I found the IP in my network, will return the arp_entry*/
		if (ip_to_compare == arp_cache[i].ip)
			return &arp_cache[i];
	}

	return NULL;
}

void swap_mac_addr(struct ether_header *eth)
{
	uint8_t auxiliary[6];
	memcpy(auxiliary, eth->ether_dhost, 6);
	memcpy(eth->ether_dhost, eth->ether_shost, 6);
	memcpy(eth->ether_shost, auxiliary, 6);
}

void swap_ip_addr(struct iphdr *ip)
{
	uint32_t auxiliary = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = auxiliary;
}

void build_ether_header(struct ether_header *new_eth, struct ether_header *eth, int interface)
{
	new_eth->ether_type = htons(0x0800);
	// invert the addresses
	memcpy(new_eth->ether_dhost, eth->ether_shost, 6);
	// the host is the router
	get_interface_mac(interface, new_eth->ether_shost);
}

void build_ip_header(struct iphdr *new_ip, struct iphdr *ip, int interface)
{
	memcpy(new_ip, ip, sizeof(struct iphdr));
	// invert the addresses
	new_ip->daddr = ip->saddr;

	struct in_addr aux_ip;
	inet_aton(get_interface_ip(interface), &aux_ip);

	// the source becomes the router
	new_ip->saddr = aux_ip.s_addr; //already in network order because of inet_aton
	new_ip->protocol = 1;
	new_ip->ttl = 64;
	new_ip->tot_len = htons(2 * (sizeof(struct iphdr) + sizeof(struct icmphdr)));

	/*header ip + icmp + ip + 8 bytes*/
	new_ip->check = 0;
	
	int new_checksum = checksum((uint16_t *)new_ip, sizeof(struct iphdr));

	new_ip->check = htons(new_checksum);
}

void build_new_icmp_header(struct icmphdr *new_icmp, struct icmphdr *icmp, struct iphdr *ip)
{	
	/*I will move all the headers received as 
	arguments in a string in order to calculate the
	checksum of the new icmp header*/
	
	char buffer[MAX_PACKET_LEN];

	int offset = 0;

	new_icmp->checksum = 0; //just to be safe

	memcpy(buffer + offset, new_icmp, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	memcpy(buffer + offset, ip, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	memcpy(buffer + offset, icmp, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	int new_checksum = checksum((uint16_t *) buffer, offset);

	new_icmp->checksum = htons(new_checksum);
}

void build_new_checksum(struct iphdr *ip_hdr)
{

	ip_hdr->ttl--;

	/*because we need to modify the ckecksums*/
	ip_hdr->check = 0;
	/*MODIFY this to */
	uint16_t new_checksum = checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr));

	ip_hdr->check = htons(new_checksum);
}

int check_checksum(struct iphdr *ip_hdr)
{
	//! Set the ip_hdr->check on 0 in order to compute the checksum

	uint16_t auxiliary_checksum = ntohs(ip_hdr->check);

	ip_hdr->check = 0;

	uint16_t check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	/*the packet is not OK*/
	if (check != auxiliary_checksum)
		return 1;

	/*
	 * because i think i will use the checksum later, I do not do this for
	 * the other branch because i will drop the package anyway
	 */
	ip_hdr->check = htons(check);

	return 0;
}

int check_ttl(struct iphdr *ip_hdr)
{
	if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
		return 1;
	return 0;
}

char *assemble_icmp_respond_packet(struct iphdr *ip, struct ether_header *eth, struct icmphdr *icmp, char *payload)
{
	char *packet_to_send = (char *)malloc(MAX_PACKET_LEN);

	uint16_t offset = 0;

	memcpy(packet_to_send + offset, eth, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);

	memcpy(packet_to_send + offset, ip, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	memcpy(packet_to_send + offset, icmp, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	// uint16_t aux_offset = (uint16_t) ( ntohs(ip->tot_len) - offset );

	memcpy(packet_to_send + offset, payload, len - offset);

	return packet_to_send;
}

void icmp_reply(struct iphdr *ip, struct ether_header *eth, struct icmphdr *icmp, char *buffer, int interface)
{
	/*
	 *	Because what will need to do is basically to modify some thing in the headers
	 *	and send the packet back, we also need to invert the destination addresses,
	 *	both mac and ip
	 */

	swap_ip_addr(ip);
	swap_mac_addr(eth);

	/*build the icmp header for sending the packet*/
	icmp->code = echo_reply_code;
	icmp->type = echo_reply_type;

	icmp->checksum = 0;

	//uint16_t offset = (uint16_t)(ntohs(ip->tot_len) - sizeof(struct iphdr));
	uint16_t icmp_checksum = checksum((uint16_t *)icmp, sizeof(struct icmphdr));

	icmp->checksum = icmp_checksum;

	/*Decrement the ttl, and create a new ip header checksum because of the previously
	modified variables*/
	build_new_checksum(ip);

	/*The payload is located after all the headers*/
	uint16_t payload_offset = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	char *payload = (char *)(buffer + payload_offset);

	char *packet = assemble_icmp_respond_packet(ip, eth, icmp, payload);

	int size_of_packet = ntohs(ip->tot_len) + sizeof(struct ether_header) + sizeof(struct icmphdr);

	send_to_link(interface, packet, size_of_packet);
}

void reply_to_arp(struct ether_header *eth, struct arp_header *arp_hdr, uint32_t ip, int interface)
{
	/*reply to the request*/
	arp_hdr->op = htons(arp_reply);
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = ip;

	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	get_interface_mac(interface, arp_hdr->sha);

	memcpy(eth->ether_dhost, eth->ether_shost, 6);
	get_interface_mac(interface, eth->ether_shost);

	char message_to_send[MAX_PACKET_LEN];
	int offset = 0;

	memcpy(message_to_send + offset, eth, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);

	memcpy(message_to_send + offset, arp_hdr, sizeof(struct arp_header));
	offset += sizeof(struct arp_header);

	// send the packet - it works, daca dau ping trece de al arp, la ipv4

	printf("aici e posibil sa crape\n");
	send_to_link(interface, message_to_send, offset);
}

void throw_some_error(struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp,
					  char *buffer, int type_of_error, int interface)
{
	/*
	 *	We will need to build new headers (eth and ip), compute the new checksums
	 *	assemble the packet and send it	
	 *	The form of an error packet
	 *  New ethernet header
	 * 	New ip header
	 * 	New icmp header
	 *  Old ip header
	 *  Old icmp header
	 */

	struct ether_header *new_eth = malloc(sizeof(struct ether_header));
	struct iphdr *new_ip = malloc(sizeof(struct iphdr));
	/*Set to 0, just for safety, in case i forget something*/
	struct icmphdr *new_icmp = malloc(sizeof(struct icmphdr)); 
	char packet_to_send[MAX_PACKET_LEN];

	build_ether_header(new_eth, eth, interface);
	
	build_ip_header(new_ip, ip, interface);

	new_icmp->type = type_of_error;
	new_icmp->code = 0;
	new_icmp->checksum = 0;

	int offset = 0;

	memcpy(packet_to_send + offset, new_eth, sizeof(struct ether_header));
	offset += sizeof(struct ether_header);

	memcpy(packet_to_send + offset, new_ip, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	/*Will be used in order to compute the icmp checksum*/
	build_new_icmp_header(new_icmp, icmp, ip);

	memcpy(packet_to_send + offset, new_icmp, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	memcpy(packet_to_send + offset, ip, sizeof(struct iphdr));
	offset += sizeof(struct iphdr);

	memcpy(packet_to_send + offset, icmp, sizeof(struct icmphdr));
	offset += sizeof(struct icmphdr);

	int size_of_packet = sizeof(struct ether_header) + 2*sizeof(struct iphdr) + 2*sizeof(struct icmphdr);
	/*Send the packet - hope it works - IT DOES NOT*/

	send_to_link(interface, packet_to_send, size_of_packet);
}

void send_the_request(struct ether_header *eth, struct arp_header *arp_hdr, int interface, uint32_t next_ip, 
																int old_interface)
{

	struct ether_header *new_eth = malloc( sizeof(struct ether_header) );
	struct arp_header *new_arp = malloc ( sizeof(struct arp_header) );

	new_eth->ether_type = htons(2054); //decimal for 0x0806

	//broadcast
	hwaddr_aton("FF:FF:FF:FF:FF:FF", new_eth->ether_dhost);
	
	//the mac address of my router
	//!!!
	get_interface_mac(interface, new_eth->ether_shost);

	new_arp->htype = htons(1);
	new_arp->hlen = 6;

	new_arp->plen = 4;
	new_arp->ptype = htons(2048);

	new_arp->op = htons(1); // ARPREQUEST

	/*get the current ip address */
	struct in_addr current_ip;
	//the if address of the router
	inet_aton(get_interface_ip(interface), &current_ip);


	new_arp->spa = current_ip.s_addr;
	/*The sender is out current router and the size of a
	mac address is 6 bytes*/
	memcpy(new_arp->sha, new_eth->ether_shost, 6);

	/*
	 *	Set the target hardware address on 0.
	 * 	Why?
	 *	https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042622.htm
	 */
	memset(new_arp->tha, 0, sizeof(new_arp->tha));
	
	/*
	 *	The target IP address will be the same for all the arp request, 
	 *	because I'm trying to identify the MAC address linked ONE IP address
	 *	Dont need to use htons, because tpa is already in  network order
	 */
	new_arp->tpa = next_ip;

	/*build the packet that will be sent*/

	char packet_to_send[MAX_PACKET_LEN];
	int offset = 0;

	memcpy (packet_to_send + offset, new_eth, sizeof (struct ether_header));
	offset += sizeof (struct ether_header);

	memcpy (packet_to_send + offset, new_arp, sizeof (struct arp_header));
	offset += sizeof (struct arp_header);

	send_to_link (interface, packet_to_send, offset);

}

void forward_packet(struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp, int interface, char *buf, int len)
{
	//Pointless to continue
	if (check_ttl(ip) == 1) {
		throw_some_error(eth, ip, icmp, buf, time_exceeded, interface);
		printf("De aici vine o mare problema\n");
		return;
	}

	struct iphdr *new_ip = (struct iphdr *) (buf + sizeof(struct ether_header));

	struct route_table_entry *next = next_hop(ip->daddr);

	/*Didn't find a next hop, so we'll need to throw*/
	if (next == NULL) {
		printf("Merge (Sper)\n");
		throw_some_error(eth, ip, icmp, buf, destination_unreachable, interface);
		return;
	}
	printf("TTL before decrements %d\n", new_ip->ttl);

	build_new_checksum(new_ip);

	printf("TTL after decrement %d\n", new_ip->ttl);

	/*next hop*/
	struct arp_entry* from_arp_cache =  search_in_arp_cache((uint32_t) ip->daddr);

	if (from_arp_cache == NULL) {
		printf("\nNu am intrare in tabela\n");
		/*need to store the package in a queue, 
		and send and arp request to broadcast*/

		struct elements *elem = malloc(sizeof(struct elements));
		char copy_buffer[MAX_PACKET_LEN];
		int copy_len = len;

		memcpy(copy_buffer, buf, sizeof(copy_buffer));

		memcpy(elem->buf, buf, sizeof(copy_buffer));

		elem->len = copy_len;

		printf ("Checksum inaite de adaugat in coada %x\n", ip->check);
		
		queue_enq(packet_queue, elem);

		send_the_request(eth, NULL, next->interface, next->next_hop, interface);

		return;
	}

	memcpy(eth->ether_dhost, from_arp_cache->mac, 6);

	struct ether_header *new_eth = (struct ether_header *) buf;
	
	for (int i = 0; i < 6; i++) {
		printf("%hhx:", new_eth->ether_dhost[i]);
	}
	printf("\n");

	memcpy(new_eth->ether_dhost, from_arp_cache->mac, 6);
	get_interface_mac(interface, new_eth->ether_shost);

	send_to_link(next->interface, buf, len);
}

void empty_packet_queue(uint8_t *mac_address, int interface)
{
	/*the queue is not empty*/
	struct elements *elem = malloc(sizeof (struct elements));

	while (!queue_empty(packet_queue)) {
		
		elem = (struct elements *) queue_deq(packet_queue);

		struct ether_header *eth = (struct ether_header *) elem->buf;
		struct iphdr *ip_hdr = (struct iphdr *) (elem->buf + sizeof(struct ether_header));

		printf("Cand scot din coada, primesc acest checksum: %x\n", ip_hdr->check);

		memcpy(eth->ether_dhost, mac_address, 6);
		get_interface_mac(interface, eth->ether_shost);

		send_to_link(interface, elem->buf, elem->len);
	}
}

void add_to_table(struct arp_header *arp_hdr, int len, int interface)
{
	struct in_addr ip;
	/*get my ip in order to compare it to the target ip address
	of the arp header, because I want to determine if I'll need to add 
	the  ip-mac correlation in the current router's arp table*/
	inet_aton(get_interface_ip(interface), &ip);

	printf("Prima: %d\n", ip.s_addr);
	printf("A doua: %d\n", arp_hdr->tpa);

	if (ip.s_addr == arp_hdr->tpa) {
		//printf("\nDaca nu ajung aici, inseamna ca e ceva gresit!!!\n");
		/*The sender ip and mac addresses will be added in the table*/
		arp_cache[arp_cache_size].ip = arp_hdr->spa; //already in 
		memcpy(arp_cache[arp_cache_size].mac, arp_hdr->sha, 6);
		arp_cache_size++;
	}

	empty_packet_queue(arp_cache[arp_cache_size-1].mac, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * max_size);
	DIE(rtable == NULL, "Malloc error");

	rtable_len = read_rtable(argv[1], rtable);
	
	packet_queue = queue_create();

	arp_cache = malloc(100001 * sizeof(struct arp_entry));

	//arp_cache_size = parse_arp_table("arp_table.txt", arp_cache);

	/*This works*/
	sort_rtable();

	while (1)
	{
		int interface;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/*TODO: check if this is necessary, if not, remove it*/
		/*we need to convert the ip address to binary form for next comparasions*/
		/*from netinet/in.h - i think*/
		struct in_addr ip;
		/*the ip address reveceived in 127.0.0.1 form*/

		int ok = inet_aton(get_interface_ip(interface), &ip);
		DIE(ok == 0, "inet aton");

		/*
		 *	ether_header is mandatory to read, the other headers will be determined
		 *	by the connection type
		 */
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		int offset = sizeof(struct ether_header);

		/*does not have an error message*/
		int type = ntohs(eth_hdr->ether_type);

		/*0x0800 in decimal*/
		if (type == 2048)
		{
			/*if the connection is ipv4 -> we need to find the ip header and the
			icmp header*/
			struct iphdr *ip_hdr = (struct iphdr *)(buf + offset);

			/*if the packet is altered, it is pointless to continue*/
			if (check_checksum(ip_hdr))
				continue;

			offset += sizeof(struct iphdr);
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + offset);

			/*check if my ip address is equal to the destination
			address of the packet*/

			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr)
			{

				if (icmp_hdr->type == echo_request)
				{

					if (check_ttl(ip_hdr) == 1)
					{ /*we need to throw an time to live exedeed error*/
						throw_some_error(eth_hdr, ip_hdr, icmp_hdr, buf, (int)time_exceeded, interface);
					}
					else {
						/*function that will receive - and make use - of all of the headers*/
						icmp_reply(ip_hdr, eth_hdr, icmp_hdr, buf, interface);
					}
				}
			}
			else if (inet_addr(get_interface_ip(interface)) != ip_hdr->daddr) {

				printf("Sunt aicisa\n");
				/*My router is not the destination, so I will need to forward the packet*/
				char buffer[MAX_PACKET_LEN];
				memcpy(buffer, buf, len);
				forward_packet(eth_hdr, ip_hdr, icmp_hdr, interface, buffer, len);
			}

		}
		if (type == arp)
		{
			/*take the arp header*/
			struct arp_header *arp_hdr = (struct arp_header *)(buf + offset);

			int op = ntohs(arp_hdr->op);

			/*I want to know the address of the router, so I will reply without 
			forwarding*/
			if (op == arp_request && arp_hdr->tpa == ip.s_addr)
			{
				printf("ESTI bine pe aici\n");
				reply_to_arp(eth_hdr, arp_hdr, ip.s_addr, interface);
			}
			else if (op == arp_reply)
			{

				printf("Ar trebui sa ajung si aici\n");
				/*Receive an arp reply with the mac address that we needed, so we will
				add the information to the arp_cache and send all the packages that were 
				stored in the packet queue*/
				add_to_table(arp_hdr, len, interface);
			}
		}
	}
}
