#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RTABLE_ENTRIES 100000 // numarul maxim de intrari in tabela de rutare
#define MAX_ARP_CACHE 256  // numarul maxim de intrari in cache-ul ARP
#define MAX_PENDING_ARP 256 // numarul maxim de cereri ARP care asteapta raspuns

// structura pentru intrarile din bucket-urile LPM
struct lpm_entry {
	uint32_t prefix_host; // prefixul in host order, obtinut prin aplicarea mastii pe prefixul din tabela de rutare
	uint32_t next_hop_net; // IP-ul next-hop-ului in network order
	int interface; // interfata de iesire
};

// structura pentru bucket-urile LPM,
struct lpm_bucket {
	struct lpm_entry *entries; // vector dinamic pentru intrarile cu acelasi prefix length
	size_t len; // numarul de intrari din bucket
	size_t cap; // capacitatea alocata pentru vectorul de intrari, se dubleaza cand e nevoie
};

// structura pentru intrarile din cache-ul ARP
struct arp_cache_entry {
	uint32_t ip_net; // adresa IP in network order
	uint8_t mac[6]; // adresa MAC a
}; // structura pentru intrarile din cache-ul ARP

// structura pentru pachetele ce asteapta raspuns ARP
struct pending_packet {
	char *data; // cadru
	size_t len; // lungimea cadrului
	size_t out_iface; // interfata de iesire
	uint32_t next_hop_ip_net; // IP-ul next-hop-ului in network order
}; 

static int is_router_ip(uint32_t ip_net, const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]);

static void arp_cache_insert_or_update(struct arp_cache_entry *cache, size_t *cache_len, uint32_t ip_net, const uint8_t mac[6]);

static int is_pending_arp(const uint32_t *pending, size_t pending_len, uint32_t ip_net);

static int get_prefix_len(uint32_t mask_host);

static void bucket_add(struct lpm_bucket *b, struct lpm_entry e);

static int lpm_entry_cmp(const void *a, const void *b);

static struct lpm_entry *bucket_binary_search(struct lpm_bucket *b, uint32_t wanted_prefix_host);

static void build_lpm_buckets(struct lpm_bucket buckets[33], const struct route_table_entry *rtable, int rtable_len);

static struct lpm_entry *find_best_route_lpm(struct lpm_bucket buckets[33], uint32_t dest_ip_net);

static void send_arp_request(size_t out_iface, uint32_t target_ip_net, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]);

static void send_arp_reply(size_t recv_iface, const struct ether_hdr *rx_eth, const struct arp_hdr *rx_arp, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]);

static void process_pending_packets_for_ip(queue *pending_q, uint32_t ip_net, const uint8_t mac[6], const uint8_t if_mac[ROUTER_NUM_INTERFACES][6]);

static void send_icmp_error_message(size_t recv_iface, const struct ether_hdr *rx_eth, const struct ip_hdr *rx_ip, size_t rx_len, size_t ip_hdr_len, uint8_t type, uint8_t code, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]);

static void send_icmp_echo_reply(size_t recv_iface, const struct ether_hdr *rx_eth, const struct ip_hdr *rx_ip, size_t rx_len, size_t ip_hdr_len, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]);


int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	struct route_table_entry *rtable = NULL;
	int rtable_len = 0;
	struct lpm_bucket lpm_buckets[33];
	memset(lpm_buckets, 0, sizeof(lpm_buckets));

	struct arp_cache_entry arp_cache[MAX_ARP_CACHE];
	size_t arp_cache_len = 0;
	uint32_t pending_arp[MAX_PENDING_ARP];
	size_t pending_arp_len = 0;
	queue pending_pkts = create_queue();

	uint8_t if_mac[ROUTER_NUM_INTERFACES][6];
	uint32_t if_ip_net[ROUTER_NUM_INTERFACES];

	DIE(argc < 3, "Usage: %s <rtable> <ifaces...>", argv[0]);

	// Do not modify this line
	init(argv + 2, argc - 2);

	// cache pentru adresele MAC/IP ale interfetelor locale
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {	
		get_interface_mac(i, if_mac[i]);

		// Convertim IP-ul interfetei din string in format network order
		if_ip_net[i] = inet_addr(get_interface_ip(i));
	}

	// initializam tabela de rutare si bucket-urile LPM
	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_ENTRIES);
	DIE(rtable == NULL, "malloc rtable esuat");
	rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0 || rtable_len > MAX_RTABLE_ENTRIES, "rtable_len invalid");
	build_lpm_buckets(lpm_buckets, rtable, rtable_len);

	while (1) {
		int interface;
		size_t len;

		// primim un frame de pe orice interfata
		interface = (int)recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// renuntam la frame-urile prea scurte
		if (len < sizeof(struct ether_hdr)) {
			continue;
		}

		// ne asiguram ca indexul interfetei este in limite
		if ((size_t)interface >= ROUTER_NUM_INTERFACES) {
			continue;
		}

		// interpretan inceputul bufferului ca header Ethernet
		struct ether_hdr *eth = (struct ether_hdr *)buf;

		// verificam daca adresa MAC destinatie este a interfetei sau este de broadcast
		if (memcmp(eth->ethr_dhost, if_mac[interface], 6) != 0 && memcmp(eth->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
    		continue;
		}

		uint16_t etype = ntohs(eth->ethr_type); // Ethertype

		// ARP
		if (etype == 0x0806) {
			// ne asiguram ca sunt suficiente date pentru un header ARP
			if (len < sizeof(struct ether_hdr) + sizeof(struct arp_hdr)) {
				continue;
			}

			// headerul ARP incepe dupa headerul Ethernet
			struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			uint16_t op = ntohs(arp->opcode); // Opcode arata daca e request sau reply

			/// retinem asocierea IP–MAC a expeditorului din orice pachet ARP
			arp_cache_insert_or_update(arp_cache, &arp_cache_len, arp->sprotoa, arp->shwa);

			if (op == 1) { // ARP Request
				// trimitem raspuns doar la cererile ARP destinate acestei interfete
				if (arp->tprotoa != if_ip_net[interface]) {
					continue;
				}

				// trimitem raspuns ARP cu MAC-ul sau IP-ul pe aceasta interfata
				send_arp_reply((size_t)interface, eth, arp, if_mac, if_ip_net);
			} 
			else if (op == 2) { // ARP Reply
				// scoatem IP-ul din lista de asteptare
				for (size_t i = 0; i < pending_arp_len; i++) {
					if (pending_arp[i] == arp->sprotoa) {
						pending_arp[i] = pending_arp[pending_arp_len - 1];
						pending_arp_len--;
					break;
					}
				}

				// trimitem pachetele ce asteptau raspunsul ARP
				process_pending_packets_for_ip(&pending_pkts, arp->sprotoa, arp->shwa, if_mac);
			}

			continue;
		}

		// ignoram orice EtherType care nu e de tip IPv4
		if (etype != 0x0800) {
			continue;
		}

		/* IPv4 */
		// asemanator ARP, ne asiguram ca sunt suficiente date pentru un header IPv4
		if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) {
			continue;
		}

		struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

		uint8_t ver_ihl = *(uint8_t *)ip; // ver_ihl contine versiunea si lungimea headerului in 32 de biti
		uint8_t ver = ver_ihl >> 4; // versiunea este in primii 4 biti, deci se face shift la dreapta cu 4
		uint8_t ihl = ver_ihl & 0x0F; // IHL este in ultimii 4 biti, deci facen AND cu 0x0F pentru a obtine doar acesti biti

		// renuntam la pachetele care nu sunt IPv4
		if (ver != 4) {
			continue;
		}

		size_t ip_hdr_len = (size_t)ihl * 4; // inmultim IHL cu 4 pentru a avea dimensiunea in bytes

		// ne asiguram ca headerul are dimensiunea minima
		if (ip_hdr_len < sizeof(struct ip_hdr)) {
			continue;
		}

		// ne asiguram ca headerul incape in frame-ul primit
		if (sizeof(struct ether_hdr) + ip_hdr_len > len) {
			continue;
		}

		/* IPv4 checksum */
		// se aplica doar headerului, fara payload
		uint16_t old_chk = ip->checksum;
		ip->checksum = 0;
		uint16_t calc_chk = checksum((uint16_t *)ip, ip_hdr_len);

		// old_chk este stocat in network byte order in pachet, deci il convertim la host order
		// renuntam la pachet daca are header invalid
		if (calc_chk != ntohs(old_chk)) {
			continue;
		}

		ip->checksum = old_chk;

		/* ICMP Echo */
		if (is_router_ip(ip->dest_addr, if_ip_net)) {
			// ne intereseaza doar ICMP Echo Request, ignoram alte protocoale
			if (ip->proto != IPPROTO_ICMP) { 
				continue;
			}

			// ne asiguram ca avem suficiente date pentru header
			if (len < sizeof(struct ether_hdr) + ip_hdr_len + sizeof(struct icmp_hdr)) {
				continue;
			}

			const struct icmp_hdr *icmp = (const struct icmp_hdr *)((const char *)ip + ip_hdr_len);

			// ICMP Echo Request are type 8 si code 0
			if (icmp->mtype == 8 && icmp->mcode == 0) {
				send_icmp_echo_reply((size_t)interface, eth, ip, len, ip_hdr_len, if_mac, if_ip_net);
			}

			// nu trimitem pachetele destinate routerului
			continue;
		}


		/* verificam TTL (time to live) */
		if (ip->ttl <= 1) {
			// ttl va deveni 0, deci trimitem un mesaj ICMP Time Exceeded (type 11, code 0)
			send_icmp_error_message((size_t)interface, eth, ip, len, ip_hdr_len, 11, 0, if_mac, if_ip_net);
			continue;
		}

		/* Longest prefix match */
		struct lpm_entry *route = find_best_route_lpm(lpm_buckets, ip->dest_addr);
		if (route == NULL) {
			// nu exista ruta pentru destinatia pachetului, deci trimitem un mesaj ICMP Destination Unreachable (type 3, code 0)
			send_icmp_error_message((size_t)interface, eth, ip, len, ip_hdr_len, 3, 0, if_mac, if_ip_net);
			continue;
		}

		// verificam daca interfata routerului este valida
		if (route->interface < 0 || route->interface >= ROUTER_NUM_INTERFACES) {
			continue;
		}

		size_t out_iface = (size_t)route->interface;

		// determinam IP-ul next-hop
		uint32_t next_hop_ip_net = route->next_hop_net;
		if (next_hop_ip_net == 0) {
			next_hop_ip_net = ip->dest_addr; // destinatia este direct conectata
		}
		// daca nu, se face ARP pentru next-hop-ul specificat

		/* decrementam TTL si actualizam campul pentru checksum */
		ip->ttl--;
		ip->checksum = 0;
		ip->checksum = htons(checksum((uint16_t *)ip, ip_hdr_len));

		// cautam MAC-ul next-hop-ului in cache
		uint8_t next_hop_mac[6];
		int found_mac = 0;

		for (size_t i = 0; i < arp_cache_len; i++) {
			if (arp_cache[i].ip_net == next_hop_ip_net) {
				memcpy(next_hop_mac, arp_cache[i].mac, 6);
				found_mac = 1;
				break;
			}
		}
		if (found_mac) {
			memcpy(eth->ethr_shost, if_mac[out_iface], 6);
			memcpy(eth->ethr_dhost, next_hop_mac, 6);
			send_to_link(len, buf, out_iface);
			continue;
		}

		/* ARP lipsa, deci nu se retransmite deocamdata */ 
		struct pending_packet *p = malloc(sizeof(*p));
		DIE(p == NULL, "malloc pending_packet failed");

		// compiem cadrul in heap pentru ca bufferul va fi reutilizat
		p->data = malloc(len);
		DIE(p->data == NULL, "malloc pending_packet data failed");
		memcpy(p->data, buf, len);

		// salvam informatiile necesare pentru retransmitere 
		p->len = len;
		p->out_iface = out_iface;
		p->next_hop_ip_net = next_hop_ip_net;

		//adaugam pachetul in coada de asteptare
		queue_enq(pending_pkts, p);

		// trimitem cerere ARP doar daca nu exista deja una pentru acest IP
		if (!is_pending_arp(pending_arp, pending_arp_len, next_hop_ip_net)) {
			if (pending_arp_len < MAX_PENDING_ARP) {
				pending_arp[pending_arp_len] = next_hop_ip_net;
				pending_arp_len++;
			}

			send_arp_request(out_iface, next_hop_ip_net, if_mac, if_ip_net);
		}
	}
}

static int is_router_ip(uint32_t ip_net, const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]) {
	// verificam daca IP-ul dat este unul dintre IP-urile interfetelor routerului
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		if (if_ip_net[i] == ip_net) {
			return 1;
		}
	}
	return 0;
}

static void arp_cache_insert_or_update(struct arp_cache_entry *cache, size_t *cache_len, uint32_t ip_net, const uint8_t mac[6]) {
	// functie pentru a insera sau actualiza o intrare in cache-ul ARP

	// daca se gaseste IP-ul in cache, actualizam MAC-ul
	for (size_t i = 0; i < *cache_len; i++) {
		if (cache[i].ip_net == ip_net) {
			memcpy(cache[i].mac, mac, 6);
			return;
		}
	}

	// adaugam o intrare noua doar daca mai este loc in cache
	if (*cache_len < MAX_ARP_CACHE) {
		cache[*cache_len].ip_net = ip_net;
		memcpy(cache[*cache_len].mac, mac, 6);
		(*cache_len)++;
		return;
	}

	// suprascriem prima intrare daca cache-ul este plin
	cache[0].ip_net = ip_net;
	memcpy(cache[0].mac, mac, 6);
}

static int is_pending_arp(const uint32_t *pending, size_t pending_len, uint32_t ip_net) {
	// verificam daca exista deja o cerere ARP pentru acest IP in lista de asteptare

	for (size_t i = 0; i < pending_len; i++) {
		if (pending[i] == ip_net) {
			return 1;
		}
	}
	return 0;
}

static int get_prefix_len(uint32_t mask_host) {
	// aflam lungimea prefixului din masca
	// adica numarul de biti 1 consecutivi de la stanga la dreapta

	if (mask_host == 0) {
		return 0;
	}

	int len = 0;

	uint32_t bit = 0x80000000u; // bitul cel mai din stanga (cel mai semnificativ) este 1, restul sunt 0

	while (bit != 0) {
		// verificam daca bitul curent este 1
		if ((mask_host & bit) != 0) {
			len = len + 1;
		} else {
			// daca am dat de primul 0, ne oprim
			break;
		}

		// trecem la urmatorul bit spre dreapta
		bit = bit >> 1;
	}

	return len;
}

static void bucket_add(struct lpm_bucket *b, struct lpm_entry e) {
	// adaugam o intrare in bucket

	if (b->len == b->cap) {
		// daca am depasit capacitatea, alocam mai mult spatiu, dubland capacitatea
		size_t new_cap;

		if (b->cap == 0) {
			new_cap = 16; // capacitatea initiala daca bucket-ul era gol
		} else {
			new_cap = b->cap * 2;
		}

		struct lpm_entry *tmp = realloc(b->entries, new_cap * sizeof(*tmp));
		DIE(tmp == NULL, "realloc");

		// actualizam pointerul si capacitatea bucket-ului
		b->entries = tmp;
		b->cap = new_cap;
	}

	// adaugam intrarea la finalul vectorului si incrementam lungimea
	b->entries[b->len] = e;
	b->len++;
}

static int lpm_entry_cmp(const void *a, const void *b) {
	// functie folosita la sortate, ce compara doua intrari LPM dupa prefix_host 
	const struct lpm_entry *ea = (const struct lpm_entry *)a;
	const struct lpm_entry *eb = (const struct lpm_entry *)b;

	if (ea->prefix_host < eb->prefix_host) {
		return -1; // ea ar trebui sa vina inaintea lui eb
	}
	if (ea->prefix_host > eb->prefix_host) {
		return 1; // ea ar trebui sa vina dupa eb
	}
	return 0;
}

static struct lpm_entry *bucket_binary_search(struct lpm_bucket *b, uint32_t wanted_prefix_host) {
	// cautare binara intr-un vector sortat dupa prefix_host

	size_t left = 0;
	size_t right = b->len;

	while (left < right) {
		// calculam pozitia din mijloc
		size_t mid = left + (right - left) / 2;

		// luam valoarea din mijloc
		uint32_t current_value = b->entries[mid].prefix_host;

		// daca am gasit exact ce cautam
		if (current_value == wanted_prefix_host) {
			return &b->entries[mid]; // returnam adresa intrarii gasite
		}

		// daca valoarea din mijloc e mai mica, vom cauta in dreapta
		if (current_value < wanted_prefix_host) {
			left = mid + 1;
		} else {
			// altfel, cautam in stanga
			right = mid;
		}
	}

	// nu am gasit elementul
	return NULL;
}

static void build_lpm_buckets(struct lpm_bucket buckets[33], const struct route_table_entry *rtable, int rtable_len) {
	// functie pentru a construi bucket-urile LPM din tabela de rutare

	// parcurgem toate intrarile din tabela de rutare
	for (int i = 0; i < rtable_len; i++) {

		// luam intrarea curenta
		const struct route_table_entry *route = &rtable[i];

		// ignoram intrarile cu interfete invalide
		if (route->interface < 0 || route->interface >= ROUTER_NUM_INTERFACES) {
			continue;
		}

		// convertim masca in host order
		uint32_t mask_host = ntohl(route->mask);

		// calculam lungimea prefixului
		int prefix_len = get_prefix_len(mask_host);

		// ne asiguram ca este valida
		if (prefix_len < 0 || prefix_len > 32) {
			continue;
		}

		// construim o noua intrare pentru bucket
		struct lpm_entry entry;

		// aplicam masca pe prefix
		uint32_t prefix_host = ntohl(route->prefix);
		entry.prefix_host = prefix_host & mask_host;

		// copiem restul informatiilor
		entry.next_hop_net = route->next_hop;
		entry.interface = route->interface;

		// adaugam in bucket-ul corespunzator lungimii prefixului
		bucket_add(&buckets[prefix_len], entry);
	}

	// sortam fiecare bucket pentru a putea face cautarea binara
	for (int prefix_len = 0; prefix_len <= 32; prefix_len++) {
		if (buckets[prefix_len].len > 1) {
			qsort(buckets[prefix_len].entries, buckets[prefix_len].len, sizeof(struct lpm_entry), lpm_entry_cmp);
		}
	}
}

static struct lpm_entry *find_best_route_lpm(struct lpm_bucket buckets[33], uint32_t dest_ip_net) {
	// functie pentru a gasi cea mai buna ruta folosind longest prefix match

	// convertim IP-ul destinatie in host order
	uint32_t dest_ip_host = ntohl(dest_ip_net);

	// parcurgem prefixele de la cel mai semnificativ la cel mai general
	for (int prefix_len = 32; prefix_len >= 0; prefix_len--) {

		// daca bucket-ul este gol, il sarim
		if (buckets[prefix_len].len == 0) {
			continue;
		}

		uint32_t mask_host;

		// construim masca pentru lungimea curenta
		if (prefix_len == 0) {
			mask_host = 0;
		} else {
			mask_host = 0xFFFFFFFFu << (32 - prefix_len); // facem shift la stanga pentru a avea prefix_len biti de 1 in masca
		}

		// aplicam masca pe IP-ul destinatie
		uint32_t masked_ip = dest_ip_host & mask_host;

		// cautam in bucket-ul corespunzator
		struct lpm_entry *result = bucket_binary_search(&buckets[prefix_len], masked_ip);

		// daca am gasit o ruta, o returnam imediat
		if (result != NULL) {
			return result;
		}
	}

	// nu am gasit nicio ruta potrivita
	return NULL;
}

static void send_arp_request(size_t out_iface, uint32_t target_ip_net, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]) {

	// buffer pentru pachet (Ethernet + ARP)
	char packet[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];

	struct ether_hdr *eth_header = (struct ether_hdr *)packet;
	struct arp_hdr *arp_header = (struct arp_hdr *)(packet + sizeof(struct ether_hdr));

	/* header Ethernet  */

	memset(eth_header->ethr_dhost, 0xFF, 6); // destinatia: broadcast (FF:FF:FF:FF:FF:FF)
	memcpy(eth_header->ethr_shost, if_mac[out_iface], 6); // sursa: MAC-ul interfetei de iesire

	eth_header->ethr_type = htons(0x0806); // tipul protocolului: ARP

	/* header ARP */

	arp_header->hw_type = htons(1); // Ethernet
	arp_header->proto_type = htons(0x0800); // IPv4
	arp_header->hw_len = 6; // MAC = 6 bytes
	arp_header->proto_len = 4; // IPv4 = 4 bytes
	arp_header->opcode = htons(1); // operatie: ARP Request

	memcpy(arp_header->shwa, if_mac[out_iface], 6); // expeditor: MAC-ul interfetei de iesire
	arp_header->sprotoa = if_ip_net[out_iface]; // IP-ul interfetei de iesire

	memset(arp_header->thwa, 0, 6); // destinatar: MAC necunoscut, punem 0-uri
	arp_header->tprotoa = target_ip_net; // IP-ul pentru care vrem sa aflam MAC-ul

	// trimitem pachetul
	send_to_link(sizeof(packet), packet, out_iface);
}

static void send_arp_reply(size_t recv_iface, const struct ether_hdr *rx_eth, const struct arp_hdr *rx_arp, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]) {
	// asemanator cu send_arp_request, construim un pachet ARP Reply

	char packet[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)]; // buffer

	struct ether_hdr *eth_header = (struct ether_hdr *)packet;
	struct arp_hdr *arp_header =
		(struct arp_hdr *)(packet + sizeof(struct ether_hdr));

	/* header Ethernet */

	memcpy(eth_header->ethr_dhost, rx_eth->ethr_shost, 6); // trimitem raspunsul inapoi catre expeditor
	memcpy(eth_header->ethr_shost, if_mac[recv_iface], 6); // sursa este MAC-ul interfetei noastre

	eth_header->ethr_type = htons(0x0806); // tipul protocolului: ARP

	/* header ARP */

	arp_header->hw_type = htons(1); // hardware: Ethernet
	arp_header->proto_type = htons(0x0800); // protocol: IPv4
	arp_header->hw_len = 6; // MAC = 6 bytes
	arp_header->proto_len = 4; // IPv4 = 4 bytes
	arp_header->opcode = htons(2); // operatie: ARP Reply

	// expeditor: interfata noastra
	memcpy(arp_header->shwa, if_mac[recv_iface], 6); // MAC
	arp_header->sprotoa = if_ip_net[recv_iface]; // IP

	// destinatar: expeditorul requestului ARP
	memcpy(arp_header->thwa, rx_arp->shwa, 6); // MAC
	arp_header->tprotoa = rx_arp->sprotoa; // IP

	// trimitem pachetul
	send_to_link(sizeof(packet), packet, recv_iface);
}

static void process_pending_packets_for_ip(queue *pending_q, uint32_t ip_net, const uint8_t mac[6], const uint8_t if_mac[ROUTER_NUM_INTERFACES][6]) {
	// functie ce proceseaza pachetele ce asteapta raspuns ARP pentru un anumit IP, trimise de pe o anumita interfata

	// salvam coada veche si cream una noua
	queue old_queue = *pending_q;
	queue new_queue = create_queue();

	// parcurgem toate pachetele aflate in asteptare
	while (!queue_empty(old_queue)) {

		struct pending_packet *packet = (struct pending_packet *)queue_deq(old_queue); // luam un pachet din coada

		// verificam daca pachetul asteapta exact IP-ul primit
		if (packet->next_hop_ip_net == ip_net) {

			struct ether_hdr *eth_header = (struct ether_hdr *)packet->data; // inceputul pachetului este headerul Ethernet

			memcpy(eth_header->ethr_dhost, mac, 6); // MAC-ul destinatie este cel primit ca parametru
			memcpy(eth_header->ethr_shost, if_mac[packet->out_iface], 6); // MAC-ul sursa este cel al interfetei de pe care se va trimite pachetul

			// trimitem pachetul
			send_to_link(packet->len, packet->data, packet->out_iface);

			// eliberam memoria
			free(packet->data);
			free(packet);

		} else {
			// daca inca nu avem MAC-ul, pachetul ramane in coada
			queue_enq(new_queue, packet);
		}
	}

	// stergem coada veche si o inlocuim cu cea noua
	free(old_queue);
	*pending_q = new_queue;
}

static void send_icmp_error_message(size_t recv_iface, const struct ether_hdr *rx_eth, const struct ip_hdr *rx_ip,size_t rx_len, size_t ip_hdr_len, uint8_t type, uint8_t code, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]) {
	// functie ce trimite un mesaj ICMP de eroare (Time Exceeded sau Destination Unreachable)

	char packet[MAX_PACKET_LEN]; // buffer pentru pachetul ce va fi trimis

	// inceputul bufferului este format din header Ethernet, IP si ICMP
	struct ether_hdr *eth = (struct ether_hdr *)packet;
	struct ip_hdr *ip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)((char *)ip + sizeof(struct ip_hdr));

	// calculam cati bytes din pachetul original putem include in mesajul ICMP
	size_t ip_payload_available = 0;

	if (rx_len > sizeof(struct ether_hdr)) {
		ip_payload_available = rx_len - sizeof(struct ether_hdr); // numarul de bytes disponibili dupa headerul Ethernet
	}

	// lungimea datelor pe care vrem sa le copiem in mesajul ICMP (header IP + primii 8 bytes din payload)
	size_t icmp_copied_data_len = ip_hdr_len + 8; 

	// daca nu avem destui bytes disponibili, copiem doar ce avem
	if (icmp_copied_data_len > ip_payload_available) {
		icmp_copied_data_len = ip_payload_available;
	}

	// lungimea totala a mesajului ICMP va fi headerul ICMP + datele copiate
	size_t icmp_total_len = sizeof(struct icmp_hdr) + icmp_copied_data_len;
	size_t ip_total_len = sizeof(struct ip_hdr) + icmp_total_len;
	size_t frame_len = sizeof(struct ether_hdr) + ip_total_len;

	// daca pachetul ar depasi bufferul, il abandonam
	if (frame_len > sizeof(packet)) {
		return;
	}

	/* header ethernet */

	memcpy(eth->ethr_dhost, rx_eth->ethr_shost, 6);
	memcpy(eth->ethr_shost, if_mac[recv_iface], 6);
	eth->ethr_type = htons(0x0800); // IPv4

	/* header IP */

	memset(ip, 0, sizeof(*ip)); 
	 
	// completam campurile necesare pentru headerul IP al mesajului ICMP
	ip->ver = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)ip_total_len); // lungimea totala a pachetului IP (header + payload) in network byte order
	ip->id = htons(4); 
	ip->frag = 0;
	ip->ttl = 64;
	ip->proto = IPPROTO_ICMP; 

	ip->source_addr = if_ip_net[recv_iface]; // sursa = interfata routerului
	ip->dest_addr = rx_ip->source_addr; // destinatia = sursa pachetului original

	// checksum IP (se calculeaza dupa completarea headerului)
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	/* header ICMP */

	memset(icmp, 0, sizeof(*icmp));

	icmp->mtype = type;
	icmp->mcode = code;
	icmp->check = 0;

	/* payload ICMP */

	memcpy((char *)icmp + sizeof(struct icmp_hdr), (const char *)rx_ip, icmp_copied_data_len); // copiem headerul IP original si primii 8 bytes din payload-ul original in mesajul ICMP

	// checksum ICMP (include header + payload)
	icmp->check = htons(checksum((uint16_t *)icmp, icmp_total_len));

	// trimitem pachetul
	send_to_link(frame_len, packet, recv_iface);
}

static void send_icmp_echo_reply(size_t recv_iface, const struct ether_hdr *rx_eth, const struct ip_hdr *rx_ip, size_t rx_len, size_t ip_hdr_len, const uint8_t if_mac[ROUTER_NUM_INTERFACES][6], const uint32_t if_ip_net[ROUTER_NUM_INTERFACES]) {
	// functie ce construieste si trimite un mesaj ICMP Echo Reply ca raspuns la un Echo Request primit
	// daca destinatia pachetului este routerul

	// verificam ca pachetul primit contine macar headerele Ethernet, IP si ICMP
	if (rx_len < sizeof(struct ether_hdr) + ip_hdr_len + sizeof(struct icmp_hdr)) {
		return;
	}
	
	size_t available_ip_bytes = rx_len - sizeof(struct ether_hdr); // nr de bytes disponibili dupa headerul Ethernet

	uint16_t received_ip_len = ntohs(rx_ip->tot_len); // lungimea totala a pachetului IP, citita din header

	// daca lungimea totala a pachetului IP este mai mare decat numarul de bytes disponibili, o ajustam
	if (received_ip_len > available_ip_bytes) {
		received_ip_len = (uint16_t)available_ip_bytes;
	}

	// verificam din nou ca exista loc pentru headerele IP si ICMP
	if (received_ip_len < ip_hdr_len + sizeof(struct icmp_hdr)) {
		return;
	}

	// calculam lungimea reala a mesajului ICMP

	size_t icmp_len = received_ip_len - ip_hdr_len; // lungimea mesajului ICMP primit
	size_t new_ip_len = sizeof(struct ip_hdr) + icmp_len; // lungimea noului pachet IP (header IP + mesaj ICMP)
	size_t frame_len = sizeof(struct ether_hdr) + new_ip_len; // lungimea cadrului Ethernet complet

	// verificam sa incapa in buffer
	if (frame_len > MAX_PACKET_LEN) {
		return;
	}

	// pregatim bufferul pentru raspuns

	char packet[MAX_PACKET_LEN];

	// pointeri catre headerele din buffer
	struct ether_hdr *eth_header = (struct ether_hdr *)packet;
	struct ip_hdr *ip_header = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_header = (struct icmp_hdr *)((char *)ip_header + sizeof(struct ip_hdr));

	// destinatia este expeditorul pachetului original
	memcpy(eth_header->ethr_dhost, rx_eth->ethr_shost, 6);
	memcpy(eth_header->ethr_shost, if_mac[recv_iface], 6);
	eth_header->ethr_type = htons(0x0800); // IPv4

	// completam campurile necesare pentru headerul IP al mesajului ICMP Echo Reply
	memset(ip_header, 0, sizeof(*ip_header));

	ip_header->ver = 4;
	ip_header->ihl = 5;
	ip_header->tos = 0;
	ip_header->tot_len = htons((uint16_t)new_ip_len);
	ip_header->id = htons(4);
	ip_header->frag = 0;
	ip_header->ttl = 64;
	ip_header->proto = IPPROTO_ICMP;

	// sursa devine interfata routerului pe care am primit pachetul original
	ip_header->source_addr = if_ip_net[recv_iface];

	// destinatia devine sursa pachetului original
	ip_header->dest_addr = rx_ip->source_addr;

	// calculam checksum-ul IP 
	ip_header->checksum = 0;
	ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

	// copiem mesajul ICMP original din pachetul primit in bufferul pentru raspuns
	const char *received_icmp_start = (const char *)rx_ip + ip_hdr_len; // pointer catre inceputul mesajului ICMP in pachetul original
	memcpy(icmp_header, received_icmp_start, icmp_len);

	// actualizam campurile necesare pentru a transforma mesajul ICMP intr-un Echo Reply
	icmp_header->mtype = 0; 
	icmp_header->mcode = 0;
	icmp_header->check = 0;

	// recalculam checksum-ul ICMP
	icmp_header->check = htons(checksum((uint16_t *)icmp_header, icmp_len));

	// trimitem pachetul
	send_to_link(frame_len, packet, recv_iface);
}