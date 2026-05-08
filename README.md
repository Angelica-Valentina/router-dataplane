Repository for the first homework of the Communication Networks class. In this homework the students will implement the dataplane of a router.

# README 
Student: Tiganescu Angelica-Valentina

## Descriere
Acest program are implementat un router ce primeste cadre Ethernet.
Verifica prin ce protocol au fost transmise si decide ce face cu ele pe baza acestui rezultat

Routerul poate:
- primi pachete de pe orice interfata
- verifica daca pachetul este pentru el sau poate fi ignorat
- gestiona pachete ARP si IPV4
- afla adresele MAC cu ajutorul ARP
- redirectiona pachete IPv4 catre next-hop
- daca pachetul este pentru el insusi, raspunde la ICMP Echo Request
- trimite mesaje ICMP de eroare cand e necesar
- folosi LPM pentru a gasi cea mai buna ruta

## Logica programului
1. Routerul porneste si citeste adresele MAC si IP ale interfetelor si tabela de rutare.
2. Tabela de rutare este preprocesata intr-o structura mai eficienta pentru cautare.
3. Se intra intr-o bucla infinita in care:
    a) primeste un frame
    b) verifica daca este valid
    c) afla tipul protocolului si ia decizii in functie de acesta
    e) trimite raspunsuri sau pachete mai departe

## Structuri de date
### struct lpm_entry
Retine o ruta ce are doar informatiile relevante pentru Longest Prefix Match

Campurile sunt:
- uint32_t prefix_host: prefixul de retea in host order
- uint32_t next_hop_net: next_hop-ul in network order
- int interface: interfata de iesire

### struct lpm_bucket
Reprezinta un bucket de rute ce au aceeasi lungime a prefixului.

Campurile sunt:
- struct lpm_entry *entries: vector dinamic de rute
- size_t len : numar actual de elemente
- size_t cap : capacitatea alocata

Vor exista 33 de bucket-uri.
Astfel programul va porni de la cele mai specifice rute si o sa ajunga la cele generale.

### struct arp_cache_entry
Retine o asociere IP_MAC.
Practic ajuta sa nu fie trimisa o cerere ARP de fiecare data.

Campurile sunt:
- uint32_t ip_net: adresa IP in network order
- uint8_t mac\[6]: adresa MAC

### struct pending_packet
Descrie un pachet care nu a putut fi trimis pe moment deoarece lipsea adresa MAC a next-hop-ului.
Ajuta ca bufferul principal buf sa fie reutilizat la fiecare pachet primit. 
Daca ramane doar pointer, datele se vor pierde, deci copierea in Heap ajuta ca pachetul sa fie trimis mai tarziu dupa ce soseste raspunsul ARP.

Campurile sunt:
- char *data : copia cadrului Ethernet
- size_t len : lungimea cadrului
- out_iface : interfata pe care trebuie trimis
- next_hop_ip_net : IP-ul pentru care e asteptat raspuns ARP

## Implementare
In main() sunt declarate:
- tabela de rutare
- bucket-urile pentru LPM
- cache-ul ARP
- lista IP-urilor care au deja o cerere ARP în curs
- coada cu pachete care așteaptă rezolvarea ARP
- vectorii cu adrese MAC și IP ale interfețelor locale

Dupa se verifica sa fie numarul suficient de argumente pentru ca programul are nevoie de fisierul cu tabela de rutare si lista de interfete.

Se citesc pentru fiecare interfata MAC-ul si IP-ul cu ajutorul get_interface_mac si get_interface_ip.
IP-ul e convertit in network order cu ajutorul inet_addr() pentru ca headerele de retea folosesc network byte order. 
Prin urmare, este mai eficient ca la comparare IP-urile din pachete si interfete sa aiba aceeasi reprezentare.

Prima oara este citita tabela bruta de rutare. 
Dupa este prelucrata in lpm_build() si reorganizata in bucket-uri dupa lungimea prefixului.
In acest mod, cautarea binara pentru Longest Prefix Match va fi mai simpla.

Functia recv_from_any_link() permite ca routerul sa primeasca pachete de pe orice interfata.
Returneaza interfata de pe care a venit pachetul si datele.

Dupa verifica daca pachetul este mai scurt decat un header ETHERNET pentru a nu folosi memorie invalida, ce ar putea duce la erori.
In plus, se mai verifica interfata pentru a se asigura ca e o valoare valida.

Se verifica adresa MAC destinatei pentru a evita cazul in care sunt procesate cadre ce sunt destinate altui dispozitiv.

Daca pachetele sunt ARP, se:
- verifica lungimea
- extrage opcode-ul pentru a afla daca e:
    - request:
        - afla daca cererea e pentru IP-ul interfetei care a primit-o
        - routerul construieste un raspuns in care afirma ca cererea e unde trebuie
    - reply:
        - scoate IP-ul din lista pending_arp
        - trimite toate pachetele din coade ce asteptau acel IP
- actualizeaza cache-ul ARP

Daca un pachet nu este ARP sau IPv4, este ignorat

Daca pachetele sunt IPv4, se:
- verifica lungimea minima
- extrag campurile version (primii 4 biti) si IHL (ultimii 4 biti)
- verifica sa fie IPv4, ci nu alta versiune
- calculeaza dimensiunea headerului IP 
    - se inmulteste cu 4 pentru ca IHL este exprimat in cuvinte de 32 de biti, nu in bytes
- verifica dimensiunea reala a headerului deoarece daca IHL e mai mic decat minimul valid, atunci pachetul este corupt
- verifica daca headerul IP declarat de pachet incape in lungimea totala primita si pentru ca programul sa nu citeasca dincolo de buffer
- valideaza checksum-ul IPv4 prin:
    - salvarea checksum-ului original
    - setarea temporara a campulului checksum din header cu valoarea 0
    - recalcularea checksum-ului
    - compararea cu valoarea din pachet

Un pachet este destinat routerului daca IP destinatie este una dintre adresele IP ale interfetei routerului.
Am implementat doar pentru ICMP:
- verificarea protocolului ICMP si alte protocoale se ignora
- verificarea existentei headerului
- identificarea unui Echo Request (type 8 este Echo Request si code 0 este cod standard pentru ping)
    - dupa trimite echo reply si nu forwardeaza pachetul

Dupa are loc verificarea TTL pentru pachete care trebuie forwardate.
Daca TTL este 1 sau 0, routerul nu mai poate forwarda pachetul, deoarece decrementarea TTL-ului duce la 0.

La Longest Prefix Match, rutele sunt grupate in bucket-uri, in functie de lungimea prefixului.
Asa tabela de rutare este organizata eficient, deci cautarea poate incepe direct de la cele mai specifice cazuri.
In interiorul fiecarui bucket, rutele sunt sortate dupa prefix, iar cautarea se face cu binary search. 
In loc sa parcurga liniar toate rutele, binary search reduce timpul de cautare la O(log n) in loc de (O(n))

Apoi, se decrementeaza TTL si se recalculeaza checksum.

Urmeaza cautarea MAC-ului next-hop-ului in cache cu o cautare liniara, deoarece cache-ul este mic.
Daca MAC-ul este:
- gasit, routerul completeaza headerul Ethernet:
    - sursa devine MAC-ul interfetei de iesire
    - destinatia devine MAC-ul next hop-ului
    - trimite cadrul.
- necunoscut:
    - nu trimite imediat pachetul
    - aloca un pending_packet 
    - copiaza cadrul in memorie
    - salveaza interfata si next hop-ul
    - pune pachetul in coada
    - daca nu exista deja ARP Request, trimite unul pentru acel IP

## Functii folosite
### is_router_ip
Verifica daca un IP dat apartine routerului.
Functia compara IP-ul primit cu IP-urile tuturor interfetelor routerului.

### arp_cache_insert_or_update
Adauga sau actualizeaza o intrare in cache-ul ARP.
Daca IP-ul exista deja in cache, functia doar actualizeaza MAC-ul asociat.
Daca IP-ul nu exista si mai este loc, adauga o intrare noua.
Daca cache-ul este plin, suprascrie prima intrare.

### is_pending_arp
Verifica daca exista deja o cerere ARP in asteptare pentru un anumit IP.
Functia cauta IP-ul intr-un vector care retine IP-urile pentru care s-a trimis deja ARP Request si inca nu s-a primit raspuns.

### get_prefix_len
Calculeaza lungimea prefixului dintr-o masca de retea.
Mai exact, numara cati biti de 1 are masca de la stanga la dreapta, pana la primul 0.
Functia este utila pentru partea de Longest Prefix Match.

### bucket_add
Adauga o intrare intr-un bucket LPM.
Daca bucket-ul nu mai are loc, functia mareste vectorul dinamic:
- daca era gol, porneste cu capacitatea 16
- altfel, dubleaza capacitatea
Dupa aceea, adauga noua intrare la final.

### lpm_entry_cmp
Compara doua intrari de tip lpm_entry.
Functia este folosita de qsort ca sa sorteze intrarile dintr-un bucket dupa prefix_host.

Intoarce:
- valoare negativa daca prima intrare trebuie sa vina inainte
- valoare pozitiva daca trebuie sa vina dupa
- 0 daca sunt egale

### bucket_binary_search
Cauta un prefix intr-un bucket sortat.
Functia face binary search in vectorul de intrari din bucket si incearca sa gaseasca exact prefixul dorit.

Daca il gaseste, intoarce adresa intrarii.
Daca nu, intoarce NULL.

Este mult mai rapida decat o cautare liniara, mai ales daca bucket-ul are multe intrari.

### build_lpm_buckets
Construieste bucket-urile folosite pentru Longest Prefix Match.

Functia parcurge toata tabela de rutare si pentru fiecare ruta:
- verifica daca interfata este valida
- calculeaza lungimea prefixului din masca
- aplica masca pe prefix
- pune ruta in bucket-ul corespunzator lungimii prefixului

La final, sorteaza fiecare bucket, ca sa poata fi cautat rapid cu binary search.

### find_best_route_lpm
Gaseste cea mai buna ruta pentru o adresa IP destinatie.
Functia aplica ideea de Longest Prefix Match:
- incepe cu prefixele cele mai specifice (/32)
- merge treptat spre cele mai generale (/0)
- pentru fiecare prefix, cauta in bucket-ul corespunzator

Prima ruta gasita este cea mai buna si este returnata imediat.
Daca nu exista nicio potrivire, functia intoarce NULL.

### send_arp_request
Construieste si trimite un pachet ARP Request.
Functia este folosita atunci cand routerul vrea sa afle MAC-ul asociat unui anumit IP.

Ce face:
- construieste headerul Ethernet
- pune destinatia pe broadcast
- completeaza headerul ARP
- trimite pachetul pe interfata dorita

### send_arp_reply
Construieste si trimite un pachet ARP Reply.
Functia raspunde la un ARP Request primit pentru una dintre interfetele routerului.

Adica:
- ia MAC-ul expeditorului din pachetul primit
- construieste un raspuns direct catre el
- completeaza datele despre interfata routerului
- trimite pachetul inapoi

### process_pending_packets_for_ip
Proceseaza pachetele care asteptau un raspuns ARP pentru un anumit IP.

Adica:
- cauta toate pachetele care asteptau acel MAC
- le completeaza headerul Ethernet
- le trimite mai departe

Daca un pachet asteapta alt IP, ramane in coada.

### send_icmp_error_message
Construieste si trimite un mesaj ICMP de eroare.
Este folosita in cazuri precum:
- Time Exceeded cand TTL-ul ajunge la 0
- Destination Unreachable cand nu exista ruta spre destinatie

Functia:
- construieste un nou pachet Ethernet + IP + ICMP
- pune ca destinatie sursa pachetului original
- copiaza headerul IP original si primii 8 bytes din payload
- calculeaza checksum-urile
- trimite mesajul

### send_icmp_echo_reply
Construieste si trimite un ICMP Echo Reply.
Este raspunsul trimis atunci cand routerul primeste un ICMP Echo Request, adica un ping adresat lui.

Functia:
- verifica daca pachetul primit este valid
- construieste un nou pachet de raspuns
- copiaza mesajul ICMP original
- schimba tipul in Echo Reply
- recalculeaza checksum-ul
- trimite raspunsul inapoi
