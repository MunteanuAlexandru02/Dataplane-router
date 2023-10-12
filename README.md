Munteanu Alexandru-Constantin
321 CC
README Tema 1 pcom

Tema are ca scop implementarea dataplane-ului unui router.

In conformitatea cu etapele prezentate in enuntul temei, rezolvarea mea,
as spune are 2 parti importante, care sunt impartite in functie de ce tip
de protocol foloseste pachetul curent, anume: IPv4 sau ARP.

Cel mai simplu de explicat dintre acestea doua consider ca este ARP, anume:
    -Router-ul primeste va separa pachetele ARP in doua categorii:
        1. Cand trebuie sa raspund, deci ARP request.
        2. Cand primesc un raspuns, deci ARP reply.
    -Cand primesc un pachet de tipul, ARP reply, inseamna ca pot sa 
    corelez o adresa IP cu o adresa MAC. Aceste legaturi se vor 
    adauga intr-un arp_cache, pe care il voi folosi si in procesul de 
    routare. Dupa ce am facut legatura intre IP si MAC, va trebui sa
    trimit toate pachetele stocate pana acum intr-o coada de pachete.
    -ARP request: va trebui sa transmit un ARP reply cu adrese MAC si 
    IP ale router-ului ca fiind senderul, iar target-ul va fi 
    sender-ul precedent.

IP:
    -Primesc un pachet caruia ii verific integritatea folosind functia
    check_checksum.
    -Daca pachetul este pentru router:
        1. verific daca acesta are un ttl valid, in cazul in care ttl 
        > 1, voi raspunde folosind icmp_reply,
        altfel, voi trimit o eroare de tip: "time exceeded".
    -icmp_reply: interschimba adresele MAC si IP si construieste un
    icmp header, scade ttl din ip header si recalculeaza checksum-ul
    -throw_some_error: functie care va trimite o eroare, fie aceasta
    time exceeded, fie destination_unreachable. Functia construieste
    un nou header pentru fiecare header, iar apoi asambleaza pachetul, sub forma:
        1.NEW ETHERNET HEADER
        2.NEW IP HEADER
        3.NEW ICMP HEADER
        4.OLD IP HEADER
        5.OLD ICMP HEADER
    
    -Daca pachetul nu e pentru router:
        apelez functia forward_packet care:
            1. Verifca ttl
            2. Cauta urmatorul hop, daca acest nu exista trimite 
            destination unreachable
            3. Decrementeaza ttl si recaluleaza checksum-ul
            4. Verifica daca exista avem informatii despre adresa MAC
            asociata adresei IP a urmatorului "hop" in arp cache. Daca
            exista, trimit pachetul, altfel, adaug pachetul intr-o 
            coada si trimit un request folosind functia 
            "send_the_request", care construieste un nou pachet arp
            care va fi trimis pe "broadcast".


Probabil ca cea mai dificila, din punctul meu de vedere,
parte din aceasta tema a fost intelegerea si construirea unui pachet
ICMP error. Totodata, am mai avut probleme cu determinarea 
interfetelor pe care ar trebui sa trimit pachetul.

In unele functii am construit un nou char* pentru a trimite pachetul,
deoarece, pentru anumite cazuri am crezut ca functia ar fi mai usor
de inteles.

Functiile check_checksum, build_new_checksum si altele
au fost construite pentru a preveni reutilizarea codului (oricum 
programul a iesit destul de lung).

Pentru implementarea unui algoritm LPM eficient am urmat urmatorii 
pasi:
    - Am sortat descrescator rtable in functie de prefix, iar in caz
    de egalitate, descrescator in functie de mask. Pentru sortare am
    folosit functia qsort din stdlib.
    -Pentru a cauta un numar din arp_cache am folosit un algoritm de 
    binary search putin modificat, deoarce, atunci cand voi gasi o 
    egalitate ma voi uita cateva elemente la stanga pentru a verifica
    ca am "cea mai mare masca".


Documentatie:
    In mare parte, aceasta consista in enuntul temei, deoarece a 
fost bine explicat, RFC-urile puse la dispozitie in cerinta, 
capitolele din carte, dar si video-urile, de asemenea din cerinta,
laburile de PCom, in special laboratorul 4, dar si 
https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042622.htm, 
unde am gasit foarte clar ce trebuie inclus intr-un arp request cand 
acesta este trimis pe broadcast.