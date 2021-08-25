#include <signal.h>
#include <pcap.h>
#include <netinet/ether.h>
#include "afficher.h"

#define TYPE_IP_TCP 6
#define TYPE_IP_UDP 17
#define LONG_ENTETE_IP6 40
#define LONG_ENTETE_UDP 8
#define PORT_DNS 53
#define PORT_CMD_FTP 21
#define PORT_HTTP 80
#define PORT_TELNET 23
#define PORT_SMTP_1 25
#define PORT_SMTP_2 587
#define PORT_POP 110
#define PORT_IMAP 143

int cpt_paquets = 0;

// ---------- niveau D ----------

/*
* Traite et affiche la section IMAP d'un paquet.
*/
void imap(const u_char *p, const u_char *fin_tcp, int psrc, int pdst, int verbo)
{
	const char *c = (char*) p;
	const char *fin = (char*) fin_tcp;
	int b_requete = (pdst == PORT_IMAP);
	afficher_imap(c, fin, b_requete, verbo);
}

/*
* Analyse puis affiche la section POP d'un paquet.
*/
void pop(const u_char *p, const u_char *fin_tcp, int psrc, int pdst, int verbo)
{
	const char *c = (char*) p;
	const char *fin = (char*) fin_tcp;
	int b_requete = (pdst == PORT_POP);
	afficher_pop(c, fin, b_requete, verbo);
}

/*
* Traite puis affiche la partie SMTP d'un paquet.
*/
void smtp(const u_char *p, const u_char *fin_tcp, int psrc, int pdst, int verbo)
{
	const char *c = (char*) p;
	const char *fin = (char*) fin_tcp;
	int b_requete = (pdst == PORT_SMTP_1 || pdst == PORT_SMTP_2);
	afficher_smtp(c, fin, b_requete, verbo);
}

/*
* Affiche la section Telnet d'un paquet.
*/
void telnet(const u_char *p, const u_char *fin_tcp, int verbo)
{
	afficher_telnet(p, fin_tcp, verbo);
}

/*
* Analyse et affiche la partie HTTP d'un paquet.
*/
void http(const u_char *p, const u_char *fin_tcp, int psrc, int pdst, int verbo)
{
	const char *c = (char*) p;
	const char *fin = (char*) fin_tcp;
	int b_requete = (pdst == PORT_HTTP);
	afficher_http(c, fin, b_requete, verbo);
}

/*
* Traite puis affiche la section FTP d'un paquet.
*/
void ftp(const u_char *p, const u_char *fin_tcp, int verbo)
{
	const char *c = (char*) p;
	const char *fin = (char*) fin_tcp;
	afficher_ftp(c, fin, verbo);
}

/*
* Traite et affiche la BOOTP d'un paquet, puis fait de meme
* pour les options DHCP.
*/
void bootp_dhcp(const u_char *p, int verbo)
{
	struct bootp *bp = (struct bootp*) p;
	afficher_bootp(bp, verbo);
	u_char *d = bp->bp_vend;
	if (d[0] == 0x63 && d[1] == 0x82 && d[2] == 0x53 && d[3] == 0x63)
		afficher_dhcp(d + 4, verbo);
}

/*
* Analyse et affiche l'entete d'un message DNS.
*/
void dns(const u_char *p, int verbo)
{
	const struct entete_dns *d = (struct entete_dns*) p;
	afficher_dns(d, verbo);
}

// ---------- niveau C ----------

/*
* Prepare et affiche l'entete d'un segment TCP, plus ses options,
* puis relance sur son payload.
*/
void tcp(const u_char *p, const u_char *fin_payload_ip, int verbo)
{
	const struct tcphdr *tcph = (struct tcphdr*) p;
	afficher_tcp(tcph, verbo);

	int s = ntohs(tcph->source);
	int d = ntohs(tcph->dest);
	int taille_entete_tcp = tcph->doff * 4;
	if (s == PORT_CMD_FTP || d == PORT_CMD_FTP)
		ftp(p + taille_entete_tcp, fin_payload_ip, verbo);
	else if (s == PORT_HTTP || d == PORT_HTTP)
		http(p + taille_entete_tcp, fin_payload_ip, s, d, verbo);
	else if (s == PORT_TELNET || d == PORT_TELNET)
		telnet(p + taille_entete_tcp, fin_payload_ip, verbo);
	else if (s == PORT_SMTP_1 || d == PORT_SMTP_1
						|| s == PORT_SMTP_2 || d == PORT_SMTP_2)
		smtp(p + taille_entete_tcp, fin_payload_ip, s, d, verbo);
	else if (s == PORT_POP || d == PORT_POP)
		pop(p + taille_entete_tcp, fin_payload_ip, s, d, verbo);
	else if (s == PORT_IMAP || d == PORT_IMAP)
		imap(p + taille_entete_tcp, fin_payload_ip, s, d, verbo);
	else
	{
		printf("Contenu non reconnu");
		if (verbo != 1) printf("\n");
	}
}

/*
* Prepare puis affiche l'entete d'un datagramme UDP,
* puis relance sur son payload.
*/
void udp(const u_char *p, int verbo)
{
	const struct udphdr *udph = (struct udphdr*) p;
	afficher_udp(udph, verbo);
	int s = ntohs(udph->source);
	int d = ntohs(udph->dest);
	if (s == IPPORT_BOOTPC || s == IPPORT_BOOTPS)
		bootp_dhcp(p + LONG_ENTETE_UDP, verbo);
	else if (s == PORT_DNS || d == PORT_DNS)
		dns(p + LONG_ENTETE_UDP, verbo);
	else
	{
		printf("Contenu non reconnu");
		if (verbo != 1) printf("\n");
	}
}

// ---------- niveau B ----------

/*
* Prepare et affiche l'entete d'un datagramme IPv4,
* puis relance sur son payload.
*/
void ipv4(const u_char *p, int verbo)
{
	const struct ip *iph = (struct ip*) p;
	afficher_ipv4(iph, verbo);
	switch (iph->ip_p)
	{
	case TYPE_IP_TCP:
		tcp(p + iph->ip_hl * 4, p + ntohs(iph->ip_len), verbo);
		break;
	case TYPE_IP_UDP:
		udp(p + iph->ip_hl * 4, verbo);
		break;
	default:
		printf("Contenu non reconnu (Protocole 0x%x)", iph->ip_p);
		if (verbo != 1) printf("\n");
		break;
	}
}

/*
* Prepare puis affiche l'entete d'un datagramme IPv6,
* puis relance sur son payload.
*/
void ipv6(const u_char *p, int verbo)
{
	const struct ip6_hdr *ip6 = (struct ip6_hdr*) p;
	afficher_ipv6(ip6, verbo);
	switch (ip6->ip6_nxt)
	{
	case TYPE_IP_TCP:
		tcp(p + LONG_ENTETE_IP6, p + LONG_ENTETE_IP6 + ntohs(ip6->ip6_plen), verbo);
		break;
	case TYPE_IP_UDP:
		afficher_udp((struct udphdr*) (p + LONG_ENTETE_IP6), verbo);
		break;
	default:
		printf("Contenu non reconnu (Entete suivant 0x%u)", ip6->ip6_nxt);
		if (verbo != 1) printf("\n");
		break;
	}
}

/*
* Prepare et affiche un message ARP.
*/
void arp(const u_char *p, int verbo)
{
	const struct arp_pour_adr_mac *a = (struct arp_pour_adr_mac*) p;
	afficher_arp(a, verbo);
}

// ---------- niveau A ----------

/*
* Prepare, puis affiche l'entete d'une trame ethernet,
* puis relance sur son payload en fonction de son EtherType.
*/
void ethernet(const u_char *p, int verbo)
{
	const struct ether_header *eth = (struct ether_header*) p;
	afficher_ethernet(eth, verbo);
	switch (ntohs(eth->ether_type))
	{
	case ETHERTYPE_IP:
		ipv4(p + ETH_HLEN, verbo);
		break;
	case ETHERTYPE_ARP:
		arp(p + ETH_HLEN, verbo);
		break;
	case ETHERTYPE_IPV6:
		ipv6(p + ETH_HLEN, verbo);
		break;
	default:
		printf("Contenu de la trame non reconnu (EtherType 0x%04x)", ntohs(eth->ether_type));
		if (verbo != 1) printf("\n");
		break;
	}
}

// ---------------------------

/*
* Parse une chaine de caratere pour determiner le niveau de verbosite.
* (Cette fonction est necessaire du au mode de fonctionnement de PCAP.)
*/
int fverbo(u_char *args)
{
	if (args == NULL)
		return 1;
	switch (atoi((char*) args))
	{
	case 2:
		return 2;
	case 3:
		return 3;
	default:
		return 1;
	}
}

/*
* Cette foncion est appelee a chaque nouveau paquet.
* Elle relance sur ethernet().
*/
void nouvelle_trame(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{
	++cpt_paquets;
	int verbo = fverbo(args);
	if (verbo != 1)
		printf("\n----------------- Paquet %d -----------------\n", cpt_paquets);
	ethernet(p, verbo);
	if (verbo == 1)
		printf("\n");
}

/*
* Cette foncion parse les arguments passer par ligne de commande.
*/
void get_arguments(int argc, char *argv[], char **interface, char **fichier, char **filtre, char **verbosite)
{
	for (int i = 1; i < argc - 1; i += 2)
	{
		if (strcmp(argv[i], "-i") == 0)
			*interface = argv[i + 1];
		else if (strcmp(argv[i], "-o") == 0)
			*fichier = argv[i + 1];
		else if (strcmp(argv[i], "-f") == 0)
			*filtre = argv[i + 1];
		else if (strcmp(argv[i], "-v") == 0)
			*verbosite = argv[i + 1];
	}
}

/*
* Cette fonction ouvre l'interface pour l'analyse live,
* ou ouvre un fichier PCAP si un nom de fichier est precise.
*/
void ouverture_entree(char *fichier, char **interface, pcap_t **handle)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (fichier != NULL)
		*handle = pcap_open_offline(fichier, errbuf);
	else if (*interface != NULL)
		*handle = pcap_open_live(*interface, BUFSIZ, 1, 1000, errbuf);
	else
	{
		*interface = pcap_lookupdev(errbuf);
		if (*interface == NULL)
		{
			printf("Interface ou fichier non precise. L'interface par defaut a egalement echoue!\n");
			exit(-1);
		}
		*handle = pcap_open_live(*interface, BUFSIZ, 1, 1000, errbuf);
	}
	if (*handle == NULL)
	{
		printf("Ouverture de l'interface impossible. (verifiez le nom ou vos droits)\n");
		exit(-1);
	}
}

/*
* Cette fonction met en place un filtre BPF. Dans le cas ou aucun filtre
* n'est precise, elle n'a pas d'action.
*/
void installation_filtre(pcap_t *handle, char *interface, char *filtre)
{
	if (filtre != NULL)
	{
		struct bpf_program filtre_compile;
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 reseau;
		bpf_u_int32 masque;

		if (pcap_lookupnet(interface, &reseau, &masque, errbuf) == -1)
			masque = PCAP_NETMASK_UNKNOWN;

		if (pcap_compile(handle, &filtre_compile, filtre, 0, masque) == -1
				|| pcap_setfilter(handle, &filtre_compile) == -1)
		{
			printf("Filtre BPF invalide.\n");
			exit(-1);
		}
		printf("Filtre : %s\n", filtre);
	}
}

/*
* Cette fonction est appelee pour afficher un dernier message avant
* de terminer le programme.
*/
void message_fin(int sig_num)
{
	printf("\nAnalyse terminee (%d paquets)\n", cpt_paquets);
	fflush(stdout);
	exit(0);
}

/*
* Le main !
*/
int main(int argc, char *argv[])
{
	signal(SIGINT, message_fin); // capture Ctrl+C

	pcap_t *handle;
	char *interface = NULL;
	char *fichier = NULL;
	char *filtre = NULL;
	char *verbosite = NULL;

	get_arguments(argc, argv, &interface, &fichier, &filtre, &verbosite);
	ouverture_entree(fichier, &interface, &handle);
	installation_filtre(handle, interface, filtre);

	if (fichier != NULL)
		printf("Fichier : %s\n", fichier);
	else
		printf("Interface : %s\n", interface);

	pcap_loop(handle, -1, nouvelle_trame, (u_char*) verbosite);

	if (fichier != NULL)
		message_fin(0);
}
