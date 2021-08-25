#include "afficher.h"
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#define TAILLE_BUFF 1024

char buff_mac[ETH_ALEN * 3];
char buff[TAILLE_BUFF];
char buff2[TAILLE_BUFF];


char *str_addresse_mac(const u_int8_t addr[])
{
	char aux[4];
	buff_mac[0] = '\0';
	for (int i = 0; i < ETH_ALEN - 1; ++i)
	{
		sprintf(aux, "%02x:", addr[i]);
		strcat(buff_mac, aux);
	}
	sprintf(aux, "%02x", addr[ETH_ALEN - 1]);
	strcat(buff_mac, aux);
	return buff_mac;
}

int uniquement_zero(const u_int8_t *t, int n)
{
	int i;
	for (i = 0; i < n && t[i] == 0; ++i);
	return i == n;
}

char *str_contenu_hex(const u_char *p, int n, int ligne)
{
	char aux[4];
	buff2[0] = '\0';
	for (int i = 0; i < n - 1; ++i)
	{
		if (i % ligne == ligne - 1)
			sprintf(aux, "%02x\n", p[i]);
		else
			sprintf(aux, "%02x ", p[i]);
		strcat(buff2, aux);
	}
	sprintf(aux, "%02x", p[n - 1]);
	strcat(buff2, aux);

	return buff2;
}

char *str_contenu_ascii(const u_char *p, int n, int ligne)
{
	char aux[4];
	buff2[0] = '\0';
	for (int i = 0; i < n; ++i)
	{
		if (isprint(p[i]))
		{
			if (i % ligne == ligne - 1)
				sprintf(aux, "%c\n", p[i]);
			else
				sprintf(aux, "%c", p[i]);
			strcat(buff2, aux);
		}
	}

	return buff2;
}

char *str_contenu_dec(const u_char *p, int n, int ligne)
{
	char aux[4];
	buff2[0] = '\0';
	for (int i = 0; i < n - 1; ++i)
	{
		if (i % ligne == ligne - 1)
			sprintf(aux, "%02d\n", p[i]);
		else
			sprintf(aux, "%02d ", p[i]);
		strcat(buff2, aux);
	}
	sprintf(aux, "%02d", p[n - 1]);
	strcat(buff2, aux);

	return buff2;
}

void afficher_ethernet(const struct ether_header *eth, int verbo)
{
	if (verbo == 1)
	{
		// on ne fait rien
	}
	else if (verbo == 2)
	{
		printf("Trame  %s", str_addresse_mac(eth->ether_shost));
		printf(" ->  %s", str_addresse_mac(eth->ether_dhost));
		printf(",  EtherType 0x%04x\n", ntohs(eth->ether_type));
	}
	else
	{
		printf("Trame ethernet\n\t");
		printf("Addresse source :  %s", str_addresse_mac(eth->ether_shost));
		printf("\n\tAddresse destination :  %s", str_addresse_mac(eth->ether_dhost));
		printf("\n\tEtherType : 0x%04x\n", ntohs(eth->ether_type));
	}
}

void afficher_flags_ip4(u_short ip_off)
{
	if (ip_off & IP_RF) printf("1 ");
	else printf("0 ");
	if (ip_off & IP_DF) printf("1 ");
	else printf("0 ");
	if (ip_off & IP_MF) printf("1");
	else printf("0");
}

void afficher_ipv4(const struct ip *iph, int verbo)
{
	if (verbo == 1)
	{
		printf("IP ");
		printf("%s", inet_ntoa(iph->ip_src));
		printf(" -> ");
		printf("%s,  ", inet_ntoa(iph->ip_dst));
	}
	else if (verbo == 2)
	{
		printf("IPv4  ");
		printf("%s", inet_ntoa(iph->ip_src));
		printf(" -> ");
		printf("%s", inet_ntoa(iph->ip_dst));
		printf(",  IHL %u", iph->ip_hl);
		printf(",  Long %u", ntohs(iph->ip_len));
		printf(",  TTL %u", iph->ip_ttl);
		printf(",  Protocole %u\n", iph->ip_p);
	}
	else
	{
		printf("Datagramme IP\n\t");
		printf("Version : %u\n\t", iph->ip_v);
		printf("Longueur entete : %u\n\t", iph->ip_hl);
		printf("Type de service : %u\n\t", iph->ip_tos);
		printf("Longueur totale : %u\n\t", ntohs(iph->ip_len));
		printf("Identification : %u\n\t", ntohs(iph->ip_id));
		printf("Flags : "); afficher_flags_ip4(ntohs(iph->ip_off));
		printf("\n\tFragment offset : %u\n\t", ntohs(iph->ip_off) & IP_OFFMASK);
		printf("Duree de vie (TTL) : %u\n\t", iph->ip_ttl);
		printf("Protocole : %u\n\t", iph->ip_p);
		printf("Checksum entete : %u\n\t", ntohs(iph->ip_sum));
		printf("Adresse source : %s\n\t", inet_ntoa(iph->ip_src));
		printf("Adresse destination : %s\n", inet_ntoa(iph->ip_dst));
	}
}

void afficher_ipv6(const struct ip6_hdr *ip6, int verbo)
{
	inet_ntop(AF_INET6, &(ip6->ip6_src), buff, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ip6->ip6_dst), buff2, INET6_ADDRSTRLEN);
	if (verbo == 1)
	{
		printf("IP ");
		printf("%s", buff);
		printf(" -> ");
		printf("%s,  ", buff2);
	}
	else if (verbo == 2)
	{
		printf("IPv6  ");
		printf("%s", buff);
		printf(" -> ");
		printf("%s", buff2);
		printf(",  Long %u", ntohs(ip6->ip6_plen));
		printf(",  Type suiv %u", ip6->ip6_nxt);
		printf(",  Sauts max %u\n", ip6->ip6_hops);
	}
	else
	{
		printf("Datagramme IP\n\t");
		printf("Version : %u\n\t", ip6->ip6_vfc >> 4);
		printf("Classe de trafic : %u\n\t", ntohl(ip6->ip6_flow) & 0x0FF00000);
		printf("Label de flux : %u\n\t", ntohl(ip6->ip6_flow) & 0x000FFFFF);
		printf("Longueur payload : %u\n\t", ntohs(ip6->ip6_plen));
		printf("Type entete suivant : %u\n\t", ip6->ip6_nxt);
		printf("Sauts maximum : %u\n\t", ip6->ip6_hops);
		printf("Adresse source : %s\n\t", buff);
		printf("Adresse destination : %s\n", buff2);
	}
}

void afficher_options_tcp(u_char *t, const u_char *fin, int ack)
{
	uint8_t option;
	uint32_t valeur;
	int b = 1;
	while (t < fin && b)
	{
		option = *t;
		switch (option)
		{
		case 0:
			printf("\tOption fin\n");
			b = 0;
			break;
		case 1:
			printf("\tOption NOP (padding)\n");
			t += 1;
			break;
		case 2:
			t += 2;
			valeur = ntohs(*((uint16_t*) t));
			printf("\tOption taille max segment : %u\n", valeur);
			t += 2;
			break;
		case 3:
			t += 2;
			valeur = *t;
			printf("\tOption fenetre etendu : shift %u\n", valeur);
			t += 1;
			break;
		case 4:
			printf("\tOption ACK selectif\n");
			t += 2;
			break;
		case 8:
			t += 2;
			valeur = ntohl(*((uint32_t*) t));
			printf("\tOption timestamps :\n\t\tValeur : %u\n", valeur);
			t += 4;
			valeur = ntohl(*((uint32_t*) t));
			if (ack) printf("\t\tEcho : %u\n", valeur);
			else printf("\t\tEcho : flag ACK desactive\n");
			t += 4;
			break;
		default:
			printf("\tOption %u (inconnu)\n", option);
			b = 0;
			break;
		}
	}
}

void afficher_tcp(const struct tcphdr *tcph, int verbo)
{
	if (verbo == 1)
	{
		printf("TCP ");
		printf("%u", ntohs(tcph->source));
		printf(" -> ");
		printf("%u,  ", ntohs(tcph->dest));
	}
	else if (verbo == 2)
	{
		printf("TCP  ");
		printf("%u", ntohs(tcph->source));
		printf(" -> ");
		printf("%u", ntohs(tcph->dest));
		printf(", Sequence %u,  ", ntohl(tcph->seq));
		printf("Options : ");
		if (tcph->doff > 5) printf("oui (activez \"-v 3\")\n");
		else printf("non\n");
	}
	else
	{
		printf("Segment TCP\n\t");
		printf("Port source : %u\n\t", ntohs(tcph->source));
		printf("Port destination : %u\n\t", ntohs(tcph->dest));
		printf("Numero de sequence : %u\n\t", ntohl(tcph->seq));
		printf("Numero ACK : ");
		if (tcph->ack == 1) printf("%u\n\t", ntohl(tcph->ack_seq));
		else printf("flag ACK desactive\n\t");
		printf("Taille entete : %u\n\t", tcph->doff);
		printf("Flags actives :\n\t");
		if (tcph->urg == 1) printf("\tURG (urgent) : \t%u\n\t", tcph->urg);
		if (tcph->ack == 1) printf("\tACK (recepisse) : %u\n\t", tcph->ack);
		if (tcph->psh == 1) printf("\tPSH (push) : %u\n\t", tcph->psh);
		if (tcph->rst == 1) printf("\tRST (restaurer) : %u\n\t", tcph->rst);
		if (tcph->syn == 1) printf("\tSYN (synchroniser) : %u\n\t", tcph->syn);
		if (tcph->fin == 1) printf("\tFIN (la fin !) : %u\n\t", tcph->fin);
		printf("Taille fenetre : %u\n\t", ntohs(tcph->window));
		printf("Checksum globale : %u\n\t", ntohs(tcph->check));
		printf("Pointeur urgent : ");
		if (tcph->urg == 1) printf("%u\n", ntohl(tcph->urg_ptr));
		else printf("flag URG desactive\n");
		if (tcph->doff > 5) // si options TCP alors lancer leurs affichages
		{
			u_char *t = ((u_char*) tcph) + 5 * 4; //pointe sur le debut des options
			const u_char *fin = ((u_char*) tcph) + tcph->doff * 4;
			afficher_options_tcp(t, fin, tcph->ack);
		}
	}
}

void afficher_udp(const struct udphdr *udph, int verbo)
{
	if (verbo == 1)
	{
		printf("UDP ");
		printf("%u", ntohs(udph->source));
		printf(" -> ");
		printf("%u,  ", ntohs(udph->dest));
	}
	else if (verbo == 2)
	{
		printf("UDP  ");
		printf("%u", ntohs(udph->source));
		printf(" -> ");
		printf("%u", ntohs(udph->dest));
		printf(",  Longueur %u\n", ntohs(udph->len));
	}
	else
	{
		printf("Datagramme UDP\n\t");
		printf("Port source : %u\n\t", ntohs(udph->source));
		printf("Port destination : %u\n\t", ntohs(udph->dest));
		printf("Longueur : %u\n\t", ntohs(udph->len));
		printf("Checksum : 0x%x\n", ntohs(udph->check));
	}
}

void afficher_bootp(const struct bootp *bp, int verbo)
{
	if (verbo == 1)
	{
		printf("BOOTP ");
		if (bp->bp_op == BOOTREQUEST)
			printf("requete");
		else
			printf("reponse");
		printf(" (%u),  ", bp->bp_op);
	}
	else if (verbo == 2)
	{
		printf("BOOTP  ");
		if (bp->bp_op == BOOTREQUEST)
			printf("requete");
		else
			printf("reponse");
		printf(" (code %u),  ", bp->bp_op);
		char *s;
		if (bp->bp_htype == 1) s = "ethernet";
		else s = "inconnu";
		printf("Type adr %s (%u),  ", s, bp->bp_htype);
		printf("Longeur adr %u,  ", bp->bp_hlen);
		printf("Secondes %u\n", ntohs(bp->bp_secs));
	}
	else
	{
		printf("Message BOOTP\n\t");
		printf("Code operation : %u ", bp->bp_op);
		if (bp->bp_op == BOOTREQUEST)
			printf("(requete)");
		else
			printf("(reponse)");
		printf("\n\tType adresse physique : %u\n\t", bp->bp_htype);
		printf("Longueur adresse physique : %u\n\t", bp->bp_hlen);
		printf("Nombre de saut : %u\n\t", bp->bp_hops);
		printf("Id transaction : %u\n\t", ntohl(bp->bp_xid));
		printf("Secondes depuis boot : %u\n\t", ntohs(bp->bp_secs));
		printf("Flags : 0x%x\n\t", ntohs(bp->bp_flags));
		printf("Adresse IP choisi par le client : %s\n\t", inet_ntoa(bp->bp_ciaddr));
		printf("Adresse IP donnee au client : %s\n\t", inet_ntoa(bp->bp_yiaddr));
		printf("Adresse IP serveur : %s\n\t", inet_ntoa(bp->bp_siaddr));
		printf("Adresse IP de l'agent de relais : %s\n\t", inet_ntoa(bp->bp_giaddr));
		printf("Adresse physique client :  %s", str_addresse_mac(bp->bp_chaddr));
		printf("\n\tNom du serveur hote : ");
		if (uniquement_zero(bp->bp_sname, 64)) printf(" (00000000...)\n\t");
		else printf("format inconnu\n\t");
		printf("Nom fichier de boot : ");
		if (uniquement_zero(bp->bp_file, 128)) printf(" (00000000...)\n\t");
		else printf("format inconnu\n\t");
		printf("Vendor-specific : ");
		if (bp->bp_vend[0] == 0x63 && bp->bp_vend[1] == 0x82 && bp->bp_vend[2] == 0x53 && bp->bp_vend[3] == 0x63)
			printf("DHCP (voir section suivante)\n");
		else if (uniquement_zero(bp->bp_vend, 64)) printf(" (00000000...)\n");
		else printf("inconnu\n");
	}
}

int option_dhcp(u_char **d, char **option, char **valeur)
{
	*valeur = "";
	int bool_val = 1;
	int code = (int) **d;
	*d += 1;
	int l = (int) **d;
	*d += 1;
	if (code == 53)
	{
		*option = "message type";
		switch ((int) **d) {
		case 01:
			*valeur = "discover (01)";
			break;
		case 02:
			*valeur = "offer (02)";
			break;
		case 03:
			*valeur = "request (03)";
			break;
		case 05:
			*valeur = "ack (05)";
			break;
		case 07:
			*valeur = "release (07)";
			break;
		default:
			*valeur = "inconnu";
			break;
		}
	}
	else
	{
		switch (code) {
		case 01:
			*option = "subnet mask";
			*valeur = inet_ntoa(*((struct in_addr*) *d));
			break;
		case 02:
			*option = "time offset";
			sprintf(buff, "%u", ntohl(*((int*) *d)));
			*valeur = buff;
			break;
		case 03:
			*option = "router";
			*valeur = inet_ntoa(*((struct in_addr*) *d));
			break;
		case 06:
			*option = "DNS";
			buff[0] = '\0';
			for (int i = 0; i < l; i += 4)
			{
				sprintf(buff2, "%s ", inet_ntoa(*((struct in_addr*) (*d + i))));
				strcat(buff, buff2);
			}
			*valeur = buff;
			break;
		case 12:
			*option = "host name";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 15:
			*option = "domain name";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 28:
			*option = "broadcast address";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 44:
			*option = "netbios over TCP/IP name server";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 47:
			*option = "netbios over TCP/IP scope";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 50:
			*option = "requested IP address";
			*valeur = inet_ntoa(*((struct in_addr*) *d));
			break;
		case 51:
			*option = "lease time";
			sprintf(buff, "%u", ntohl(*((int*) *d)));
			*valeur = buff;
			break;
		case 54:
			*option = "server identifier";
			*valeur = inet_ntoa(*((struct in_addr*) *d));
			break;
		case 55:
			*option = "parameter request list";
			*valeur = str_contenu_dec(*d, l, TAILLE_BUFF);
			break;
		case 58:
			*option = "renewal time";
			sprintf(buff, "%u", ntohl(*((int*) *d)));
			*valeur = buff;
			break;
		case 59:
			*option = "rebind time";
			sprintf(buff, "%u", ntohl(*((int*) *d)));
			*valeur = buff;
			break;
		case 61:
			*option = "client identifier";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 66:
			*option = "TFTP server";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 82:
			*option = "agent information";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 90:
			*option = "authentication";
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		case 120:
			*option = "SIP server";
			*valeur = inet_ntoa(*((struct in_addr*) (*d + 1)));
			break;
		case 255:
			*option = "end";
			*valeur = "";
			bool_val = 0;
			break;
		default:
			sprintf(buff, "option %u", code);
			*option = buff;
			*valeur = str_contenu_hex(*d, l, TAILLE_BUFF);
			break;
		}
	}
	*d += l;
	return bool_val;
}

void afficher_dhcp(u_char *d, int verbo)
{
	char *option, *valeur = "";
	if (verbo == 1)
	{
		printf("DHCP ");
		option_dhcp(&d, &option, &valeur);
		printf("%s", valeur);
	}
	else if (verbo == 2)
	{
		printf("Options DHCP  ");
		int n = 3, i;
		for (i = 1; i < n && option_dhcp(&d, &option, &valeur); ++i)
			printf("%s %s,  ", option, valeur);
		if (i == 3) option_dhcp(&d, &option, &valeur);
		printf("%s %s\n", option, valeur);
	}
	else
	{
		int protection = 30, i = 0;
		printf("Options DHCP\n");
		while (option_dhcp(&d, &option, &valeur) && ++i < protection)
			printf("\t%s : %s\n", option, valeur);
		if (i == protection)
			printf("\toption fin manquant\n");
		else
			printf("\t%s\n", option);
	}
}

void afficher_dns(const struct entete_dns *d, int verbo)
{
	if (verbo == 1)
	{
		printf("DNS ");
		if ((ntohs(d->flags) & DNS_QR) == 0)
			printf("requete");
		else printf("reponse");
	}
	else if (verbo == 2)
	{
		printf("DNS  ");
		if ((ntohs(d->flags) & DNS_QR) == 0)
			printf("requete");
		else printf("reponse");
		printf(",  ID %x,  ", ntohs(d->id));
		if ((ntohs(d->flags) & DNS_OPCODE) == 0)
			printf("Opcode standard");
		else if ((ntohs(d->flags) & DNS_OPCODE) == 1)
			printf("Opcode inverse");
		else printf("status du serveur");
		printf(",  Nombre de questions %u", ntohs(d->nb_requetes));
		printf(",  Nombre de reponses %u\n", ntohs(d->nb_reponses));
	}
	else
	{
		printf("Message DNS\n\t");
		printf("Identifiant : %x\n\t", ntohs(d->id));
		printf("Type de message : ");
		if ((ntohs(d->flags) & DNS_QR) == 0)
			printf("requete");
		else printf("reponse");
		printf("\n\tOpcode : ");
		if ((ntohs(d->flags) & DNS_OPCODE) == 0)
			printf("URL -> IP (standard)");
		else if ((ntohs(d->flags) & DNS_OPCODE) == 1)
			printf("IP -> URL (inverse)");
		else printf("status du serveur");
		printf("\n\tNombre de questions : %u\n\t", ntohs(d->nb_requetes));
		printf("Nombre de reponses : %u\n\t", ntohs(d->nb_reponses));
		printf("Nombre de serveurs : %u\n\t", ntohs(d->nb_serveur));
		printf("Ressources additionnelles : %u\n", ntohs(d->nb_rr_plus));
	}
}

void afficher_arp(const struct arp_pour_adr_mac *a, int verbo)
{
	if (verbo == 1)
	{
		printf("ARP ");
		if (ntohs(a->opcode) == 1)
		{
			sprintf(buff, "%s", inet_ntoa(*((struct in_addr*) a->ip_cible)));
			sprintf(buff2, "%s", inet_ntoa(*((struct in_addr*) a->ip_envoyeur)));
			printf("requete -> Qui a %s ? Repondez a %s", buff, buff2);
		}
		else if (ntohs(a->opcode) == 2)
		{
			sprintf(buff, "%s", inet_ntoa(*((struct in_addr*) a->ip_envoyeur)));
			sprintf(buff2, "%s", str_addresse_mac(a->mac_envoyeur));
			printf("reponse -> %s appartient a %s", buff, buff2);
		}
		else printf("opcode %u", ntohs(a->opcode));
	}
	else if (verbo == 2)
	{
		printf("ARP  ");
		if (ntohs(a->opcode) == 1)
		{
			sprintf(buff, "%s", inet_ntoa(*((struct in_addr*) a->ip_cible)));
			sprintf(buff2, "%s", inet_ntoa(*((struct in_addr*) a->ip_envoyeur)));
			printf("requete,  Qui a l'adresse %s ? Repondez a cette adresse : %s\n", buff, buff2);
		}
		else if (ntohs(a->opcode) == 2)
		{
			sprintf(buff, "%s", inet_ntoa(*((struct in_addr*) a->ip_envoyeur)));
			sprintf(buff2, "%s", str_addresse_mac(a->mac_envoyeur));
			printf("reponse,  L'adresse IP %s appartient a l'adresse MAC %s\n", buff, buff2);
		}
		else printf("opcode %u\n", ntohs(a->opcode));
	}
	else
	{
		printf("Message ARP\n\t");
		printf("Format addresse physique : %u\n\t", ntohs(a->format_m));
		printf("Format addresse protocole : 0x%x\n\t", ntohs(a->format_p));
		printf("Longeur addresse physique : %u\n\t", a->long_m);
		printf("Longeur addresse protocole : %u\n\t", a->long_p);
		printf("Opcode : %u\n\t", ntohs(a->opcode));
		printf("Adresse MAC envoyeur : %s\n\t", str_addresse_mac(a->mac_envoyeur));
		printf("Adresse IP envoyeur : %s\n\t", inet_ntoa(*((struct in_addr*) a->ip_envoyeur)));
		printf("Adresse MAC cible : %s\n\t", str_addresse_mac(a->mac_cible));
		printf("Adresse IP cible : %s\n", inet_ntoa(*((struct in_addr*) a->ip_cible)));
	}
}

char *get_cmd_ftp(const char *c)
{
	buff[0] = '\0';
	int i;
	for (i = 0; isalpha(c[i]); ++i)
		buff[i] = c[i];
	buff[i] = '\0';
	return buff;
}

char *get_code_ftp(const char *c)
{
	buff[0] = *c;
	buff[1] = *(c + 1);
	buff[2] = *(c + 2);
	buff[3] = '\0';
	return buff;
}

void afficher_ftp(const char *c, const char *fin, int verbo)
{
	if (c >= fin)
	{
		if (verbo == 1) printf("FTP tcp seul");
		else if (verbo == 2) printf("FTP  tcp seul, pas de contenu\n");
		else printf("Message FTP\n\ttcp seul, pas de contenu\n");
		return;
	}
	if (verbo == 1)
	{
		if (isalpha(*c)) printf("FTP requete %s", get_cmd_ftp(c));
		else if (isdigit(*c)) printf("FTP reponse %s", get_code_ftp(c));
		else printf("FTP format inconnu");
	}
	else if (verbo == 2)
	{
		if (isalpha(*c)) printf("FTP  requete ");
		else if (isdigit(*c)) printf("FTP  reponse ");
		else
		{
			printf("FTP  format inconnu\n");
			return;
		}
		int ligne = 55;
		int i = 0;
		while (c < fin && isprint(*c) && i < ligne)
		{
			printf("%c", *c);
			++c;
			++i;
		}
		if (i == ligne) printf("...");
		printf("\n");
	}
	else
	{
		printf("Message FTP\n");
		printf("\tType : ");
		if (isalpha(*c))
		{
			printf("requete\n");
			char *s = get_cmd_ftp(c);
			printf("\tCommande : %s\n", s);
			c += strlen(s);
		}
		else if (isdigit(*c))
		{
			printf("reponse\n");
			printf("\tCode : %s\n", get_code_ftp(c));
			c += 3;
		}
		else
		{
			printf("format inconnu\n");
			return;
		}
		int tab_plus = 10;
		printf("\tMessage : ");
		int ligne = 50;
		int i = 0;
		while (isprint(*c) && c < fin)
		{
			if (i % ligne == ligne - 1) printf("\n\t%*s", tab_plus, "");
			printf("%c", *c);
			++c;
			++i;
		}
		printf("\n");
	}
}

char *get_mot_http(const char **c)
{
	// la premiere boucle sert a se placer au debut d'un mot
	int i;
	for (i = 0; (*c)[i] == ' ' || (*c)[i] == '\r' || (*c)[i] == '\n'; ++i)
	{}
	*c += i;
	for (i = 0; (*c)[i] != ' ' && (*c)[i] != '\r' && (*c)[i] != '\n'; ++i)
		buff[i] = (*c)[i];
	buff[i] = '\0';
	*c += i;
	return buff;
}

char *get_ligne(const char **c, const char *fin)
{
	// la premiere boucle sert a se placer au debut d'une ligne
	int i;
	for (i = 0; (*c + i < fin) && !isprint((*c)[i]); ++i)
	{}
	*c += i;
	for (i = 0; (*c + i < fin) && isprint((*c)[i]); ++i)
		buff[i] = (*c)[i];
	buff[i] = '\0';
	*c += i;
	return buff;
}

void afficher_http(const char *c, const char *fin, int b_requete, int verbo)
{
	if (c >= fin)
	{
		if (verbo == 1) printf("HTTP tcp seul");
		else if (verbo == 2) printf("HTTP  tcp seul, pas de contenu\n");
		else printf("Contenu HTTP\n\ttcp seul, pas de contenu\n");
		return;
	}
	buff[0] = c[0]; buff[1] = c[1]; buff[2] = c[2]; buff[3] = '\0';
	if (strcmp(buff, "HTT") != 0 && strcmp(buff, "GET") != 0 && strcmp(buff, "POS") != 0)
	{
		if (verbo == 1) printf("PDU HTTP fragment");
		else if (verbo == 2) printf("PDU HTTP  Ce paquet semble etre un fragment (paquet initial trop large)\n");
		else printf("Contenu HTTP\n\tce paquet semble etre un fragment d'un PDU HTTP\n");
		return;
	}
	if (verbo == 1)
	{
		if (b_requete) printf("HTTP requete %s", get_mot_http(&c));
		else
		{
			get_mot_http(&c); // le premier mot n'est pas utilise
			printf("HTTP reponse %s ", get_mot_http(&c));
		}
	}
	else if (verbo == 2)
	{
		if (b_requete)
		{
			printf("HTTP  requete %s,  ", get_mot_http(&c));
			get_ligne(&c, fin); // la premiere ligne n'est pas utilise
			printf("%s\n", get_ligne(&c, fin));
		}
		else
		{
			get_mot_http(&c);
			printf("HTTP  reponse %s,  ", get_mot_http(&c));
			get_ligne(&c, fin);
			printf("%s\n", get_ligne(&c, fin));
		}
	}
	else
	{
		int nb_ligne = 4;
		int taille_ligne = 50;
		printf("Contenu HTTP\n\tType : ");
		if (b_requete) printf("requete\n");
		else printf("reponse\n");
		for (int i = 0; i < nb_ligne; ++i)
			printf("\t%.*s\n", taille_ligne, get_ligne(&c, fin));
		if (c < fin) printf("\t...\n");
	}
}

char *get_option_telnet(u_char opt)
{
	switch (opt)
	{
	case TELOPT_ECHO:
		return "Echo";
	case TELOPT_SGA:
		return "Suppress go ahead";
	case TELOPT_STATUS:
		return "Status";
	case TELOPT_TM:
		return "Timing mark";
	case TELOPT_TTYPE:
		return "Terminal type";
	case TELOPT_NAWS:
		return "Window size";
	case TELOPT_TSPEED:
		return "Terminal speed";
	case TELOPT_LFLOW:
		return "Remote flow control";
	case TELOPT_LINEMODE:
		return "Linemode";
	case TELOPT_OLD_ENVIRON:
		return "(Old) environment var";
	case TELOPT_AUTHENTICATION:
		return "Authenticate";
	case TELOPT_NEW_ENVIRON:
		return "(New) environment var";
	case TELOPT_BINARY:
		return "Binary transmission";
	default:
		sprintf(buff2, "Code %u", opt);
		return buff2;
	}
}

char *get_cmd_telnet(const u_char **p)
{
	*p += 1;
	u_char type = **p;
	*p += 1;
	switch (type)
	{
	case DONT:
		sprintf(buff, "Don't %s", get_option_telnet(**p));
		*p += 1;
		return buff;
	case DO:
		sprintf(buff, "Do %s", get_option_telnet(**p));
		*p += 1;
		return buff;
	case WONT:
		sprintf(buff, "Won't %s", get_option_telnet(**p));
		*p += 1;
		return buff;
	case WILL:
		sprintf(buff, "Will %s", get_option_telnet(**p));
		*p += 1;
		return buff;
	case SB:
		return "Interpret as subnegotiation";
	case SE:
		return "End sub negotiation";
	case NOP:
		return  "Nop";
	default:
		sprintf(buff, "type %u", type);
		return buff;
	}
}

void afficher_telnet(const u_char *p_, const u_char *fin, int verbo)
{
	const u_char *p = p_;
	if (p >= fin)
	{
		if (verbo == 1) printf("TELNET tcp seul");
		else if (verbo == 2) printf("TELNET  tcp seul, pas de contenu\n");
		else printf("Message TELNET\n\ttcp seul, pas de contenu\n");
		return;
	}
	if (verbo == 1)
	{
		printf("TELNET message");
		return;
	}

	// Ce qui suit est le cas ou il y a des cmd et/ou des donnees a afficher :

	if (verbo == 2) printf("TELNET  ");
	else printf("Message TELNET\n");
	int taille_ligne = 50;
	int vide = 1;
	while (p < fin - 1)
	{
		if (*p == IAC && *(p + 1) == IAC) // pour le mode binaire
			p += 2;
		else if (*p == IAC) // une commande est detectee
		{
			vide = 0;
			if (verbo == 2)
			{
				printf("Commande %s ...\n", get_cmd_telnet(&p));
				break;
			}
			else
				printf("\tCommande : %s\n", get_cmd_telnet(&p));
		}
		else if ((*p == '\r' && *(p + 1) == '\n')
							|| (*p == '\n' && *(p + 1) == '\r')) // une ligne ASCII
		{
			vide = 0;
			p += 2;
			char *s = get_ligne((const char**) &p, (char*) fin);
			if (verbo == 2)
			{
				printf("\\r\\n");
				if (strlen(s) > 0)
					printf(" %.*s ...\n", taille_ligne, s);
				break;
			}
			else
			{
				printf("\tDonnees : \\r\\n\n");
				if (strlen(s) > 0)
					printf("\tDonnees : %.*s\n", taille_ligne, s);
			}
		}
		else ++p;
	}
	if (vide)
	{
		if (verbo == 3) printf("\tDonnees : ");
		int n = fin - p_;
		printf("%.*s\n", taille_ligne, str_contenu_ascii(p_, n, n + 1));
	}
}

char *get_code_smtp(const char *c)
{
	int i;
	for (i = 0; i < 3 && isdigit(c[i]); ++i)
		buff[i] = c[i];
	buff[i] = '\0';
	return buff;
}

void afficher_smtp(const char *c, const char *fin, int b_requete, int verbo)
{
	if (c >= fin)
	{
		if (verbo == 1) printf("SMTP tcp seul");
		else if (verbo == 2) printf("SMTP  tcp seul, pas de contenu\n");
		else printf("Contenu SMTP\n\ttcp seul, pas de contenu\n");
		return;
	}
	if (verbo == 1)
	{
		printf("SMTP ");
		if (b_requete) printf("C -> S");
		else printf("S -> C (code %s)", get_code_smtp(c));
	}
	else if (verbo == 2)
	{
		int taille_ligne = 49;
		printf("SMTP  ");
		if (b_requete) printf("Client -> Serveur,  ");
		else printf("Serveur -> Client,  ");
		printf("%.*s", taille_ligne, get_ligne(&c, fin));
		if (c + 2 < fin) printf(" ...");
		printf("\n");
	}
	else
	{
		int taille_ligne = 70;
		int nb_ligne_max = 20;
		int n = 0;
		printf("Contenu SMTP\n\tDirection : ");
		if (b_requete) printf("Client -> Serveur\n");
		else printf("Serveur -> Client\n");
		while (c + 2 < fin && n < nb_ligne_max)
		{
			printf("\t%.*s\n", taille_ligne, get_ligne(&c, fin));
			++n;
		}
		if (c + 2 < fin) printf("\t...\n");
	}
}

char *get_cmd_pop(const char *c)
{
	snprintf(buff, 5, "%s", c);
	if (strcmp(buff, "CAPA") == 0)
		return "CAPA";
	if (strcmp(buff, "QUIT") == 0)
		return "QUIT";
	if (strcmp(buff, "AUTH") == 0)
		return "AUTH";
	if (strcmp(buff, "USER") == 0)
		return "USER";
	if (strcmp(buff, "PASS") == 0)
		return "PASS";
	if (strcmp(buff, "QUIT") == 0)
		return "QUIT";
	if (strcmp(buff, "STAT") == 0)
		return "STAT";
	if (strcmp(buff, "LIST") == 0)
		return "LIST";
	if (strcmp(buff, "RETR") == 0)
		return "RETR";
	if (strcmp(buff, "DELE") == 0)
		return "DELE";
	if (strcmp(buff, "NOOP") == 0)
		return "NOOP";
	if (strcmp(buff, "RSET") == 0)
		return "RSET";
	if (strcmp(buff, "APOP") == 0)
		return "APOP";
	if (strcmp(buff, "TOP ") == 0)
		return "TOP";
	if (strcmp(buff, "UIDL") == 0)
		return "UIDL";
	else return "";
}

void afficher_pop(const char *c, const char *fin, int b_requete, int verbo)
{
	if (c >= fin)
	{
		if (verbo == 1) printf("POP tcp seul");
		else if (verbo == 2) printf("POP  tcp seul, pas de contenu\n");
		else printf("Contenu POP\n\ttcp seul, pas de contenu\n");
		return;
	}
	if (verbo == 1)
	{
		printf("POP ");
		if (b_requete) printf("C -> S %s", get_cmd_pop(c));
		else
		{
			char *s;
			if (c[0] == '+' && c[1] == 'O')
				s = "+OK";
			else if (c[0] == '-' && c[1] == 'E')
				s = "-ERR";
			else s = "";
			printf("S -> C %s", s);
		}
	}
	else if (verbo == 2)
	{
		int taille_ligne = 49;
		printf("POP  ");
		if (b_requete) printf("Client -> Serveur,  ");
		else printf("Serveur -> Client,  ");
		printf("%.*s", taille_ligne, get_ligne(&c, fin));
		if (c + 2 < fin) printf(" ...");
		printf("\n");
	}
	else
	{
		int taille_ligne = 70;
		int nb_ligne_max = 20;
		int n = 0;
		printf("Contenu POP\n\tDirection : ");
		if (b_requete) printf("Client -> Serveur\n");
		else printf("Serveur -> Client\n");
		while (c + 2 < fin && n < nb_ligne_max)
		{
			printf("\t%.*s\n", taille_ligne, get_ligne(&c, fin));
			++n;
		}
		if (c + 2 < fin) printf("\t...\n");
	}
}

void afficher_imap(const char *c, const char *fin, int b_requete, int verbo)
{
	if (c >= fin)
	{
		if (verbo == 1) printf("IMAP tcp seul");
		else if (verbo == 2) printf("IMAP  tcp seul, pas de contenu\n");
		else printf("Contenu IMAP\n\ttcp seul, pas de contenu\n");
		return;
	}
	if (verbo == 1)
	{
		printf("IMAP ");
		if (b_requete) printf("C -> S");
		else printf("S -> C");
	}
	else if (verbo == 2)
	{
		int taille_ligne = 49;
		printf("IMAP  ");
		if (b_requete) printf("Client -> Serveur,  ");
		else printf("Serveur -> Client,  ");
		printf("%.*s", taille_ligne, get_ligne(&c, fin));
		if (c + 2 < fin) printf(" ...");
		printf("\n");
	}
	else
	{
		int taille_ligne = 70;
		int nb_ligne_max = 20;
		int n = 0;
		printf("Contenu IMAP\n\tDirection : ");
		if (b_requete) printf("Client -> Serveur\n");
		else printf("Serveur -> Client\n");
		while (c + 2 < fin && n < nb_ligne_max)
		{
			printf("\t%.*s\n", taille_ligne, get_ligne(&c, fin));
			++n;
		}
		if (c + 2 < fin) printf("\t...\n");
	}
}
