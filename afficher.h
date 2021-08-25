#ifndef AFFICHER_H
#define AFFICHER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "bootp.h"

#define DNS_QR 0b1000000000000000
#define DNS_OPCODE 0b0111100000000000

struct entete_dns
{
  uint16_t	id;
  uint16_t	flags;
  uint16_t	nb_requetes;
  uint16_t	nb_reponses;
  uint16_t	nb_serveur;
  uint16_t	nb_rr_plus;
};

struct arp_pour_adr_mac
{
  uint16_t format_m;
  uint16_t format_p;
  uint8_t long_m;
  uint8_t long_p;
  uint16_t opcode;
  uint8_t mac_envoyeur[ETH_ALEN];
  uint8_t ip_envoyeur[4];
  uint8_t mac_cible[ETH_ALEN];
  uint8_t ip_cible[4];
};

/*
* Affiche le contenu d'une trame ethernet (avec verbo = 1, rien n'est affiche.)
*/
void afficher_ethernet(const struct ether_header *eth, int verbo);

/*
* Affiche le contenu d'un datagramme IPv4.
*/
void afficher_ipv4(const struct ip *iph, int verbo);

/*
* Affiche le contenu d'un datagramme IPv6.
*/
void afficher_ipv6(const struct ip6_hdr *ip6, int verbo);

/*
* Affiche le contenu d'un segment TCP.
*/
void afficher_tcp(const struct tcphdr *tcph, int verbo);

/*
* Affiche le contenu d'un datagramme UDP.
*/
void afficher_udp(const struct udphdr *udph, int verbo);

/*
* Affiche l'entete d'un message BOOTP, sans les options vendor specific.
*/
void afficher_bootp(const struct bootp *bp, int verbo);

/*
* Affiche les options DHCP.
*/
void afficher_dhcp(u_char *d, int verbo);

/*
* Affiche l'entete d'un message DNS.
*/
void afficher_dns(const struct entete_dns *d, int verbo);

/*
* Affiche un message ARP.
*/
void afficher_arp(const struct arp_pour_adr_mac *a, int verbo);

/*
* Affiche le contenu (les commandes ou les reponses) d'un message FTP.
*/
void afficher_ftp(const char *c, const char *fin, int verbo);

/*
* Affiche le contenu d'un paquet HTTP.
*/
void afficher_http(const char *c, const char *fin, int b_requete, int verbo);

/*
* Affiche le contenu d'un message Telnet.
*/
void afficher_telnet(const u_char *p_, const u_char *fin, int verbo);

/*
* Affiche le contenu d'un PDU SMTP.
*/
void afficher_smtp(const char *c, const char *fin, int b_requete, int verbo);

/*
* Affiche le contenu d'un PDU POP.
*/
void afficher_pop(const char *c, const char *fin, int b_requete, int verbo);

/*
* Affiche le contenu d'un PDU IMAP.
*/
void afficher_imap(const char *c, const char *fin, int b_requete, int verbo);




#endif /* AFFICHER_H */
