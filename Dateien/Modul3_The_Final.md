---
created: 2024-07-03T06:23
updated: 2024-09-06T16:54
---

TARGET DECK: Modul3


START
Einfach
Vorderseite:
### Erkläre den Begriff **DNS**

Rückseite:
Zentraler Bestandteil des Internets, der Domainnamen in IP-Adressen auflöst 
Es besteht aus verschiedenen Komponenten:
- Root-Nameservern
- TLD-Nameservern
- autoritativen Nameservern
- rekursiven Resolvern

END

### START
Einfach
Vorderseite:Erkläre den Begriff **mDNS**

Rückseite:
### **mDNS (Multicast DNS)** 

ein Netzwerkprotokoll, das Teil des Zeroconf-Systems (Zero Configuration Networking) ist. 

Es ermöglicht Geräten in einem **lokalen** Netzwerk (LAN), sich gegenseitig zu finden und zu verbinden, ohne dass ein dedizierter DNS-Server erforderlich ist.

END

START
Einfach
Vorderseite:
### Erkläre den Begriff **LLMNR**

Rückseite:
#### **LLMNR (Link-Local Multicast Name Resolution)** 

ein Netzwerkprotokoll, das verwendet wird, um Hostnamen in **lokalen Netzwerken** aufzulösen, wenn kein DNS-Server verfügbar ist. Es ermöglicht die Namensauflösung von Geräten im selben **Subnetz**, ähnlich wie **mDNS**, und wurde hauptsächlich für kleine Netzwerke ohne DNS-Infrastruktur entwickelt.

END

START
Einfach
Vorderseite:
### Welche privaten IP-Netze gibt es

Rückseite:
1. **Klasse A: 10.0.0.0 - 10.255.255.255**
   - Subnetzmaske: 255.0.0.0 (CIDR-Notation: 10.0.0.0/8)
   - Anzahl der Adressen: 16.777.216 (2^24)

2. **Klasse B: 172.16.0.0 - 172.31.255.255**
   - Subnetzmaske: 255.240.0.0 (CIDR-Notation: 172.16.0.0/12)
   - Anzahl der Adressen: 1.048.576 (2^20)

3. **Klasse C: 192.168.0.0 - 192.168.255.255**
   - Subnetzmaske: 255.255.0.0 (CIDR-Notation: 192.168.0.0/16)
   - Anzahl der Adressen: 65.536 (2^16)

END

START
Einfach
Vorderseite:
### Was ist **NAT**

Rückseite:
- **NAT - Network Address Translation**
- Verfahren in IP-Routern zur Verbindung lokaler Netzwerke mit dem Internet.
- Übersetzt private IP-Adressen in öffentliche IP-Adressen, um den Mangel an IPv4-Adressen zu umgehen.
- Mehrere Netzwerkgeräte mit verschiedenen privaten IP-Adressen können sich hinter einer einzigen öffentlichen IP-Adresse befinden.

END

START
Einfach
Vorderseite:
### Was ist **Carrier-grade NAT**

Rückseite:
Carrier-grade NAT ist eine spezielle Implementierung von NAT, die von Internetdienstanbietern verwendet wird, um Kosten zu senken und IPv4-Adressknappheit zu bewältigen, indem mehrere Kunden eines Providers eine gemeinsame öffentliche IP-Adresse verwenden.   

END

START
Einfach
Vorderseite:
### Was ist OWASP

Rückseite:
Das Open Web Application Security Project ist eine gemeinnützige Organisation, die sich darauf konzentriert, die Sicherheit von Software zu verbessern. OWASP stellt eine Vielzahl von Ressourcen, Tools, Dokumentationen und Projekten bereit,

Wir haben die OWASP Top 10 kennengelernt, eine Liste der zehn kritischsten Sicherheitsrisiken für Webanwendungen.

END

START
Einfach
Vorderseite:
### Was ist SQL

Rückseite:
SQL - Structured Query Language 

Eine standardisierte Programmiersprache zum Abrufen und Verwalten von Daten aus einer relationalen Datenbank

END

START
Einfach
Vorderseite:
### Erkläre den Begriff SQL Injection

Rückseite:
Ein Angreifer fügt schädlichen SQL-Code in eine Eingabe einer (Web-)Anwendung ein, die dann unbeabsichtigt als Teil einer SQL-Abfrage ausgeführt wird. Dadurch kann der Angreifer auf unbefugte Weise auf die Datenbank zugreifen.

END

START
Einfach
Vorderseite:
### Was ist nmap

Rückseite:
Nmap, Network Mapper, ist ein leistungsstarkes Open-Source-Werkzeug, um Informationen über verbundene Geräte, offene Ports und laufende Dienste zu sammeln.

**Was kann Nmap?**

- **Host-Discovery:** alle aktiven Hosts in einem Netzwerk finden.
- **Port-Scanning:** einzelne Hosts oder ganze Netzwerke nach offenen Ports scannen und  die zugehörigen Dienste ermitteln.
- **Dienst- und Betriebssystemerkennung:** den Typ des laufenden Dienstes und das Betriebssystem eines Geräts erkennen.
- **Vulnerabilitäts-Scanning:** in Verbindung mit anderen Tools Schwachstellen identifizieren.
- **Netzwerküberwachung:** Änderungen in einem Netzwerk verfolgen 

END

START
Einfach
Vorderseite:
### Erkläre das Tool CrackMapExec

Rückseite:
**CrackMapExec** (CME) ist ein Open-Source-Tool, das speziell für die Post-Exploitation entwickelt wurde. Es ermöglicht es einem Angreifer, nach einer erfolgreichen Erstzugriff auf ein System, die Kontrolle auf andere Systeme im Netzwerk auszuweiten.

**Was macht CrackMapExec?**

- **Passwort-Cracking:**
- **Sitzungsentführung:**
- **Lateral Movement:**
- **Privilege Escalation:**


END


START
Einfach
Vorderseite:
### Was macht man mit dem impacket - Paket? Erkläre zwei Komponenten daraus

Rückseite:
Impacket ist ein Paket für Netzwerkprotokolle, oft in Penetrationstests genutzt.

Zwei wichtige Komponenten:

impacket-GetNPUsers: Holt Kerberos-Hashes von Benutzern ohne Pre-Authentication.

impacket-GetUserSPNs: Extrahiert Kerberos-Hashes von Service Accounts.

END

START
Einfach
Vorderseite:
### Was ist SMB

Rückseite:
SMB (Server Message Block) ist ein Netzwerkprotokoll. Es ermöglicht, Dateien, Drucker und andere Ressourcen innerhalb eines Netzwerks gemeinsam zu nutzen. Es operiert auf OSI-Schicht 5 (Sitzungsschicht). Angreifer können mit Tools wie `CrackMapExec` oder `Metasploit` SMB-Enumerierungen durchführen, um Benutzerkonten, Freigaben oder schwache Konfigurationen zu entdecken, die zu lateralem Bewegung oder Privilegieneskalation führen. 

END


START
Einfach
Vorderseite:
### Was ist Hashcaracking, nenne zwei Tools dafür 

Rückseite:
**Hashcracking** ist der Prozess, bei dem ein **Hashwert** (eine verschlüsselte oder kodierte Form eines Passworts oder einer Datei) durch verschiedene Techniken zurück in den ursprünglichen Klartext (z. B. ein Passwort) übersetzt wird. 

Wir kennen folgende Arten:
1. Brute-Force-Angriff
2. Wörterbuchangriff
3. Rainbow-Tables
4. Kombinierte Angriffe

Wir kenn die Tools:
hashcat und john(the ripper)

END

START
Einfach
Vorderseite:
### Was ist OSINT, und welche Tools verwenden wir dafür

Rückseite:
OSINT (Open Source Intelligence) ist die Sammlung und Analyse von öffentlich zugänglichen Informationen aus offenen Quellen, um nützliche Erkenntnisse zu gewinnen.

Tools dafür:

Maltego
theHarvester

Tools:
theHarvester

END


START
Einfach
Vorderseite:
### Was ist Google Hacking

Rückseite:
Google Dorking bezeichnet das gezielte Ausnutzen der Suchmaschine Google, um Schwachstellen oder sensible Informationen zu finden, die versehentlich öffentlich zugänglich sind. Mithilfe spezieller Suchoperatoren können z.B. Datenbanken, Admin-Panels oder Login-Seiten entdeckt werden. Ein Beispiel-Dork wäre:
inurl:admin "login" (sucht nach Webseiten, die eine Admin-Login-Seite enthalten.)
Weitere Beispiele: Ungesicherte Druckernetzwerke & leicht zugängliche Webcams 

END


START
Einfach
Vorderseite:
### Welche AD-Serviceaccounts gibt es und wofür werden sie verwendet

Rückseite:
Serviceaccounts haben bestimmte Berechtigungen und Privilegien, die auf ihre Funktion zugeschnitten sind:

Lokale Servicekonten
- Lokales Systemkonto für Windows-Dienste, die uneingeschränkten Zugriff auf lokale Ressourcen benötigen
- Lokales Dienstkonto mit minimalen Rechten für Dienste, die im Netzwerk laufen müssen, aber keine hohen Privilegien benötigen
- Netzwerkdienstkonto wie das lokale Dienstkonto, aber mit erweiterten Netzwerkberechtigungen

Domainbasierte Servicekonten
- Domänen-Benutzerkonto reguläres Benutzerkonto, speziell für einen Dienst (zB SQL) erstellt wird.
- Verwaltetes Dienstkonto, MSA = Managed Service Account wird speziell für einen Dienst oder eine Anwendung im AD erstellt, Diese Konten sind speziell für automatische Passwortverwaltung und vereinfachte Verwaltung ausgelegt.
- Gruppenverwaltete Dienstkonten, gMSG sind erweiterete MSA für den Einsatz auf mehreren Computern in der Domäne zB für ein SQL Server Cluster
- Virtuelle Konten werden von Anwendungen benötigt, die keinen expliziten Benutzer brauchen zB der Taskmanager

END


START
Einfach
Vorderseite:
### Erkläre das Kerberos-Protokoll 

Rückseite:
Kerberos ist ein Netzwerk-Authentifizierungsprotokoll, das sicheres Single Sign-On ermöglicht. Es verwendet Tickets für die Authentifizierung, um Benutzer und Dienste zu verifizieren und den Zugriff zu kontrollieren.

Schritte:

TGT-Anfrage: Benutzer fordert ein Ticket Granting Ticket (TGT) an.
TGT-Erhalt: TGT wird vom KDC (Key Distribution Center) ausgestellt.
Service-Ticket-Anfrage: Benutzer fordert ein Service-Ticket an.
Service-Ticket-Nutzung: Das Ticket wird verwendet, um sich bei einem Dienst zu authentifizieren.

END


START
Einfach
Vorderseite:
### Beschreibe den Ablauf der Kerberos-Authentifizierung

Rückseite:
Die Kerberos-Authentifizierung läuft in vier Schritten ab:

Anfrage an KDC: Der Client fordert ein Ticket beim Key Distribution Center (KDC) an.
TGT-Erhalt: Der Client erhält ein Ticket Granting Ticket (TGT).
Service-Ticket-Anfrage: Mit dem TGT fordert der Client ein Service-Ticket an.
Service-Ticket-Nutzung: Der Client verwendet das Service-Ticket, um sich beim Ziel-Dienst zu authentifizieren.

END

START
Einfach
Vorderseite:
### Was ist Kerberosting

Rückseite:
Kerberoasting ist eine Technik, bei der Service-Accounts in einem Active Directory durch das Knacken von Kerberos Tickets (TGS) angegriffen werden. Ein Angreifer fordert von einem Domain-Controller ein verschlüsseltes Ticket für einen bestimmten Dienst an und versucht anschließend, dieses Ticket offline zu cracken, um an das Passwort des Service-Accounts zu gelangen. 
Ein gängiges Tool für Kerberoasting ist `Rubeus`. 
Beispiel: Rubeus.exe kerberoast /outfile:hashes.txt
Das extrahierte Ticket wird dann mit Tools wie `Hashcat` geknackt. 

END


START
Einfach
Vorderseite:
### Nenne die 6 Schritte der Schwachstellenanalyse

Rückseite:
1. Planung und Vorbereitung: Identifizieren von Systemen
2. Identifizieren von Schwachstellen
3. Analysieren, potentielle Auswirkungen, Bewertung der Schwachstelle
4. Risikobewertung: Ausnutzungswahrscheinlichkeit und Risikotoleranz
5. Behebung / Minderung
6. Laufende Überwachung & Überprüfung

END

START
Einfach
Vorderseite:
### Was ist ssh-Forwarding und was ist der Unterschied zwischen local und remote ssh-Forwarding

Rückseite:
SSH Tunneling ermöglicht verschlüsselte Kommunikation zwischen Client und entferntem Server.

Lokales SSH-Forwarding ermöglicht den Zugriff auf einen entfernten Dienst (z. B. Datenbank oder Webanwendung), als ob er lokal verfügbar wäre.

Remotes SSH-Forwarding ermöglicht es, einen Dienst von einem entfernten Server aus erreichbar zu machen, der auf einem lokalen Rechner oder auf einem anderen entfernten Rechner läuft.

END


START
Einfach
Vorderseite:
### Wofür nutzt man openvas und nessus

Rückseite:
OpenVAS und Nessus sind Vulnerability Scanner, die zur Identifikation von Sicherheitslücken in Netzwerken und Systemen genutzt werden.

OpenVAS: Open-Source Scanner für Schwachstellenanalyse.
Nessus: Kommerzieller Scanner mit breiter Unterstützung für Schwachstellenprüfungen.

END

START
Einfach
Vorderseite:
### erkläre das Tool SQL-Map und seinen Verwendungszweck

Rückseite:
SQL-Map ist ein Tool zur Automatisierung von SQL-Injection-Angriffen. Es ermöglicht das Testen und Ausnutzen von Schwachstellen in Webanwendungen, um Informationen aus der Datenbank zu extrahieren. Man könnte z.B. SQL-Map verwenden, um Datenbankversionen, Tabellenstrukturen und sensible Daten wie Passwörter zu enumerieren. 
Beispiel: sqlmap -u "http://example.com/vulnerable.php?id=1" --dbs
Dies listet alle Datenbanken auf dem Zielserver auf. Um Benutzerinformationen zu extrahieren, könnte man:
sqlmap -u "http://example.com/vulnerable.php?id=1" -D database_name -T users --dump

END


START
Einfach
Vorderseite:
### Wozu benutzt man das Tool Mimikatz

Rückseite:
Mimikatz ist ein Tool um Schwachstellen in Windows-Systemen zu identifizieren und auszunutzen. Wenn bereits Zugriff auf ein System besteht sind folgende Funktionen möglich:
- Passwortdumping im Klartexrt
- NTLM-Hashes extrahieren und damit Pass-the-Hash Authentifizierungen durchführen
- Kerberos Ticket Extraction und Pass-the-Ticket Angriffe im Kontext des Dam-Admins
- Golden Ticket-Angriff: Nach Extraktion des NTLM Hash des krbtgt-Kontos kann der Angreifer sich als jeder Domainuser ausgeben
- LSASS Dumping, Anmeldeinfos von Admins und Usern, die gerade angemeldet sind, können extrahiert werden.

END

START
Einfach
Vorderseite:
### Wozu benutzt man das Tool ldapsearch

Rückseite:
ldapsearch dient zum Abfragen und Durchsuchen von LDAP-Verzeichnissen nach Benutzerdaten und anderen Einträgen.

END

START
Einfach
Vorderseite:
### Wozu benutzt man das Tool DonPAPI

Rückseite:
DonPAPI extrahiert und entschlüsselt Anmeldeinformationen und Daten aus der Windows DPAPI, wie Passwörter und Browserdaten.

END

START
Einfach
Vorderseite:
### Was ist die DPAPI und wofür wird sie genutzt

Rückseite:
Die Data Protection API (DPAPI) wird von Windows verwendet, um sensible Daten wie Anmeldeinformationen, Zertifikate und Passwörter sicher zu verschlüsseln. Angreifer können Tools wie `mimikatz` verwenden, um DPAPI-verschlüsselte Daten zu entschlüsseln, wenn sie Zugriff auf die Benutzer- oder Systemkonten haben. DPAPI ist oft das Ziel bei Post-Exploitation-Aktivitäten, um lokal gespeicherte Passwörter zu extrahieren, die z.B. in Browsern oder VPN-Clients gespeichert sind.

END

START
Einfach
Vorderseite:
### Was ist WebFuzzing

Rückseite:
Eine Technik zum Aufdecken von Schwachstellen wie:

- SQL-Injection 
- Cross-Site-Scripting
- Buffer Overflows oder
- Command Injection 

END

START
Einfach
Vorderseite:
### Welche 3 Netzwerkprofile kennt die Windows Firewall

Rückseite:
Die Windows Firewall kennt drei Netzwerkprofile:

Privat (Private)
Öffentlich  (Public)
Domäne  (Domain)

END

START
Einfach
Vorderseite:
### Was ist PFSense, und wofür wird sie verwendet

Rückseite:
PFSense ist eine Firewall- und Router-Software auf FreeBSD-Basis, die in Netzwerken für Sicherheit und Routing verwendet wird. Wird oft als VPN-Gateway oder zur Implementierung von Intrusion Detection Systemen (IDS) wie `Snort` genutzt. PFSense bietet zahlreiche Funktionen wie Load-Balancing, Paketfilterung und VPN-Dienste. Wird oft in Unternehmensumgebungen eingesetzt, um Netzwerksicherheit zu gewährleisten und potenzielle Angriffsvektoren zu minimieren.

END

START
Einfach
Vorderseite:
### Erkläre die folgenden Begriffe im Kontext vom Active Directory

Wer darf einer der folgenden Gruppen hinzugefügt werden, und wer darf worauf zugreifen
Domain Locale Gruppe
Globale Gruppe 
Universale Gruppe

Rückseite:
Einer domänenlokalen Gruppe kann ich Nutzer anderer Domänen hinzufügen
Der Zugriff ist auf Ressourcen der lokalen Domain beschränkt

Einer globale Gruppe können nur Mitglieder der eigenen Domain zugefügt werden, 
Zugriff auf Ressourcen anderer Domänen ist erlaubt

Die einzige Gruppe ohne Einschränkung ist die Universelle, sie darf Mitglieder aus anderen Domains aufnehmen und auf Ressourcen anderer Domains zugreifen

END


START
Einfach
Vorderseite:
### Was ist IGDLA

Rückseite:
Das **IGDLA-Prinzip** ist ein Sicherheitskonzept, das in Microsoft Windows-Umgebungen verwendet wird, um den Zugriff auf Ressourcen innerhalb einer Domäne zu verwalten. 

Die Abkürzung IGDLA steht für 

**Identity 
Global 
Domain Local 
Access** 

und beschreibt eine hierarchische Struktur zur Verwaltung von Benutzer- und Gruppenrechten

END

START
Einfach
Vorderseite:
### Nenne drei Arten der Zugriffsteuerung und erkläre sie kurz


Rückseite:
Discretionary Access Control (DAC): Der Eigentümer eines Ressourcenobjekts entscheidet, wer darauf zugreifen darf und welche Berechtigungen gelten.

Mandatory Access Control (MAC): Zugriffskontrolle basiert auf festen Regeln und Klassifikationen, die vom Systemadministrator definiert werden. Benutzer können keine Berechtigungen ändern.

Role-Based Access Control (RBAC): Zugriff wird basierend auf Rollen vergeben, die Benutzern zugewiesen sind. Berechtigungen werden Rollen zugeordnet, nicht einzelnen Benutzern.


END


START
Einfach
Vorderseite:
### Erkläre den Unterschied zwischen SAM und LSA, welche Daten werden wo gespeichert

Rückseite:
Die Security Account Manager (SAM)-Datenbank speichert lokale Benutzerkonten und Passworthashes. Sie ist ein primäres Ziel, wenn es um die Extraktion von Passwörtern und Hashes geht (z.B. mit Tools wie `mimikatz` oder `pwdump`). Die Local Security Authority (LSA) hingegen verwaltet sicherheitsrelevante Informationen und speichert sensitive Daten wie Kerberos-Tickets und Sicherheitstoken. 
Während SAM Passwörter speichert, ist die LSA für die Handhabung von Authentifizierungsdaten und Sicherheitsrichtlinien zuständig.

END

START
Einfach
Vorderseite:
### Nenne sechs Social Engineering Techniken


Rückseite:
- Identitätsdiebstahl und Phishing
- Angst als sozialer Faktor
- Physische Täuschungen
- Online Täuschungen
- Quid pro Quo
- Deep Fakes

END


START
Einfach
Vorderseite:
### Wofür wird das Tool Bloodhound verwendet

Rückseite:
BloodHound analysiert Active Directory-Netzwerke, um Sicherheitsrisiken und Angriffspfade durch Berechtigungen und Beziehungen zu identifizieren.

END

START
Einfach
Vorderseite:
### Was ist Kerberos Pre-Authentication und welche Bedeutung hat sie im Kontext der Sicherheit eines Active Directory 

Rückseite:
Mechanismus, der sicherstellt, dass Benutzer ihre Identität nachweisen, bevor sie ein Ticket vom Domain-Controller erhalten. Der Benutzer verschlüsselt einen Zeitstempel mit seinem Passwort-Hash. Ohne Pre-Authentication könnten Angreifer versuchen, Anfragen ohne gültige Authentifizierung an den Domain-Controller zu senden und verschlüsselte Tickets offline zu cracken. Dies kann zu Brute-Force-Angriffen führen, weshalb die Pre-Authentication als sicherheitskritisch für Active Directory gilt.

END

START
Einfach
Vorderseite:
### Man-in-the-Middle in einem ActiveDirectory

Rückseite:
ein Angriff, bei dem sich ein Angreifer sich in die Kommunikation zwischen zwei legitimen Entitäten (z. B. einem Client und einem Server) einschaltet und die Kommunikation manipuliert, ohne dass die beteiligten Parteien davon Kenntnis haben.

END

START
Einfach
Vorderseite:
### Was ist ein Forrest

Rückseite:
Ein Forest umfasst alle Domains, die durch Vertrauensbeziehungen miteinander verknüpft sind -> ganzes GOAD Lab entspricht **einem** Forest

END

START
Einfach
Vorderseite:
### Nenne die 4 Windows Control Levels mit je einem typischen User 

Rückseite:
System - Kein Benutzer (höchste Kontrolle)
High Administrator - Administrator
Medium User - Normaler Benutzer
Low Guest - Gastbenutzer

END

START
Einfach
Vorderseite:
### Was ist der Unterschied zwischen lokaler und horizontaler Escalation of Privilege

Rückseite:
Lokale Escalation of Privilege: Erhöht Rechte innerhalb des gleichen Systems, z.B. von einem Standardbenutzer zu Administratorrechten.

Horizontale Escalation of Privilege: Erhält höhere Rechte auf einem anderen System oder Dienst, oft durch Zugriff auf zusätzliche Konten oder Systeme im Netzwerk.

END

START
Einfach
Vorderseite:
### Was macht ``visudo``

Rückseite:
Wichtiges Kommandozeilentool, das verwendet wird, um die Datei `/etc/sudoers` sicher zu bearbeiten und zu verwalten. Es gewährleistet, dass Syntaxfehler in der Datei vermieden werden, die das Sudo-System funktionsunfähig machen könnten. Das Tool sperrt die Datei während der Bearbeitung, um Konflikte zu verhindern, und prüft die Änderungen auf Fehler, bevor sie übernommen werden.

END


START
Einfach
Vorderseite:
### Erkläre den Unterschied zwischen Kerberoasting und AS-REP Roasting

Rückseite:

| Merkmal                  | Kerberoasting                                                                                     | AS-REP Roasting                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Zielkonten**           | Dienstkonten mit Service Principal Names (SPNs)                                                   | Benutzerkonten ohne Pre-Authentication (DONT_REQUIRE_PREAUTH)                                         |
| **Angeforderte Tickets** | Ticket Granting Service Tickets (TGS)                                                             | Authentication Service Response Tickets (AS-REP)                                                      |
| **Verschlüsselung**      | TGS-Tickets sind mit dem Hash des Dienstkontopassworts verschlüsselt                              | AS-REP-Tickets sind mit dem Hash des Benutzerpassworts verschlüsselt                                  |
| **Anforderung durch**    | Jeder authentifizierte Benutzer in der Domäne                                                     | Jeder authentifizierte Benutzer, wenn das Zielkonto Pre-Authentication deaktiviert hat                |
| **Typ des Angriffs**     | Offline-Knacken des TGS-Tickets                                                                   | Offline-Knacken des AS-REP-Tickets                                                                    |
| **Erhöhte Rechte**       | Kann Zugang zu privilegierten Dienstkonten gewähren                                               | Kann Zugang zu Benutzerkonten mit deaktivierter Pre-Authentication gewähren                           |
| Angriff mit              | impacket-GetUserSPNs                                                                              | GetNPUsers.py                                                                                         |
| Bsp                      | impacket-GetUserSPNs north.7kingdoms.lc/jeor.mormont:_L0ngCl@w_ -dc-ip 192.168.30.11 -request \*) | impacket-GetNPUsers sevenkingdoms.local/ -no-pass -usersfile userlist.txt -dc-ip 192.168.30.10  \*\*) |

END


START
Einfach
Vorderseite:
### Was sind SPN

Rückseite:
Ein **Service Principal Name (SPN)** ist ein eindeutiger Bezeichner, der in Windows Active Directory verwendet wird, um einen Dienst auf einem Netzwerk eindeutig zu identifizieren.

END


START
Einfach
Vorderseite:
### Erkläre den Unterschied zwischen IP-Forwarding und Peerforwarding

Rückseite:
IP-Forwarding: Leitet IP-Pakete zwischen verschiedenen Netzwerken weiter, typischerweise durch Router oder Gateways.

Peerforwarding: Leitet Pakete direkt zwischen Peers in einem Netzwerk weiter, ohne einen zentralen Router oder Gateway.

END


