# Wireshark-traffic-analysis


# Objective
The objective of this lab was to perform detailed network traffic analysis using Wireshark within the TryHackMe Wireshark: Traffic Analysis room. The lab focused on understanding how to inspect packet captures (PCAP files), identify malicious or suspicious network activity, reconstruct attacker behavior, and extract actionable indicators of compromise (IOCs). This exercise simulated real-world SOC investigations by requiring in-depth protocol analysis, filtering techniques, and traffic correlation to determine the nature and impact of potential security incidents.


# Lab Focus 

# Understanding Packet Capture (PCAP) Analysis

* Navigating large packet captures efficiently

* Interpreting traffic at multiple OSI layers

* Identifying relevant conversations within noisy datasets

# Protocol Analysis & Traffic Inspection

* DNS traffic analysis (queries, responses, suspicious domains)

* HTTP request/response inspection (GET/POST methods, status codes, file downloads)

* TCP stream analysis and session reconstruction

* Identifying abnormal ports, suspicious IP communication, and unusual traffic patterns

# Traffic Filtering & Investigation Techniques

* Using display filters (e.g., ip.addr, tcp.port, dns, http)

* Following TCP streams to reconstruct full sessions

* Applying time-based and protocol-based filtering to isolate malicious activity

# Indicator of Compromise (IOC) Identification

* Extracting malicious IP addresses, domains, and file names

* Identifying command-and-control (C2) traffic patterns

* Detecting cleartext credentials or data exfiltration attempts

# STEPS

I conducted a deep-dive network traffic investigation using Wireshark through the TryHackMe "Traffic Analysis" module. This project simulated real-world scenarios including reconnaissance detection, Man-in-the-Middle (MitM) attacks, and exploit identification.
​Below is a structured report of my methodology, findings, and the specific filters I employed to isolate malicious activity.

# ​1. Reconnaissance Analysis (Nmap Scans)
​My first task was to identify scanning patterns within the packet captures to determine the scope of attacker reconnaissance.

**TCP Connect Scans:** I isolated full three-way handshakes typically associated with Nmap's -sT scan.

<img width="624" height="292" alt="image" src="https://github.com/user-attachments/assets/4e28f238-855d-4172-a52f-d8e890845e23" />

<img width="624" height="290" alt="image" src="https://github.com/user-attachments/assets/dbba7a76-61fd-43a6-809c-07f3420dfe4c" />

* ​Filter Used: **tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024**  and **tcp.port==80**
 
* ​Finding: Identified 1000 scan packets targeting port 80. It was a TCP connect scan due to the three-way handshake being present.
   
**​UDP Port Scanning:** I looked for ICMP "Destination Unreachable" messages to identify closed UDP ports.

<img width="624" height="306" alt="image" src="https://github.com/user-attachments/assets/ccfa952c-268e-4cb1-bdc3-f47876c70bb0" />

<img width="624" height="292" alt="image" src="https://github.com/user-attachments/assets/efa8fc49-ac9c-4a74-97e8-e41ff5dd8888" />

* ​Filter Used: **icmp.type==3 && icmp.code==3
udp && !(icmp.type==3 and icmp.code==3)**

* ​Finding: Discovered 1083 closed port messages and identified an open service on UDP port 68 using the filters. 

# ​2. MitM and ARP Poisoning Investigation

​I investigated a potential ARP spoofing incident where an attacker intercepted local traffic.

<img width="624" height="292" alt="image" src="https://github.com/user-attachments/assets/2349e4db-d4f3-446f-81b7-cd4621f2d3eb" />


* ​Attacker Identification: I looked for duplicate MAC addresses claiming multiple IP addresses.
  
* ​Filter Used: **arp.duplicate-address-detected or arp.duplicate-address-fram** and 
**eth.src == 00:0c:29:e2:18:b4 && arp.opcode == 1**

* Finding: Attacker MAC 00:0c:29:e2:18:b4 was found spoofing the gateway with multiple IP addresses.
* Credential Sniffing: Once the MitM was confirmed, I filtered for unencrypted HTTP POST requests to find stolen credentials.

<img width="624" height="340" alt="image" src="https://github.com/user-attachments/assets/1a8d254d-806e-4907-86bc-9b7276be2b61" />

<img width="624" height="295" alt="image" src="https://github.com/user-attachments/assets/c425e45d-e0b7-4d9c-b69e-f74d1e5dde6d" />


* Filter Used: **http.request.method == "POST" or (urlencoded-form.key == "uname") && (urlencoded-form.key == "pass")**, **http.request.full_uri=="http://testphp.vulnweb.com/userinfo.php"**  and
**http.request.method==POST and urlencoded-form contains "uname"**

* ​Finding: Recovered 6 sets of credentials, including the password clientnothere! for user Client986.
  
# ​3. Cleartext Protocol Analysis (FTP & HTTP)

​Analyzing unencrypted protocols is critical for identifying data exfiltration and unauthorized access.
​FTP Analysis

* ​Brute Force Detection: I searched for failed login attempts (Response 530).

<img width="624" height="542" alt="image" src="https://github.com/user-attachments/assets/306c9350-0647-4d96-9bc9-fa2e0a0dc5ca" />

<img width="624" height="368" alt="image" src="https://github.com/user-attachments/assets/05869247-90c7-4b6e-bcd5-c2a106c6d32f" />


* Filter Used: **ftp.response.code == 530** and
**ftp.response.code == 213**

* ​Finding: Logged 737 incorrect login attempts. The file size accessed by the ftp account was 39424
  
* **Unauthorized Uploads**: I manually looked through the FTP traffic, since I had trouble identifying the correct command to filter on. Originally I tried filtering on FILE, but later I found out that we have to use STOR. I tracked the STOR command to find files uploaded by the adversary. You can then see the whole TCP conversation by right-clicking the packet and pressing Conversation Filter -> TCP. 

<img width="624" height="287" alt="image" src="https://github.com/user-attachments/assets/401c1885-b7a4-418e-a959-15557e6e85b7" />

<img width="624" height="534" alt="image" src="https://github.com/user-attachments/assets/59ddf969-1c8a-46ec-8af6-584d7f10102f" />


* ​Filter Used: **ftp.request.command == "STOR"**

* Finding: The attacker uploaded resume.doc and attempted to escalate permissions using CHMOD 777.
  
# ​HTTP & Log4j Analysis
**Anomaly Detection**: I analyzed User-Agent strings to find non-standard or misspelled headers.
* ​Filter Used: http.user_agent

**(http.user_agent contains "$") or (http.user_agent contains "==")**

**http.request.method == "POST"**

**(frame contains "jndi") or (frame contains "Exploit")**

* ​Finding: Identified 6 anomalous types; packet 52 contained a subtle spelling error used for evasion.
  
**​Log4j Exploit**: I located the initial JNDI injection attempt in a POST request.
* Filter Used: **http.request.method == "POST"**
  
* ​Finding: The attack began at packet 444, communicating with the malicious IP 62[.]210[.]130[.]250.

# ​4. Advanced Analysis (Decryption & Tunneling)
​I moved beyond cleartext to analyze encrypted streams and covert channels.

* ​HTTPS Decryption: Using the provided KeysLogFile.txt, I decrypted TLS traffic to inspect HTTP2 headers.

**Steps:** We can dig  up the domain name first by looking in the packet details under TLS -> Handshake Protocol -> Extension: server_name. 

<img width="624" height="464" alt="image" src="https://github.com/user-attachments/assets/0d81f580-f4c7-400c-8c69-cc2b35b01022" />



I chose to apply this(server_Name) field as a column, to find the answer more easily as seen below.  The relevant frame is number 16.

<img width="624" height="100" alt="image" src="https://github.com/user-attachments/assets/f244b494-b4eb-4d27-ac1f-6d5a124480ed" />


Thereafter I  
Loaded keys via: 
Edit –> Preferences –> Protocols –> TLS –> (Pre)-Master-Secret log filename and then  input the _keysLogFile.txt_ filepath  into the Master-Secret log filename field. This menu is also accessible by right-clicking the TLS section in the packet details pane. 

<img width="624" height="430" alt="image" src="https://github.com/user-attachments/assets/7e54e27f-b92d-4ba3-89a6-71666593e370" />


After which, I went ahead to  filter via http2 traffic then scrolled to frame 322 and underneath HTTP2 in the packet details the authority header field was noted as safebrowsing[.]googleapis[.]com.



Since there are only 100 or so packets, I looked around manually. I came across frame #1576 which includes a HTTP GET call to a flag.txt file.

<img width="624" height="123" alt="image" src="https://github.com/user-attachments/assets/e0b9170e-8e56-4fae-8f05-b7e8ca96b5e2" />


But this is not the way to export the txt. We can go to File – > Export Objects -> HTTP( as seen below)

<img width="624" height="496" alt="image" src="https://github.com/user-attachments/assets/0e3230c7-fc02-4c0b-97b7-599b0b9215e1" />


I opened the HTTP object list, chose the first file on the list, saved it to the desktop, and then opened it

<img width="624" height="470" alt="image" src="https://github.com/user-attachments/assets/ac5f51a3-39a8-40f3-ab2f-027296819431" />


The  flag was found on opening the file, positioned above and below the image of the alien figure. 


<img width="624" height="455" alt="image" src="https://github.com/user-attachments/assets/40f40d6b-cf6c-4d83-bcaf-34af89630ce4" />


* Filters: 
**tls.handshake.type == 1** and **http.2**

* Finding: Isolated 115 HTTP2 packets and found a suspicious authority header for safebrowsing[.]googleapis[.]com. The packets were decrypted and the flag was found to be FLAG{THM-PACKETMASTER}

**Tunneling Detection:** I inspected ICMP and DNS traffic for data encapsulation. 
○Steps Using the display filter  data.len > 64 and icmp I filtered ICMP traffic with a larger than normal packet size. Looking at the packet bytes, the SSH banner was noted.

<img width="624" height="419" alt="image" src="https://github.com/user-attachments/assets/ace13a94-5357-43fe-aaf9-c85b410430f4" />


**Steps**: I started  by scanning for known signatures. Using the filter dns contains "dnscat" allows you to isolate packets specifically associated with dnscat2. This tool is frequently used for creating covert communication channels through DNS queries.​ The first search yielded no viable results, so I pivoted to identifying unusually long domain names, which often hide encoded data. Started with dns.qry.name.len > 15 and !mdns to exclude standard Multicast DNS and find long queries. I then refined the results by tightening the parameters. Increasing the threshold to dns.qry.name.len > 55 and !mdns filters out most legitimate traffic. ​By using the stricter length filter, I   effectively isolated the noise, located the suspicious main domain and defanged it. The  suspicious exfiltration domain was called dataexfil[.]com.

<img width="624" height="416" alt="image" src="https://github.com/user-attachments/assets/a9c03b8c-d502-4fd8-8488-c60b674cdd40" />


* ​Filter Used: **icmp (checking for unusual payload size)** and **dns contains "dnscat"**

 dns dns.qry.name.len > 15 and !mdns 

* Finding: Identified an SSH tunnel over ICMP and a suspicious exfiltration domain dataexfil[.]com.
  
# ​5. Remediation: Firewall ACL Generation
​To conclude the investigation, I utilized Wireshark’s built-in tools to generate firewall rules based on the identified Indicators of Compromise (IoCs).


