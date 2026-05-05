from pathlib import Path

def analyze_pcap(pcap_path: Path) -> list:
    """Parsuje PCAP i zwraca IOC: IP, domeny, URL, SNI, protokoly, FTP, SMTP, SSH, RDP, SMB, NTP, DHCP"""
    iocs = []
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest, TLS, FTP, SMTP, SSH, RDP, SMB, NTP, DHCP
        packets = rdpcap(str(pcap_path))
        seen_ips = set(); seen_dns = set(); seen_urls = set(); seen_sni = set()
        seen_ftp = set(); seen_smtp = set(); seen_ssh = set(); seen_rdp = set(); seen_smb = set(); seen_ntp = set(); seen_dhcp = set()

        for pkt in packets:
            # Zewnetrzne IP (nie RFC1918, nie loopback)
            if IP in pkt:
                dst = pkt[IP].dst; src = pkt[IP].src
                for ip in (dst, src):
                    if ip not in seen_ips and not _is_private(ip):
                        seen_ips.add(ip)
                        iocs.append({'type': 'IP', 'value': ip,
                                     'proto': _proto(pkt), 'severity': 'MEDIUM'})

            # DNS queries (TCP/UDP)
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                domain = pkt[DNSQR].qname.decode().rstrip('.')
                if domain not in seen_dns and not domain.endswith('.local'):
                    seen_dns.add(domain)
                    iocs.append({'type': 'DNS', 'value': domain,
                                 'severity': _dns_severity(domain)})

            # HTTP (port 80)
            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith(('GET','POST','PUT','HEAD')):
                        line = payload.split('\n')[0].strip()
                        if line not in seen_urls:
                            seen_urls.add(line)
                            iocs.append({'type': 'HTTP', 'value': line, 'severity': 'HIGH'})
                except Exception:
                    pass

            # HTTPS SNI (port 443, TLS Client Hello)
            if TCP in pkt and pkt[TCP].dport == 443 and TLS in pkt:
                try:
                    tls = pkt[TLS]
                    if hasattr(tls, 'msg') and tls.msg:
                        for msg in tls.msg:
                            if hasattr(msg, 'ext') and msg.ext:
                                for ext in msg.ext:
                                    if hasattr(ext, 'servernames') and ext.servernames:
                                        for sn in ext.servernames:
                                            sni = sn.servername.decode() if isinstance(sn.servername, bytes) else str(sn.servername)
                                            if sni not in seen_sni:
                                                seen_sni.add(sni)
                                                iocs.append({'type': 'SNI', 'value': sni, 'severity': _dns_severity(sni)})
                except Exception:
                    pass

            # FTP (port 21)
            if TCP in pkt and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21) and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('USER ', 'PASS ', 'RETR ', 'STOR ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_ftp:
                            seen_ftp.add(cmd)
                            iocs.append({'type': 'FTP', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SMTP (port 25)
            if TCP in pkt and pkt[TCP].dport == 25 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('MAIL FROM:', 'RCPT TO:')):
                        addr = payload.split(':')[1].strip()
                        if addr not in seen_smtp:
                            seen_smtp.add(addr)
                            iocs.append({'type': 'SMTP', 'value': addr, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SSH (port 22)
            if TCP in pkt and pkt[TCP].dport == 22 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if 'SSH-' in payload:
                        version = payload.split('\n')[0].strip()
                        if version not in seen_ssh:
                            seen_ssh.add(version)
                            iocs.append({'type': 'SSH', 'value': version, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # RDP (port 3389)
            if TCP in pkt and pkt[TCP].dport == 3389 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith('\x03\x00\x00'):  # RDP header
                        if 'RDP' not in seen_rdp:
                            seen_rdp.add('RDP Connection')
                            iocs.append({'type': 'RDP', 'value': 'RDP Connection Attempt', 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # SMB (port 445)
            if TCP in pkt and pkt[TCP].dport == 445 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if '\xffSMB' in payload:  # SMB header
                        if 'SMB' not in seen_smb:
                            seen_smb.add('SMB Connection')
                            iocs.append({'type': 'SMB', 'value': 'SMB Connection Attempt', 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # NTP (port 123, UDP)
            if UDP in pkt and pkt[UDP].dport == 123 and NTP in pkt:
                try:
                    ntp = pkt[NTP]
                    server = pkt[IP].dst
                    if server not in seen_ntp:
                        seen_ntp.add(server)
                        iocs.append({'type': 'NTP', 'value': server, 'severity': 'LOW'})
                except Exception:
                    pass

            # DHCP (ports 67/68, UDP)
            if UDP in pkt and (pkt[UDP].dport == 67 or pkt[UDP].sport == 67) and DHCP in pkt:
                try:
                    dhcp = pkt[DHCP]
                    options = dhcp.options
                    for opt in options:
                        if opt[0] == 'domain':
                            domain = opt[1].decode() if isinstance(opt[1], bytes) else str(opt[1])
                            if domain not in seen_dhcp:
                                seen_dhcp.add(domain)
                                iocs.append({'type': 'DHCP', 'value': domain, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # HTTP responses (port 80)
            if TCP in pkt and pkt[TCP].sport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith('HTTP/'):
                        status_line = payload.split('\n')[0].strip()
                        if status_line not in seen_urls:
                            seen_urls.add(status_line)
                            iocs.append({'type': 'HTTP_RESP', 'value': status_line, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # POP3 (port 110)
            if TCP in pkt and pkt[TCP].dport == 110 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('USER ', 'PASS ', 'RETR ', 'DELE ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'POP3', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # IMAP (port 143)
            if TCP in pkt and pkt[TCP].dport == 143 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('LOGIN ', 'SELECT ', 'FETCH ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'IMAP', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # Telnet (port 23)
            if TCP in pkt and pkt[TCP].dport == 23 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload and not payload.startswith('\xff'):  # avoid telnet control chars
                        cmd = payload[:50]  # first 50 chars
                        if cmd not in seen_ssh:  # reuse set
                            seen_ssh.add(cmd)
                            iocs.append({'type': 'TELNET', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # SNMP (port 161, UDP)
            if UDP in pkt and pkt[UDP].dport == 161 and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) > 6 and payload[0] == 0x30:  # ASN.1 SEQUENCE
                        community = payload[6:].decode('utf-8', errors='ignore').split('\x00')[0]
                        if community and community not in seen_dhcp:  # reuse set
                            seen_dhcp.add(community)
                            iocs.append({'type': 'SNMP', 'value': community, 'severity': 'HIGH'})
                except Exception:
                    pass

            # IRC (port 6667)
            if TCP in pkt and pkt[TCP].dport == 6667 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('NICK ', 'USER ', 'JOIN ', 'PRIVMSG ')):
                        cmd = payload.split()[0] + ' ' + payload.split()[1] if len(payload.split()) > 1 else payload
                        if cmd not in seen_smtp:  # reuse set
                            seen_smtp.add(cmd)
                            iocs.append({'type': 'IRC', 'value': cmd, 'severity': 'HIGH'})
                except Exception:
                    pass

            # HTTP User-Agent and Referer (port 80)
            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    lines = payload.split('\n')
                    for line in lines:
                        if line.lower().startswith('user-agent:'):
                            ua = line.split(':', 1)[1].strip()
                            if ua not in seen_urls:
                                seen_urls.add(ua)
                                iocs.append({'type': 'HTTP_UA', 'value': ua, 'severity': 'LOW'})
                        elif line.lower().startswith('referer:'):
                            ref = line.split(':', 1)[1].strip()
                            if ref not in seen_urls:
                                seen_urls.add(ref)
                                iocs.append({'type': 'HTTP_REF', 'value': ref, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # TLS Certificate (port 443)
            if TCP in pkt and pkt[TCP].dport == 443 and TLS in pkt:
                try:
                    tls = pkt[TLS]
                    if hasattr(tls, 'msg') and tls.msg:
                        for msg in tls.msg:
                            if hasattr(msg, 'certificates') and msg.certificates:
                                for cert in msg.certificates:
                                    if hasattr(cert, 'tbsCertificate') and cert.tbsCertificate:
                                        subj = cert.tbsCertificate.subject
                                        if subj and str(subj) not in seen_sni:
                                            seen_sni.add(str(subj))
                                            iocs.append({'type': 'TLS_CERT', 'value': str(subj), 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # MySQL (port 3306)
            if TCP in pkt and pkt[TCP].dport == 3306 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith('\x00\x00\x00'):  # MySQL packet
                        query = payload[4:]  # skip length
                        if 'SELECT' in query or 'INSERT' in query or 'UPDATE' in query:
                            if query not in seen_smtp:  # reuse
                                seen_smtp.add(query)
                                iocs.append({'type': 'MYSQL', 'value': query[:100], 'severity': 'HIGH'})
                except Exception:
                    pass

            # PostgreSQL (port 5432)
            if TCP in pkt and pkt[TCP].dport == 5432 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if 'SELECT' in payload or 'INSERT' in payload or 'UPDATE' in payload:
                        query = payload.split('\x00')[0]
                        if query not in seen_smtp:  # reuse
                            seen_smtp.add(query)
                            iocs.append({'type': 'PGSQL', 'value': query[:100], 'severity': 'HIGH'})
                except Exception:
                    pass

            # LDAP (port 389)
            if TCP in pkt and pkt[TCP].dport == 389 and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) > 2 and payload[0] == 0x30:  # LDAP BER
                        op = payload[1]
                        if op == 0x60:  # bindRequest
                            iocs.append({'type': 'LDAP', 'value': 'LDAP Bind Attempt', 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # Kerberos (port 88, UDP/TCP)
            if (TCP in pkt and pkt[TCP].dport == 88) or (UDP in pkt and pkt[UDP].dport == 88):
                try:
                    payload = pkt[Raw].load if Raw in pkt else b''
                    if payload.startswith(b'\x6a'):  # AS-REQ
                        realm = payload[10:20].decode('utf-8', errors='ignore')  # approximate
                        if realm and realm not in seen_dhcp:  # reuse
                            seen_dhcp.add(realm)
                            iocs.append({'type': 'KERBEROS', 'value': realm, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # SIP (port 5060)
            if UDP in pkt and pkt[UDP].dport == 5060 and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    if payload.startswith(('INVITE ', 'REGISTER ', 'BYE ')):
                        method = payload.split()[0]
                        if method not in seen_smtp:  # reuse
                            seen_smtp.add(method)
                            iocs.append({'type': 'SIP', 'value': method, 'severity': 'MEDIUM'})
                except Exception:
                    pass

            # ICMP types
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                if icmp_type not in seen_ntp:  # reuse
                    seen_ntp.add(str(icmp_type))
                    iocs.append({'type': 'ICMP', 'value': f'ICMP Type {icmp_type}', 'severity': 'LOW'})

            # Anomalies: Large payloads, Rare ports
            if Raw in pkt:
                payload_len = len(pkt[Raw].load)
                if payload_len > 10000:  # arbitrary large
                    iocs.append({'type': 'ANOMALY', 'value': f'Large payload {payload_len} bytes', 'severity': 'MEDIUM'})
                port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                if port > 1024 and port not in [80,443,21,25,22,110,143,23,161,6667,3389,445,123,67,5060,3306,5432,389,88]:
                    iocs.append({'type': 'RARE_PORT', 'value': f'Port {port}', 'severity': 'LOW'})
    except Exception as e:
        iocs.append({'type': 'ERROR', 'value': str(e), 'severity': 'LOW'})
    return iocs

def _is_private(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4: return True
    a = int(parts[0]); b = int(parts[1])
    return (a==10 or a==127 or (a==172 and 16<=b<=31) or (a==192 and b==168) or a>=224)

def _proto(pkt) -> str:
    from scapy.all import TCP, UDP, ICMP
    if TCP in pkt:   return f'TCP/{pkt["TCP"].dport}'
    if UDP in pkt:   return f'UDP/{pkt["UDP"].dport}'
    return 'OTHER'

def _dns_severity(domain: str) -> str:
    suspicious = ['.ru','.cn','.tk','.xyz','.top','.click','dyndns','no-ip','ngrok']
    return 'HIGH' if any(s in domain for s in suspicious) else 'MEDIUM'
