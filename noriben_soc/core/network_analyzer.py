from pathlib import Path

def analyze_pcap(pcap_path: Path) -> list:
    """Parsuje PCAP i zwraca IOC: IP, domeny, URL, protokoly"""
    iocs = []
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, HTTPRequest
        packets = rdpcap(str(pcap_path))
        seen_ips = set(); seen_dns = set(); seen_urls = set()

        for pkt in packets:
            # Zewnetrzne IP (nie RFC1918, nie loopback)
            if IP in pkt:
                dst = pkt[IP].dst; src = pkt[IP].src
                for ip in (dst, src):
                    if ip not in seen_ips and not _is_private(ip):
                        seen_ips.add(ip)
                        iocs.append({'type': 'IP', 'value': ip,
                                     'proto': _proto(pkt), 'severity': 'MEDIUM'})

            # DNS queries
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
