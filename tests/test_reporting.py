from soc_pcap_tool.models import PacketRecord
from soc_pcap_tool.reporting import build_report


def sample_records():
    return [
        PacketRecord(timestamp='2026-04-14T00:00:01+00:00', src_ip='10.0.0.5', dst_ip='8.8.8.8', protocol='DNS', src_port=53000, dst_port=53, length=90, dns_id=1, dns_query='evil-example.test', flow_id='f1'),
        PacketRecord(timestamp='2026-04-14T00:00:02+00:00', src_ip='8.8.8.8', dst_ip='10.0.0.5', protocol='DNS', src_port=53, dst_port=53000, length=110, dns_id=1, dns_is_response=True, dns_query='evil-example.test', dns_answers=['1.2.3.4'], flow_id='f1'),
        PacketRecord(timestamp='2026-04-14T00:00:05+00:00', src_ip='10.0.0.5', dst_ip='1.2.3.4', protocol='TLS/HTTPS', src_port=50123, dst_port=443, length=250, tls_sni='evil-example.test', tls_is_client_hello=True, flow_id='f2'),
        PacketRecord(timestamp='2026-04-14T00:00:06+00:00', src_ip='10.0.0.5', dst_ip='1.2.3.4', protocol='HTTP', src_port=50124, dst_port=80, length=300, http_method='POST', http_host='evil-example.test', http_uri='/login', flow_id='f3'),
    ]


def test_report_contains_pivots_and_pairs():
    report = build_report(sample_records(), mode='hunt', top_n=10, file_name='x.pcap')
    assert report['dns_pairs']
    assert report['host_summary']
    assert report['host_details']
    assert report['top_domains']
    assert report['findings']
