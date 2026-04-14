from soc_pcap_tool.parsers import extract_tls_sni_from_payload, parse_http_payload


def test_parse_http_request_payload():
    payload = 'POST /login HTTP/1.1\r\nHost: evil-example.test\r\nUser-Agent: UnitTest\r\n\r\n'
    parsed = parse_http_payload(payload)
    assert parsed['http_method'] == 'POST'
    assert parsed['http_host'] == 'evil-example.test'
    assert parsed['http_uri'] == '/login'


def test_tls_parser_returns_tuple_for_invalid_payload():
    sni, hello = extract_tls_sni_from_payload(b'\x16\x03\x01\x00\x05hello')
    assert hello in {False, True}
    assert sni is None
