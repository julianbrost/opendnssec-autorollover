import unittest
import os

from opendnssec_autorollover import opendnssec

class OpenDNSSECInterfaceTest(unittest.TestCase):
    def test_normalize_zone_root(self):
        self.assertEqual(opendnssec.normalize_zone('.'), '.')

    def test_normalize_zone_no_change(self):
        self.assertEqual(opendnssec.normalize_zone('example.org'), 'example.org')

    def test_normalize_zone_trim(self):
        self.assertEqual(opendnssec.normalize_zone('example.org.'), 'example.org')

    def test_parse_dnskey_spaces(self):
        inp = b'example.org. 3600 IN DNSKEY 257 3 13 QaKao0U+ru1z8cwhmDYQLio04pw1r2FcFe34hKp1g4W90GNrkaMFJIMG4IK3wxwNlgD2qDWe1FMjWkUCo5WxTQ=='
        res = ('example.org', (257, 13, 'QaKao0U+ru1z8cwhmDYQLio04pw1r2FcFe34hKp1g4W90GNrkaMFJIMG4IK3wxwNlgD2qDWe1FMjWkUCo5WxTQ=='))
        self.assertEqual(opendnssec.parse_dnskey(inp), res)

    def test_parse_dnskey_tabs(self):
        inp = b'example.org.\t3600\tIN\tDNSKEY\t257\t3\t13\tQaKao0U+ru1z8cwhmDYQLio04pw1r2FcFe34hKp1g4W90GNrkaMFJIMG4IK3wxwNlgD2qDWe1FMjWkUCo5WxTQ=='
        res = ('example.org', (257, 13, 'QaKao0U+ru1z8cwhmDYQLio04pw1r2FcFe34hKp1g4W90GNrkaMFJIMG4IK3wxwNlgD2qDWe1FMjWkUCo5WxTQ=='))
        self.assertEqual(opendnssec.parse_dnskey(inp), res)

    # TODO: get_dnskeys_by_state, get_pending_dnskey_changes, get_ds_by_state,
    # get_pending_ds_changes, notify_ds. But requires some way to mock
    # ods-enforcer calls.
