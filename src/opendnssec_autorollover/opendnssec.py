from subprocess import check_output, check_call, CalledProcessError
from collections import defaultdict

## DNSKEY

def parse_dnskey(key):
    zone, ttl, cls, typ, flags, proto, alg, pubkey = key.split()
    assert cls == b'IN'
    assert typ == b'DNSKEY'
    assert int(proto) == 3
    return (zone.decode('ascii'), (int(flags), int(alg), pubkey.decode('ascii')))

def get_dnskeys_by_state(state):
    output = check_output(['ods-enforcer', 'key', 'export', '--all', '--keytype', 'KSK', '--keystate', state])
    return [parse_dnskey(key) for key in output.splitlines()]

def get_pending_dnskey_changes():
    zones = defaultdict(list)

    for state in ['ready', 'retire']:
        for zone, key in get_dnskeys_by_state(state):
            zones[zone].append((state, key))

    return zones


## DS

def parse_ds(ds):
    zone, ttl, cls, typ, keytag, key_alg, hash_alg, hash_val = ds.split()
    assert cls == b'IN'
    assert typ == b'DS'
    return (zone.decode('ascii'), (int(keytag), int(key_alg), int(hash_alg), hash_val.decode('ascii')))

def get_ds_by_state(state):
    output = check_output(['ods-enforcer', 'key', 'export', '--ds', '--all', '--keytype', 'KSK', '--keystate', state])
    return [parse_ds(key) for key in output.splitlines() if not key.startswith(b';')]

def get_pending_ds_changes():
    zones = defaultdict(list)

    for state in ['ready', 'retire']:
        for zone, key in get_ds_by_state(state):
            zones[zone].append((state, key))

    return zones

def notify_ds(zone, keytag, action):
    assert action in ['seen', 'gone']
    zone = zone.rstrip('.')
    keytag = str(int(keytag))
    try:
        check_call(['ods-enforcer', 'key', 'ds-{}'.format(action), '--zone', zone, '--keytag', keytag])
    except CalledProcessError as e:
        # ds-gone only changes the internal state, so the DS records stays in
        # the retire state for some while after issuing a ds-gone command
        if action == 'gone' and e.returncode != 11:
            raise
