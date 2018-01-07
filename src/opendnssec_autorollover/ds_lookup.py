import dns.resolver
import dns.name
from socket import getaddrinfo

def get_ds_sets(zone):
    name = dns.name.from_text(zone)
    parent = name.parent()

    result = []

    for ns in dns.resolver.query(parent, 'NS'):
        for family, socktype, proto, canonname, sockaddr in getaddrinfo(ns.target.to_text(), 53):
            ns_addr = sockaddr[0]
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [ns_addr]
            try:
                ds = r.query(name, 'DS')
                result.append(set((d.key_tag, d.algorithm, d.digest_type, d.digest.hex()) for d in ds))
            except dns.resolver.NoAnswer:
                result.append(set())

    return result
