import ipaddress

from tqdm import tqdm

from classes.domain_status import DomainStatus
from collections import defaultdict

from utils.dns.as_retriever import get_as


def analyze_ips(_domain_statuses: list[DomainStatus]):
    with tqdm(desc="IP Analysis", total=4, ncols=100, position=1, leave=False) as progress:
        # === Count Domains x IP ===
        _ip_count = defaultdict(lambda: {'domains': []})

        for _domain_status in tqdm(_domain_statuses, desc="IPs Mapping", ncols=100, position=2, leave=False):
            if _domain_status.use_spf:
                _spf_policy = _domain_status.dns_entries.get_rrs_spf(_domain_status.domain).get(0).policy

                _ipv4, _ipv6 = _spf_policy.get_ips(_qualifier='+')

                for _ip_net in _ipv4:
                    _ip_net = _ip_net['ip']

                    for _ip in _ip_net:
                        _ip = str(_ip)
                        if _domain_status.domain not in _ip_count[_ip]['domains']:
                            _ip_count[_ip]['domains'].append(_domain_status.domain)

        progress.update()

        # return dict(sorted(_ip_count.items(), key=lambda x: x[1]['count'], reverse=True))

        # todo MODIFICATO DA QUI

        # === Inverts Dictionary ===
        _grouped = defaultdict(lambda: {"ips": []})

        # Riorganizza per tupla dei domini
        for _ip, _data in tqdm(_ip_count.items(), desc="Building TMP Dictionary", ncols=100, position=2, leave=False):
            _domains_key = tuple(_data["domains"])  # Usiamo la tupla come chiave
            _grouped[_domains_key]["ips"].append(_ip)

        progress.update()

        # === Groups IPs ===

        for _domains, _data in tqdm(_grouped.items(), desc="Grouping IPs into networks", ncols=100, position=2, leave=False):
            _ip_objects = [ipaddress.IPv4Address(_ip) for _ip in _data["ips"]]
            _collapsed = list(ipaddress.collapse_addresses(_ip_objects))

            _data["ips"] = [str(_net) for _net in _collapsed]

        progress.update()

        # === Creates the final Dictionary NET --> Domains ===
        _final_dict = defaultdict(lambda: {'count': 0, 'domains': []})

        for _domains, _data in tqdm(_grouped.items(), desc="Building Final Dictionary", ncols=100, position=2, leave=False):
            for _net in _data["ips"]:
                _final_dict[_net]['count'] = len(_domains)
                _final_dict[_net]['autonomous_system'] = get_as(_net)              #todo AGGIUNTO
                _final_dict[_net]['domains'] = list(_domains)

        progress.update()

        return dict(sorted(_final_dict.items(), key=lambda x: x[1]['count'], reverse=True))
