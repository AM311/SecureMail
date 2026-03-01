import ipaddress
from functools import lru_cache

from concurrent.futures import as_completed
from concurrent.futures.process import ProcessPoolExecutor

from tqdm import tqdm

from classes.domain_status import DomainStatus
from collections import defaultdict

from utils.dns.as_retriever import get_as


def process_domain(_domain_status):
    local_ip_count = defaultdict(set)

    if _domain_status.use_spf:
        _spf_policy = _domain_status.dns_entries.get_rrs_spf(_domain_status.domain).get(0).policy
        _ipv4, _ipv6 = _spf_policy.get_ips(_qualifier='+')

        for _ip_net in _ipv4:
            for _ip in _ip_net['ip']:
                local_ip_count[str(_ip)].add(_domain_status.domain)

    return local_ip_count


def analyze_ips(_domain_statuses: list[DomainStatus]):
    threshold = 50

    with tqdm(desc="IP Analysis", total=4, ncols=100, position=1, leave=False) as progress:
        # === Count Domains x IP ===
        _ip_count = defaultdict(set)
        # _ip_count = defaultdict(lambda: {'domains': []})

        with ProcessPoolExecutor(max_workers=4) as executor:
            for local_result in tqdm(
                    executor.map(process_domain, _domain_statuses, chunksize=100),
                    total=len(_domain_statuses),
                    desc="Building IP map",
                    ncols=100
            ):
                for ip, domains in local_result.items():
                    _ip_count[ip].update(domains)

        progress.update()

        # === Filtra IP per soglia ===
        _filtered_ip_count = {}

        for ip, domains in tqdm(_ip_count.items(), desc=f"Filtering (≥{threshold} domains)", ncols=100, position=2,
                                leave=False):
            if len(domains) >= threshold:
                _filtered_ip_count[ip] = domains

        progress.update()

        # === Inverts Dictionary ===
        _grouped = defaultdict(set)

        # Riorganizza per tupla dei domini
        for _ip, _domains in tqdm(_filtered_ip_count.items(), desc="Building TMP Dictionary", ncols=100, position=2,
                                  leave=False):
            _domains_key = frozenset(_domains)
            _grouped[_domains_key].add(_ip)

        progress.update()

        # === Creates the final Dictionary NET --> Domains ===

        @lru_cache(maxsize=None)
        def get_as_cached(ip_or_net: str):
            return get_as(ip_or_net)

        _final_dict = {}

        for _domains, _ips in tqdm(_grouped.items(), desc="Building Final Dictionary", ncols=100, position=2,
                                   leave=False):
            # Collassa gli IP in subnet (IPv4 only)
            ip_objs = [ipaddress.IPv4Address(ip) for ip in _ips]
            collapsed_nets = ipaddress.collapse_addresses(ip_objs)

            for net in collapsed_nets:
                net_str = str(net)
                if net_str not in _final_dict:
                    _final_dict[net_str] = {
                        'count': len(_domains),
                        'domains': list(_domains),
                        'autonomous_system': get_as_cached(net_str)
                    }

        progress.update()

        return dict(sorted(_final_dict.items(), key=lambda x: x[1]['count'], reverse=True))
