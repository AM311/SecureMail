from collections import defaultdict

import pandas as pd

from tqdm import tqdm

from classes.domain_status import DomainStatus
from utils.dns.as_retriever import get_as
from utils.mail.organizational_domains import get_organizational_domain


# ==========

# todo TQDM

#todo GESTIRE CASI IN CUI NON CI SONO RISULTATI PER IL DOMINIO

def analyze_dns_results(_domain_statuses: list[DomainStatus]):
    _servers_providers_as = {}

    def get_servers_providers_as(_domain):
        _domain_data = {}

        # === NS ===

        _domain_data_ns = {}

        _servers_ns = []
        _providers_ns = set()
        _as_ns = set()

        for _rr in _domain_status.dns_entries.get_rrs_ns(_domain):
            _ns = _rr.value

            try:
                # If more than 1 IPs are available, arbitrarily keeps the first one
                _ip = _domain_status.dns_entries.get_rrs_a(_ns).get(0).value
                _as = _domain_status.dns_entries.get_rrs_a(_ns).get(0).autonomous_system

                # If a CNAME entry exists, keeps the value of this one
                _rr_list_cname = _domain_status.dns_entries.get_rrs_cname(_ns)

                if not _rr_list_cname.is_empty():
                    _ns = _rr_list_cname.get(0).value

                _servers_ns.append({_ns: {'ip': _ip, 'as': _as}})

                # ---

                _org_domain = get_organizational_domain(_ns)
                _providers_ns.add(_org_domain)
                _as_ns.add(_as['asn'])
            except Exception:
                continue

        _domain_data_ns['servers'] = _servers_ns
        _domain_data_ns['providers'] = list(_providers_ns)
        _domain_data_ns['as'] = list(_as_ns)

        _domain_data['NS'] = _domain_data_ns

        # === MX ===

        _domain_data_mx = {}

        _servers_mx = []
        _providers_mx = set()
        _as_mx = set()

        for _rr in _domain_status.dns_entries.get_rrs_mx(_domain):
            _mx = _rr.value

            try:
                # If more than 1 IPs are available, arbitrarily keeps the first one
                _ip = _domain_status.dns_entries.get_rrs_a(_mx).get(0).value
                _as = _domain_status.dns_entries.get_rrs_a(_mx).get(0).autonomous_system

                # If a CNAME entry exists, keeps the value of this one
                _rr_list_cname = _domain_status.dns_entries.get_rrs_cname(_mx)

                if not _rr_list_cname.is_empty():
                    _mx = _rr_list_cname.get(0).value

                _servers_mx.append({_mx: {'ip': _ip, 'as': _as}})

                _org_domain = get_organizational_domain(_mx)
                _providers_mx.add(_org_domain)
                _as_mx.add(_as['asn'])
            except Exception:
                continue

        _domain_data_mx['servers'] = _servers_mx
        _domain_data_mx['providers'] = list(_providers_mx)
        _domain_data_mx['as'] = list(_as_mx)

        _domain_data['MX'] = _domain_data_mx

        # === A (Policies MTA-STS) ===

        _domain_data_web = {}

        _servers_web = []
        _providers_web = set()
        _as_web = set()

        if _domain_status.use_mtasts:
            _mtasts_domain = f"mta-sts.{_domain}"
            for _rr in _domain_status.dns_entries.get_rrs_a(_mtasts_domain):
                _server = _mtasts_domain

                try:
                    _ip = _rr.value
                    _as = _rr.autonomous_system

                    # If a CNAME entry exists, keeps the value of this one
                    _rr_list_cname = _domain_status.dns_entries.get_rrs_cname(_server)

                    if not _rr_list_cname.is_empty():
                        _server = _rr_list_cname.get(0).value

                    _servers_web.append({_server: {'ip': _ip, 'as': _as}})

                    _org_domain = get_organizational_domain(_server)
                    _providers_web.add(_org_domain)
                    _as_web.add(_as['asn'])
                except Exception:
                    continue

        _domain_data_web['servers'] = _servers_web
        _domain_data_web['providers'] = list(_providers_web)
        _domain_data_web['as'] = list(_as_web)

        _domain_data['WEB'] = _domain_data_web

        # ===

        _domain_data['org_domain'] = get_organizational_domain(_domain)

        return _domain_data

    def analyze_providers_as(_servers_providers_as):
        # Tracciamento dei domini per provider separato per NS e MX
        provider_domain_count_ns = defaultdict(int)
        provider_domain_count_mx = defaultdict(int)
        provider_domain_count_web = defaultdict(int)

        # Determinazione della relazione tra NS e MX (se gestiti dallo stesso provider)
        _results = {}

        for domain, data in _servers_providers_as.items():
            org_domain = data["org_domain"]
            _domain_results = {}

            _domain_results['domain'] = domain

            # Contabilizzazione dei provider per NS
            ns_providers = set(data["NS"]["providers"])
            for provider in ns_providers:
                provider_domain_count_ns[provider] += 1

            # Contabilizzazione dei provider per MX
            mx_providers = set(data["MX"]["providers"])
            for provider in mx_providers:
                provider_domain_count_mx[provider] += 1

            _has_web = False

            # Contabilizzazione dei provider per WEB
            web_providers = set(data["WEB"]["providers"])
            for provider in web_providers:
                _has_web = True
                provider_domain_count_web[provider] += 1

            # Verifica se NS e MX sono gestiti dallo stesso provider
            common_providers_mx_ns = mx_providers.intersection(ns_providers)
            common_providers_mx_web = mx_providers.intersection(web_providers)
            common_providers_ns_web = ns_providers.intersection(web_providers)

            common_as_mx_ns = set(data["MX"]["as"]).intersection(set(data["NS"]["as"]))
            common_as_mx_web = set(data["MX"]["as"]).intersection(set(data["WEB"]["as"]))
            common_as_ns_web = set(data["NS"]["as"]).intersection(set(data["WEB"]["as"]))

            if common_providers_mx_ns or common_as_mx_ns:
                _domain_results['same_MX_NS'] = True
            else:
                _domain_results['same_MX_NS'] = False

            if _has_web:
                if common_providers_mx_web or common_as_mx_web:
                    _domain_results['same_MX_WEB'] = True
                else:
                    _domain_results['same_MX_WEB'] = False

                if common_providers_ns_web or common_as_ns_web:
                    _domain_results['same_NS_WEB'] = True
                else:
                    _domain_results['same_NS_WEB'] = False
            else:
                _domain_results['same_MX_WEB'] = None
                _domain_results['same_NS_WEB'] = None

            # Uguaglianza è transitiva

            if _domain_results['same_MX_WEB'] and _domain_results['same_NS_WEB']:
                _domain_results['same_MX_NS'] = True

            if _domain_results['same_MX_NS'] and _domain_results['same_MX_WEB']:
                _domain_results['same_NS_WEB'] = True

            if _domain_results['same_MX_NS'] and _domain_results['same_NS_WEB']:
                _domain_results['same_MX_WEB'] = True

            # -----

            # Determinazione se NS/MX sono gestiti internamente o esternamente
            _domain_results['NS'] = ("INT" if org_domain in ns_providers else "EXT")
            _domain_results['MX'] = ("INT" if org_domain in mx_providers else "EXT")
            if _has_web:
                _domain_results['WEB'] = ("INT" if org_domain in web_providers else "EXT")
            else:
                _domain_results['WEB'] = None

            # Controllo della gestione esterna/interna basata sul numero di domini gestiti

            _match_ns = False
            _match_mx = False
            _match_web = False

            for provider in ns_providers:
                if provider_domain_count_ns[provider] > 10:
                    _match_ns = True
                    _domain_results["NS"] = "EXT"

            for provider in mx_providers:
                if provider_domain_count_mx[provider] > 10:
                    _match_mx = True
                    _domain_results["MX"] = "EXT"

            if _has_web:
                for provider in web_providers:
                    if provider_domain_count_web[provider] > 3:
                        _match_web = True
                        _domain_results["WEB"] = "EXT"

            # -- Caso 3 --
            if not _match_ns and org_domain not in ns_providers:
                _domain_results["NS"] = "INT"

            if not _match_mx and org_domain not in mx_providers:
                _domain_results["MX"] = "INT"

            if _has_web:
                if not _match_web and org_domain not in web_providers:
                    _domain_results["WEB"] = "INT"

            # -- Caso 4 --
            _conv = False
            _i = 0

            while _i <= 0 or not _conv:
                _conv = True
                _i += 1

                if _domain_results['same_MX_NS'] is True and _domain_results['MX'] != _domain_results['NS']:
                    _conv = False
                    _domain_results['NS'] = 'EXT'
                    _domain_results['MX'] = 'EXT'

                if _domain_results['same_MX_WEB'] is True and _domain_results['MX'] != _domain_results['WEB']:
                    _conv = False
                    _domain_results['MX'] = 'EXT'
                    _domain_results['WEB'] = 'EXT'

                if _has_web:
                    if _domain_results['same_NS_WEB'] is True and _domain_results['NS'] != _domain_results['WEB']:
                        _conv = False
                        _domain_results['NS'] = 'EXT'
                        _domain_results['WEB'] = 'EXT'

            _results[domain] = _domain_results

        return _results

    for _domain_status in tqdm(_domain_statuses, desc="PROVIDERS Analysis", ncols=100, position=1, leave=False):
        _domain = _domain_status.domain

        _domain_providers_servers = get_servers_providers_as(_domain)

        _servers_providers_as[_domain] = _domain_providers_servers

    _status = analyze_providers_as(_servers_providers_as)
    _status_df = pd.DataFrame(_status).T

    return _servers_providers_as, _status_df
