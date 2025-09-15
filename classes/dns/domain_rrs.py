from classes.dns.rr import RR_SPF, RR
from classes.dns.rr_list import RR_List
from utils.dns.queries_handler import query, query_dmarc_delegation


class DomainRRs:
    def __init__(self, _base_domain: str):
        self.base_domain = _base_domain

        self.rrs: dict = {'MX': {}, 'NS': {}, 'A': {}, 'CNAME': {}, 'TLSRPT': {}, 'MTASTS': {}, 'SPF': {}, 'DKIM': {},
                          'DMARC': {}, 'DMARC_REPORT': {}, 'DNSKEY': {}}

    # ===== SETTERS =====

    def add_rrs_mx(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'MX')

    def add_rrs_ns(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'NS')

    def add_rrs_a(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'A')

    def add_rrs_cname(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'CNAME')

    def add_rrs_tlsrpt(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'TLSRPT')

    def add_rrs_mtasts(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'MTASTS')

    def add_rrs_spf(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'SPF')

    def add_rrs_dkim(self, _rrs_lists: list[RR_List]):
        for _rr_list in _rrs_lists:
            self.__add_rrs(_rr_list, 'DKIM')

    def add_rrs_dmarc(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'DMARC')

    def add_rrs_dmarc_report(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'DMARC_REPORT')

    def add_rrs_dnskey(self, _rrs: RR_List):
        self.__add_rrs(_rrs, 'DNSKEY')

    def __add_rrs(self, _rrs: RR_List, _type: str):
        _domain = _rrs.domain

        if _type not in self.rrs:
            raise ValueError("Invalid RR Type")

        if _domain not in self.rrs[_type]:
            self.rrs[_type][_domain] = _rrs
        else:
            self.rrs[_type][_domain].extend(_rrs)

    # ===== GETTERS =====

    def get_rrs_mx(self, _domain=None):
        return self.__get_rrs('MX', _domain)

    def get_rrs_ns(self, _only_not_empty=True, _domain=None):
        if _only_not_empty:
            for _dom, _rrs in self.rrs['NS'].items():
                if not _rrs.is_empty():
                    return _rrs

            return None

        return self.__get_rrs('NS', _domain)

    def get_rrs_a(self, _domain=None):
        return self.__get_rrs('A', _domain)

    def get_rrs_cname(self, _domain=None):
        return self.__get_rrs('CNAME', _domain)

    def get_rrs_tlsrpt(self, _domain=None):
        return self.__get_rrs('TLSRPT', _domain)

    def get_rrs_mtasts(self, _domain=None):
        return self.__get_rrs('MTASTS', _domain)

    def get_rrs_spf(self, _domain=None):
        return self.__get_rrs('SPF', _domain)

    def get_rrs_dkim(self, _only_not_empty=True, _domain=None):
        _res = []

        if _only_not_empty:
            for _dom, _rrs in self.rrs['DKIM'].items():
                if not _rrs.is_empty():
                    _res.append({_dom: _rrs})

            if len(_res) == 0:
                return None
            else:
                return _res

        return self.__get_rrs('DKIM', _domain)

    def get_rrs_dmarc(self, _only_not_empty=True, _domain=None):  # todo DIVERSO DA ALTRI -- METTERE ANCHE SU NS
        if _only_not_empty:
            for _dom, _rrs in self.rrs['DMARC'].items():
                if not _rrs.is_empty():
                    return _rrs

            return None

        return self.__get_rrs('DMARC', _domain)

    def get_rrs_dmarc_report(self, _domain=None):
        return self.__get_rrs('DMARC_REPORT', _domain)

    def get_rrs_dnskey(self, _domain=None):
        return self.__get_rrs('DNSKEY', _domain)

    def __get_rrs(self, _type: str, _domain=None) -> RR_List:
        if _type not in self.rrs:
            raise ValueError("Invalid RR Type")

        # todo MERGE

        if _domain is None:
            return self.rrs[_type]
        else:
            try:
                return self.rrs[_type][_domain]
            except KeyError:
                return RR_List(_domain)

    # ===== AUTO-QUERIES =====

    def query_std(self):
        self.add_rrs_cname(query(self.base_domain, 'CNAME'))
        self.add_rrs_mx(query(self.base_domain, 'MX'))

        for _rr in self.get_rrs_mx(self.base_domain):
            self.add_rrs_a(query(_rr.value, 'A'))
            self.add_rrs_cname(query(_rr.value, 'CNAME'))

        self.add_rrs_ns(query(self.base_domain, 'NS'))

        if self.get_rrs_ns():
            for _rr in self.get_rrs_ns():
                self.add_rrs_a(query(_rr.value, 'A'))
                self.add_rrs_cname(query(_rr.value, 'CNAME'))

    def query_tlsrpt(self):
        self.add_rrs_tlsrpt(query(self.base_domain, 'TLSRPT'))
        self.add_rrs_cname(query(f"_smtp._tls.{self.base_domain}", 'CNAME'))

    def query_mtasts(self):
        self.add_rrs_mtasts(query(self.base_domain, 'MTASTS'))
        self.add_rrs_cname(query(f"_mta-sts.{self.base_domain}", 'CNAME'))

        _mtasts_policy_subdomain = f"mta-sts.{self.base_domain}"

        self.add_rrs_a(query(_mtasts_policy_subdomain, 'A'))
        self.add_rrs_cname(query(_mtasts_policy_subdomain, 'CNAME'))

    # todo SE ERRORE QUI, ALLORA AGGIUNGE VALIDATION_ERROR A POLICY BASE: Unable to retrieve some included or redirected policies.
    def query_spf(self):
        def get_spf_policy_recursively(_cur_domain, level=0):
            for _rr in self.get_rrs_spf(_cur_domain):
                _inc = _rr.policy.get_includes()
                _red = _rr.policy.get_redirects()

                # --- Redirects
                for _domain in _red:
                    self.add_rrs_cname(query(_domain, 'CNAME'))
                    self.add_rrs_spf(query(_domain, 'SPF'))

                    for _rrr in self.get_rrs_spf(_domain):
                        _policy = _rrr.policy
                        _rr.policy.add_redirected_policy(_policy)

                        # Recursion
                        if _policy.get_redirects() or _policy.get_includes():
                            get_spf_policy_recursively(_domain, level + 1)

                # --- Includes
                for _i in _inc:
                    _domain = _i['domain']
                    self.add_rrs_cname(query(_domain, 'CNAME'))
                    self.add_rrs_spf(query(_domain, 'SPF'))

                    for _rrr in self.get_rrs_spf(_domain):
                        _policy = _rrr.policy
                        _rr.policy.add_included_policy(_i['qualifier'], _policy)

                        # Recursion
                        if _policy.get_redirects() or _policy.get_includes():
                            get_spf_policy_recursively(_domain, level + 1)

        self.add_rrs_spf(query(self.base_domain, 'SPF'))

        get_spf_policy_recursively(self.base_domain)

    def query_dmarc(self):
        self.add_rrs_dmarc(query(self.base_domain, 'DMARC'))

    def query_dkim(self):
        self.add_rrs_dkim(query(self.base_domain, 'DKIM'))

    def query_dmarc_report(self, _source_domain, _report_domain):
        self.add_rrs_dmarc_report(query_dmarc_delegation(_source_domain, _report_domain))

    def query_dnssec(self):
        self.add_rrs_dnskey(query(self.base_domain, 'DNSKEY'))

    # ===== ***** =====

    def __repr__(self):
        _str = f"DNS RR for domain {self.base_domain}:\r\n"

        for k, v in self.rrs.items():
            _str += f">>>{k} {v}\r\n"

        return _str

    def __str__(self):
        return self.__repr__()

    def to_dict(self):
        return {
            "base_domain": self.base_domain,
            "rrs": {
                key: {
                    subkey: rrlist.to_dict()
                    for subkey, rrlist in subdict.items()
                } for key, subdict in self.rrs.items()
            }
        }
