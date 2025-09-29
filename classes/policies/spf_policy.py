import ipaddress
import re

import dns


class SPF_Policy:
    def __init__(self, _raw_text: str, _domain: str):
        self.raw_text = _raw_text
        self.domain = _domain

        self.version = None
        self.terms = []

        self.ipv4 = []
        self.ipv6 = []

        # Must be added manually
        self.included_policies = []
        self.redirected_policies = []

        self.validation_error = None

        def validate_policy():
            _terms = [_t.strip() for _t in self.raw_text.split(" ") if len(_t.strip()) > 0]

            if len(_terms) == 0:
                return "Empty policy"

            if _terms[0] != "v=spf1":
                return "First field must be 'v=spf1'"
            else:
                self.version = _terms[0].split("=")[1]

            # ---

            _mechanisms = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']
            _qualifiers = ['+', '-', '?', '~']
            _modifiers = ['redirect', 'explanation']  # Custom modifiers also supported

            _domain_spec_pattern = r"^(?:(%{[slodiphcrt]\d*r?[-.,+/=_]*})|([!$&'(*),;=@A-Za-z0-9._%-]+))(\.[A-Za-z0-9-]+)+$|%[_%-]+$"
            _macro_string_pattern = r"^(%{[slodiphcrt]\d*r?[-.,+/=_]*})|([!$&'\()*\),;=@A-Za-z0-9._%-]+)$"

            _mx_count = 0
            _ptr_count = 0

            for _term in _terms[1:]:
                _term = _term.strip()

                _matches = [_item for _item in _mechanisms if (_term.startswith(_item) or _term[1:].startswith(_item))]

                if len(_matches) > 0:
                    # -- IS DIRECTIVE
                    _mechanism = _matches[0]

                    _qualifier = None

                    if _term[0] in _qualifiers:
                        _qualifier = _term[0]
                        _term = _term[1:]
                    elif _term[0] != _mechanism[0]:
                        return f"Invalid qualifier {_term[0]} in directive: {_term}"

                    _spec = _term.split(":", 1)

                    _domain_spec = None

                    if len(_spec) > 1:
                        _domain_spec = _spec[1]

                        if _mechanism not in ['ip4', 'ip6']:
                            if not re.match(_domain_spec_pattern, _domain_spec):
                                return f"Invalid domain spec {_domain_spec} for directive: {_term}"
                    elif _mechanism == 'all':
                        _domain_spec = _spec[0]
                    elif _mechanism in ['a', 'mx', 'ptr']:
                        _domain_spec = self.domain
                    elif _mechanism in ['include', 'ip4', 'ip6', 'exists']:
                        return f"Insufficient arguments for the given directive: {_term}"

                    if _mechanism == 'mx':
                        _mx_count = _mx_count + 1

                        if _mx_count > 10:
                            return f"Max 10 MX entries, {_mx_count} found"
                    elif _mechanism == 'ptr':
                        _ptr_count = _ptr_count + 1

                        if _ptr_count > 10:
                            return f"Max 10 PTR entries, {_ptr_count} found"

                    self.terms.append({'type': 'directive', 'qualifier': (_qualifier or '+'), 'mechanism': _mechanism,
                                       'domain_spec': _domain_spec})
                else:
                    # -- IS MODIFIER
                    _tokens = _term.split("=")

                    if len(_tokens) < 2 or len(_tokens) > 2:
                        return f"Invalid modifier: {_term}"

                    _name = _tokens[0]
                    _domain_spec = _tokens[1]

                    if _name in _modifiers:
                        if not re.match(_domain_spec_pattern, _domain_spec):
                            return f"Invalid domain spec {_domain_spec} for mechanism: {_term}"
                    else:
                        if not re.match(r"^[A-Za-z][A-Za-z0-9\-_.]*$", _name):
                            return f"Invalid name {_name} for mechanism: {_term}"
                        if not re.match(_macro_string_pattern, _domain_spec):
                            return f"Invalid macro string {_domain_spec} for mechanism: {_term}"

                    self.terms.append({'type': 'modifier', 'name': _name, 'domain_spec': _domain_spec})

            # If exists ALL, there must be no REDIRECT
            _all_mechanism_exists = any(
                _term['type'] == 'directive' and _term['mechanism'] == 'all' for _term in self.terms
            )

            _redirect_exists = any(
                _term['type'] == 'modifier' and _term['name'] == 'redirect' for _term in self.terms
            )

            if _all_mechanism_exists and _redirect_exists:
                return f"No 'redirect' mechanism must exist if an 'all' directive is declared"

            return None

        # Crea liste di IP a partire dalle policy
        def retrieve_all_ips(_recursive=True, _resolve_dns=True):
            for _term in self.terms:
                if _term['type'] == 'directive':
                    _ip_domain = _term['domain_spec']
                    _qualifier = _term['qualifier']

                    if _term['mechanism'] == 'ip4':
                        _ipObj = ipaddress.IPv4Network(_ip_domain, strict=False)

                        self.ipv4.append({'qualifier': _qualifier, 'ip': _ipObj})
                    elif _term['mechanism'] == 'ip6':
                        _ipObj = ipaddress.IPv6Network(_ip_domain, strict=False)

                        self.ipv6.append({'qualifier': _qualifier, 'ip': _ipObj})
                    elif _term['mechanism'] == 'a' and _resolve_dns:
                        try:
                            _answers_4 = dns.resolver.resolve(_term['domain_spec'], 'A')

                            for _rr in _answers_4:
                                _ip = str(_rr.address).removesuffix('.')
                                _ipObj = ipaddress.IPv4Network(_ip, strict=False)

                                self.ipv4.append({'qualifier': _qualifier, 'ip': _ipObj})
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            pass

                        try:
                            _answers_6 = dns.resolver.resolve(_term['domain_spec'], 'AAAA')

                            for _rr in _answers_6:
                                _ip = str(_rr.address).removesuffix('.')
                                _ipObj = ipaddress.IPv6Network(_ip, strict=False)

                                self.ipv6.append({'qualifier': _qualifier, 'ip': _ipObj})
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            pass
                    elif _term['mechanism'] == 'mx' and _resolve_dns:
                        try:
                            _answers_mx = dns.resolver.resolve(_term['domain_spec'], 'MX')

                            for _rr_mx in _answers_mx:
                                _domain = _rr_mx.exchange.to_text().removesuffix('.')

                                try:
                                    _answers_a4 = dns.resolver.resolve(_domain, 'A')

                                    for _rr_a in _answers_a4:
                                        _ip = str(_rr_a.address).removesuffix('.')
                                        _ipObj = ipaddress.IPv4Network(_ip, strict=False)

                                        self.ipv4.append({'qualifier': _qualifier, 'ip': _ipObj})
                                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                    pass

                                try:
                                    _answers_a6 = dns.resolver.resolve(_domain, 'AAAA')

                                    for _rr_a in _answers_a6:
                                        _ip = str(_rr_a.address).removesuffix('.')
                                        _ipObj = ipaddress.IPv6Network(_ip, strict=False)

                                        self.ipv6.append({'qualifier': _qualifier, 'ip': _ipObj})

                                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                    pass
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            pass

            # todo OSS: la concatenazione di recursive/include è fatta in fase di verifica
            if _recursive:
                for _p in self.included_policies:
                    _p['policy'].retrieve_all_ips(_recursive)

                for _p in self.redirected_policies:
                    _p.retrieve_all_ips(_recursive)

        self.validation_error = validate_policy()
        retrieve_all_ips()

    def __eq__(self, __other):
        if not isinstance(__other, SPF_Policy):
            return NotImplemented
        return (self.domain == __other.domain) and (self.raw_text == __other.raw_text)

    # =====

    # todo POLICY INCLUSA NON VALIDA
    def is_invalid(self, _recursive=True):
        if _recursive:
            for _p in self.included_policies:
                if _p['policy'].is_invalid():
                    return False

            for _p in self.redirected_policies:
                if _p.is_invalid():
                    return False

        return self.validation_error is not None

    def get_validation_error(self, _recursive=True):
        if _recursive:
            for _p in self.included_policies:
                if _p['policy'].is_invalid():
                    return _p.validation_error

            for _p in self.redirected_policies:
                if _p.is_invalid():
                    return _p.validation_error

        return self.validation_error

    def get_includes(self):
        return [{'qualifier': _entry['qualifier'], 'domain': _entry['domain_spec']} for _entry in self.terms if
                (_entry['type'] == 'directive' and _entry['mechanism'] == 'include')]

    def get_redirects(self):
        return [_entry['domain_spec'] for _entry in self.terms if
                (_entry['type'] == 'modifier' and _entry['name'] == 'redirect')]

    # =====

    def get_default_policy(self):
        # INCLUDES (+ --> +)
        for _incl in [_p for _p in self.included_policies if (_p['qualifier'] == '+')]:
            _incl_policy = _incl['policy']

            _incl_qualifier = _incl_policy.get_default_policy()

            if _incl_qualifier == '+':
                return '+'

        # LOCAL
        for _all in [_t for _t in self.terms if (_t['type'] == 'directive' and _t['mechanism'] == 'all')]:
            return _all['qualifier']

        # REDIRECT
        for _red in self.redirected_policies:
            return _red.get_default_policy()

        return '?'

    # =====

    def add_included_policy(self, _qualifier, _included_policy):
        _new_entry = {'qualifier': _qualifier, 'policy': _included_policy}

        if _new_entry not in self.included_policies:
            self.included_policies.append(_new_entry)

    def add_redirected_policy(self, _redirected_policy):
        if _redirected_policy not in self.redirected_policies:
            self.redirected_policies.append(_redirected_policy)

    def get_included_policies(self):
        return self.included_policies

    def get_redirected_policies(self):
        return self.redirected_policies

    # =====

    def get_ips(self, _qualifier=None, _recursive=True):
        if _qualifier:
            _ips4 = [_ip for _ip in self.ipv4 if _ip['qualifier'] == _qualifier]
            _ips6 = [_ip for _ip in self.ipv6 if _ip['qualifier'] == _qualifier]
        else:
            _ips4 = self.ipv4
            _ips6 = self.ipv6

        if _recursive:
            for _p in [_pp for _pp in self.included_policies if
                       ((_qualifier is None or _pp['qualifier'] == _qualifier) and not _pp['policy'].is_invalid())]:
                _sub_ips4, _sub_ips6 = _p['policy'].get_ips(_qualifier, _recursive)
                _ips4 += _sub_ips4
                _ips6 += _sub_ips6

            for _p in [_pp for _pp in self.redirected_policies if not _pp.is_invalid()]:
                _sub_ips4, _sub_ips6 = _p.get_ips(_qualifier, _recursive)
                _ips4 += _sub_ips4
                _ips6 += _sub_ips6

        return _ips4, _ips6

    def check_overlaps(self, _qualifier=None, _recursive=True):
        _ips4, _ips6 = self.get_ips(_qualifier, _recursive)

        for _i, _ip1 in enumerate(_ips4):
            _ip1 = _ip1['ip']
            for _j, _ip2 in enumerate(_ips4):
                _ip2 = _ip2['ip']

                if _i < _j:
                    if _ip1.overlaps(_ip2):
                        return True

        for _i, _ip1 in enumerate(_ips6):
            _ip1 = _ip1['ip']
            for _j, _ip2 in enumerate(_ips6):
                _ip2 = _ip2['ip']

                if _i < _j:
                    if _ip1.overlaps(_ip2):
                        return True

        return False

    # todo CHECK MATCH

    def __repr__(self):
        return self.raw_text

    def to_dict(self):
        return {
            "version": self.version,
            "terms": self.terms,
            # "ipv4": list(map(lambda x : str(x), self.ipv4)),
            # "ipv6": list(map(lambda x : str(x), self.ipv6)),
            "validation_error": self.validation_error,
        }
