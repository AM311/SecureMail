import re

import dns.resolver

from classes.policies.dkim_policy import DKIMPolicy
from classes.policies.dmarc_policy import DMARCPolicy
from classes.policies.spf_policy import SPF_Policy
from classes.policies.tlsrpt_policy import TLSRPT_Policy
from utils.dns.as_retriever import get_as


class RR:
    def __init__(self, _domain: str, _type: str, _value: str):
        self.domain = _domain
        self.type = _type
        self.value = _value.removesuffix('.')
        self.validation_error = None

    def is_valid(self):
        return True if not self.validation_error else False

    def get_validation_error(self):
        return self.validation_error

    def __repr__(self):
        return f"{self.domain} {self.type} {self.value}"

    def __str__(self):
        return f"{self.domain} {self.type} {self.value}"

    def to_dict(self):
        return {
            # "domain": self.domain,
            "type": self.type,
            "value": self.value,
            "validation_error": self.validation_error
        }


#####

class RR_MX(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.MX):
        super().__init__(_domain, 'MX', str(_value.exchange))


#####

class RR_CNAME(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.CNAME):
        super().__init__(_domain, 'CNAME', str(_value.target))


#####

class RR_A(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.A):
        super().__init__(_domain, 'A', str(_value.address))

        self.autonomous_system = get_as(self.value)

    def to_dict(self):
        return {
            # "domain": self.domain,
            "type": self.type,
            "value": self.value,
            'autonomous_system': self.autonomous_system,
            "validation_error": self.validation_error
        }


#####

class RR_NS(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.NS):
        super().__init__(_domain, 'NS', str(_value))


#####

class RR_TLSRPT(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        self.policy = None

        # -----

        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        self.policy = TLSRPT_Policy(_value, _domain)

        self.validation_error = self.policy.get_validation_error()


class RR_MTASTS(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        self.value = None
        self.id = None
        self.extensions = []

        # -----

        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        def validate_rr():
            _version = None
            _id = None
            _extensions = []

            # -----
            # -- v validation --

            _fields = [_f.strip() for _f in _value.split(";") if len(_f) > 0]

            if _fields[0] != "v=STSv1":
                return '"V" must be the first field'
            else:
                _versions = [_f for _f in _fields if _f.startswith("v=")]

                if len(_versions) != 1:
                    return 'Multiple "v" fields provided'
                else:
                    self.version = _fields[0].split("=")[1]

            # -- id validation --

            _fields = _fields[1:]

            _ids = [_f for _f in _fields if _f.startswith("id=")]

            if len(_ids) != 1:
                return 'Multiple "id" fields provided'
            else:
                if not _ids[0].split('=')[1].isalnum():
                    return '"id" field must be alphanumeric'
                else:
                    self.id = _ids[0].split('=')[1]

            # -- Extensions --

            for _ext in [_ff for _ff in _fields if _ff not in _ids]:
                _tokens = _ext.split('=')

                if len(_tokens) != 2:
                    return f'Invalid format for extension {_ext}'

                _key = _tokens[0]
                _val = _tokens[1]

                # KEY validation
                if not _key[0].isalnum():
                    return 'Extension key must be alphanumeric'

                if not re.match(r'^[A-Za-z0-9][_A-Za-z0-9.-]{0,31}$', _key):
                    return 'Extension key does not match the validation rule'

                if not _val:
                    return 'Extension value must not be empty'

                _forbidden_chars = {'=', ';', ' ', *map(chr, range(0, 32)), chr(127)}

                for _char in _val:
                    if _char in _forbidden_chars:
                        return 'Extension value does not match the validation rule'
                    if not ((33 <= ord(_char) <= 58)  # Caratteri tra '!' e ':'
                            or (_char == '<')  # Carattere '<'
                            or (62 <= ord(_char) <= 126)  # Caratteri tra '>' e '~'
                    ):
                        return 'Extension value does not match the validation rule'

                self.extensions.append(_ext)

            # -----

            return None

        self.validation_error = validate_rr()

    def to_dict(self):
        return {
            "value": self.value,
            "id": self.id,
            "extensions": self.extensions,
            "validation_error": self.validation_error,
        }


class RR_SPF(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        self.policy = None

        # -----

        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        self.policy = SPF_Policy(_value, _domain)

        self.validation_error = self.policy.get_validation_error()


class RR_DMARC(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        self.policy = None

        # -----

        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        self.policy = DMARCPolicy(_value, _domain)

        self.validation_error = self.policy.get_validation_error()


class RR_DKIM(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        self.policy = None

        # -----

        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        self.policy = DKIMPolicy(_value, _domain)

        self.validation_error = self.policy.get_validation_error()


class RR_DMARC_REPORT(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.TXT):
        _value = "".join([_s.decode('utf-8') for _s in _value.strings])

        super().__init__(_domain, 'TXT', _value)

        if not _value.startswith("v=DMARC1"):
            self.validation_error = "DMARC Report RR must begin with 'v=DMARC1'"


class RR_DNSKEY(RR):
    def __init__(self, _domain: str, _value: dns.rdatatype.DNSKEY):
        super().__init__(_domain, 'DNSKEY', str(_value))
