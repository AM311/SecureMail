import fnmatch
import re

from classes.dns.rr import RR_MX
from classes.dns.rr_list import RR_List


class MTASTS_Policy:
    def __init__(self, raw_text):
        self.raw_text = raw_text

        self.version = None
        self.mode = None
        self.max_age = None
        self.mx = []
        self.extensions = []

        self.validation_error = None

        def validate_policy():
            for _line in [_l for _l in self.raw_text.splitlines() if len(_l) > 0]:
                _line = _line.strip()

                if ":" not in _line:
                    return f"Invalid MTA-STS policy line: '{_line}'"

                _key, _value = [part.strip() for part in _line.split(":", 1)]

                if _key == "version":
                    if self.version is None:
                        self.version = _value

                        if _value != "STSv1":
                            return f"Version field must be 'version=STSv1' {_value} provided"

                elif _key == "mode":
                    if self.mode is None:
                        self.mode = _value

                        if _value not in ("enforce", "testing", "none"):
                            return f"Mode field must assume one of the 3 accepted values: {_value} provided"

                elif _key == "max_age":
                    if self.max_age is None:
                        self.max_age = _value

                        if not _value.isdigit():
                            return f"Max_age field must be an integer: {_value} provided"

                elif _key == "mx":
                    self.mx.append(_value)

                    _is_valid_mx = False

                    _mx_domain_pattern = r"^(\*\.|)([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$"
                    _mx_subdomain_pattern = r"([a-zA-Z0-9])([a-zA-Z0-9-]*[a-zA-Z0-9])?"

                    if re.match(_mx_domain_pattern, _value):
                        _domain_part = _value[2:] if _value.startswith("*.") else _value
                        _subdomains = _domain_part.split(".")

                        for _subdomain in _subdomains:
                            if not re.match(_mx_subdomain_pattern, _subdomain):
                                return f"Invalid MX field ({_value}): subdomain not matching validation rule"

                        _is_valid_mx = True

                    if not _is_valid_mx:
                        return f"Invalid MX field ({_value}): domain not matching validation rule"

                else:
                    self.extensions.append(_line)

                    _ext_key_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9_-\.]{0,30}[a-zA-Z0-9])?$"

                    if not bool(re.match(_ext_key_pattern, _key)):
                        return f"Invalid extension field ({_line}): key not matching validation rule'"

                    if any(ord(c) < 32 or ord(c) == 127 for c in _value):
                        return f"Invalid extension field ({_line}): value not matching validation rule'"

                    for c in _value:
                        if not (0x21 <= ord(c) <= 0x7E or 0xC0 <= ord(c) <= 0xFD):
                            return f"Invalid extension field ({_line}): value not matching validation rule'"

            if len(self.mx) == 0 and self.mode != "none":
                return "At least one MX entry must be specified"

            return None

        self.validation_error = validate_policy()


    def is_invalid(self):
        return self.validation_error is not None

    def get_validation_error(self):
        return self.validation_error

    # =====

    def get_aligned(self, _mxs: RR_List) -> RR_List:
        def check_alignment_single_mx(_mx: RR_MX) -> bool:
            for _rule in self.mx:
                if fnmatch.fnmatch(_mx.value, _rule):
                    return True
            return False

        _matching_RRs = RR_List(_mxs.domain)

        for _mx in _mxs:
            if check_alignment_single_mx(_mx):
                _matching_RRs.add_rr(_mx)

        return _matching_RRs

    def __repr__(self):
        return self.raw_text

    def to_dict(self):
        return {
            "version": self.version,
            "mode": self.mode,
            "max_age": self.max_age,
            "mx": self.mx,
            "extensions": self.extensions,
            "validation_error": self.validation_error,
        }