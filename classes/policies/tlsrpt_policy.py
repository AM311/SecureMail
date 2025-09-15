import ipaddress
import re

import dns


class TLSRPT_Policy:
    def __init__(self, _raw_text: str, _domain: str):
        self.raw_text = _raw_text
        self.domain = _domain

        self.version = None
        self.ruas = []
        self.extensions = []

        self.validation_error = None

        def validate_policy():
            _terms = [_t.strip() for _t in self.raw_text.split(";") if len(_t.strip()) > 0]

            if len(_terms) == 0:
                return "Empty policy"

            if _terms[0] != "v=TLSRPTv1":
                return "First field must be 'v=TLSRPTv1'"
            else:
                self.version = _terms[0].split("=")[1]

            # ---

            for _term in _terms[1:]:
                _term = _term.strip()

                _tokens = _term.split("=")

                if len(_tokens) != 2:
                    return f"Invalid term: {_term}"

                _key = _tokens[0].strip()
                _value = _tokens[1].strip()

                if _key == "rua":
                    self.ruas.append(_tokens[1])
                else:
                    if not re.match(r"^[A-Za-z0-9]{31}[A-Za-z0-9_\-\.]+$", _key):
                        return f"Invalid key {_key} for term: {_term}"

                    if not re.match(r"^[!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]+$", _value):
                        return f"Invalid key {_value} for term: {_term}"

                    self.extensions.append({'key': _key, 'value': _value})

            return None

        self.validation_error = validate_policy()

    # =====

    def is_invalid(self):
        return self.validation_error is not None

    def get_validation_error(self):
        return self.validation_error

    # =====

    def __repr__(self):
        return self.raw_text

    def to_dict(self):
        return {
            "version": self.version,
            "ruas": self.ruas,
            "extensions": self.extensions,
            "validation_error": self.validation_error,
        }
