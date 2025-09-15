import base64
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class DKIMPolicy:
    def __init__(self, raw_text: str, _base_domain: str):
        self.raw_text = raw_text

        self.version = None
        self.hashAlgs = []
        self.keyType = None
        self.notes = None
        self.publicKey = None
        self.keyLength = None
        self.serviceTypes = []
        self.flags = []

        self.otherTerms = []

        self.validation_error = None

        def validate_policy():
            _terms = [_t.strip() for _t in self.raw_text.split(";") if len(_t.strip()) > 0]

            if len(_terms) == 0:
                return "Empty policy"

            # Check if there are duplicate keys
            _keys = [_term.split("=")[0].strip() for _term in _terms]

            if len(_keys) != len(set(_keys)):
                return f"Some duplicated keys exist: {_keys}"

            if 'p' not in _keys:
                return f"Missing 'p' field"

            # ---

            for _term in _terms:
                _tokens = _term.split("=")

                if len(_tokens) != 2:
                    return f"Invalid field: {_term}"

                _key = _tokens[0].strip()
                _value = _tokens[1].strip()

                # ---

                if _key == 'v':
                    if not _terms[0].startswith('v'):
                        return f"Version field must be the first field"
                    if _value != 'DKIM1':
                        return f"Version must be 'DKIM1', another value provided: {_value}"
                    self.version = _value
                elif _key == 'h':
                    _algs = _value.split(':')

                    for _alg in [_a.strip() for _a in _algs]:
                        if _alg not in ['sha1', 'sha256']:
                            if re.match(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", _alg):
                                return f"Invalid hash algorithm: {_alg}"
                        self.hashAlgs.append(_alg)
                elif _key == 'k':
                    if _value not in ['rsa']:
                        if re.match(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", _value):
                            return f"Invalid key type: {_value}"
                    self.keyType = _value
                elif _key == 'n':
                    if not re.match(
                            r"^([!-/0-9A-Za-z?^_`a-zA-Z]|=[0-9A-Fa-f]{2})*(\t| )?([!-/0-9A-Za-z?^_`a-zA-Z]|=[0-9A-Fa-f]{2})$",
                            _value):
                        return f"Invalid notes: {_value}"
                    self.notes = _value
                elif _key == 'p':
                    if len(_value) == 0:
                        return f"Empty public key"
                    elif not re.match(r"^([A-Za-z0-9+/](?:[ \t]*[A-Za-z0-9+/])*)[ \t]*=?[ \t]*=?$", _value):
                        return f"Invalid public key: {_value}"
                    self.publicKey = _value

                    # --

                    try:
                        der_bytes = base64.b64decode(_value)
                        public_key = serialization.load_der_public_key(der_bytes, backend=default_backend())
                        self.keyLength = int(public_key.key_size)
                    except Exception:
                        pass
                elif _key == 's':
                    _servs = _value.split(':')

                    for _serv in [_s.strip() for _s in _servs]:
                        if _serv not in ['email', '*']:
                            if re.match(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", _serv):
                                return f"Invalid service type: {_serv}"
                        self.serviceTypes.append(_serv)
                elif _key == 't':
                    _flags = _value.split(':')

                    for _flag in [_f.strip() for _f in _flags]:
                        if _flag not in ['y', 's']:
                            if re.match(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", _flag):
                                return f"Invalid flag: {_flag}"
                        self.flags.append(_flag)
                else:
                    if re.match(r"^[A-Za-z][A-Za-z0-9_]*$", _key):
                        return f"Invalid key: {_key}"
                    if re.match(r"^[!-/0-9A-Z_a-z|~]+(?:[ \t]+[!-/0-9A-Z_a-z|~]+)*$", _value):
                        return f"Invalid value: {_value}"

                    self.otherTerms.append(_term)

            return None

        self.validation_error = validate_policy()

    # =====

    def is_invalid(self, ):
        return self.validation_error is not None

    def get_validation_error(self, _recursive=True):
        return self.validation_error

    # =====

    def __repr__(self):
        return self.raw_text

    def to_dict(self):
        return {
            "version": self.version,
            "hashAlgs": self.hashAlgs,
            "keyType": self.keyType,
            "notes": self.notes,
            "publicKey": self.publicKey,
            "keyLength": self.keyLength,
            "serviceTypes": self.serviceTypes,
            "flags": self.flags,
            "otherTerms": self.otherTerms,

            "validation_error": self.validation_error,
        }
