import re
from urllib.parse import urlparse


class DMARCPolicy:
    def __init__(self, raw_text: str, _base_domain: str):
        self.raw_text = raw_text

        self.base_domain = _base_domain.split('.', 1)[1]

        self.version = None
        self.policy = None

        self.adkim = "r"
        self.aspf = "r"
        self.fo = "0"
        self.pct = 100
        self.rf = "arfr"
        self.ri = 86400
        self.rua = None
        self.ruf = None
        self.sp = None

        self.validation_error = None

        def validate_policy():
            _policies_values = ['none', 'quarantine', 'reject']

            # =====

            _terms = [_t.strip() for _t in self.raw_text.split(";") if len(_t.strip()) > 0]

            if len(_terms) == 0:
                return "Empty policy"
            if len(_terms) < 2:
                return 'Invalid policy: at least "v" and "p" tags MUST be present'

            _v = _terms[0].split('=')
            _p = _terms[1].split('=')

            if len(_v) != 2 or len(_p) != 2:
                return "First fields must be 'v' and 'p'"

            if _v[0].strip() != "v" or _v[1].strip() != "DMARC1":
                return "First field must be 'v=DMARC1'"
            else:
                self.version = _v[1].strip()

            if _p[0].strip() != "p":
                return "Second field must be 'p'"
            elif _p[1].strip() not in _policies_values:
                return f"Invalid value for 'p' field: {_p[1].strip()}"
            else:
                self.policy = _p[1].strip()

            # ---
            # Check if there are duplicate keys
            _keys = [_term.split("=")[0].strip() for _term in _terms[2:]]

            if len(_keys) != len(set(_keys)):
                return f"Some duplicated keys exist: {_keys}"

            # ---

            for _term in _terms[2:]:
                _tokens = _term.split("=")

                if len(_tokens) != 2:
                    return f"Invalid field: {_term}"

                _key = _tokens[0].strip()
                _value = _tokens[1].strip()

                # ---

                if _key in ['adkim', 'aspf']:
                    if _value not in ['r', 's']:
                        return f"Invalid value for '{_key}' field: {_value}"

                    if _key == 'adkim':
                        self.adkim = _value
                    elif _key == 'aspf':
                        self.aspf = _value
                elif _key in ['rua', 'ruf']:
                    def is_valid_dmarc_uri(uri: str) -> bool:
                        dmarc_uri_suffix_regex = re.compile(r"!\d+[kKmMgGtT]?$")
                        email_regex = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

                        # Se c'è un punto esclamativo, separa URI e suffix
                        if "!" in uri:
                            base_uri, suffix = uri.split("!", 1)
                            suffix = "!" + suffix
                        else:
                            base_uri, suffix = uri, None

                        # Validazione URI
                        parsed = urlparse(base_uri.strip())

                        # Gestione speciale per mailto:
                        if parsed.scheme.strip() == 'mailto':
                            if not parsed.path or not email_regex.fullmatch(parsed.path.strip()):
                                return False
                        else:
                            if not parsed.scheme or not parsed.netloc:
                                return False

                        # Validazione suffix se presente
                        if suffix:
                            if not dmarc_uri_suffix_regex.fullmatch(suffix.strip()):
                                return False

                        return True

                    def validate_dmarc_uri_list(uri_list: str) -> bool:
                        uris = [uri.strip() for uri in uri_list.split(",")]
                        return all(is_valid_dmarc_uri(uri) for uri in uris)

                    if not validate_dmarc_uri_list(_value):
                        return f"Invalid URI for RUA/RUF field: {_value}"

                    if _key == 'rua':
                        self.rua = _value
                    elif _key == 'ruf':
                        self.ruf = _value
                elif _key == 'sp':
                    if _value not in _policies_values:
                        return f"Invalid value for '{_key}' field: {_value}"

                    self.sp = _value
                elif _key == 'fo':
                    if not re.match(r"^([01ds])(\s*:\s*([01ds]))*$", _value):
                        return f"Invalid value for '{_key}' field: {_value}"

                    self.fo = _value
                elif _key == 'pct':
                    if int(_value) < 0 or int(_value) > 100:
                        return f"Invalid value for '{_key}' field: {_value}"

                    self.pct = _value
                elif _key == 'ri':
                    if not _value.isdigit():
                        return f"Invalid value for '{_key}' field: {_value}"

                    self.ri = _value
                elif _key == 'rf':
                    if not re.match(r"^[A-Za-z0-9-]+[A-Za-z0-9](\s*:\s*[A-Za-z0-9-]+[A-Za-z0-9])*$", _value):
                        return f"Invalid value for '{_key}' field: {_value}"

                    self.rf = _value
                else:
                    return f"Invalid key: {_key}"

            return None

        self.validation_error = validate_policy()

    # =====

    def is_invalid(self, ):
        return self.validation_error is not None

    def get_validation_error(self, _recursive=True):
        return self.validation_error

    # =====

    def check_alignment(self, _spf_dkim_domain, mode='r'):
        _tokens = _spf_dkim_domain.split('@')

        if len(_tokens) > 1:
            _domain = _tokens[1]
        else:
            _domain = _tokens[0]

        # ---

        if mode == 's':
            if self.base_domain == _spf_dkim_domain:
                return True
            else:
                return False
        elif mode == 'r':
            if _spf_dkim_domain.endswith(self.base_domain):
                return True

            if self.base_domain.endswith(_spf_dkim_domain):
                return True

            return False
        else:
            raise ValueError("Invalid mode")

    def __repr__(self):
        return self.raw_text

    def to_dict(self):
        return {
            "version": self.version,
            "policy": self.policy,

            "adkim": self.adkim,
            "aspf": self.aspf,
            "rua": self.rua,
            "ruf": self.ruf,
            "sp": self.sp,
            "fo": self.fo,
            "pct": self.pct,
            "ri": self.ri,
            "rf": self.rf,

            "validation_error": self.validation_error,
        }
