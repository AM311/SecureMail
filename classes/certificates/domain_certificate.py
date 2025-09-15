import fnmatch
import re
import ssl
from datetime import datetime, timezone

import certifi
import requests
from OpenSSL import crypto


class Certificate:
    def __init__(self, _domain, _host, _pem_certificate):
        self.domain = _domain
        self.host = _host
        self.certificate = _pem_certificate

        self.cn = None
        self.san = []
        self.expiration_date = None
        self.not_before = None

        self.key_type = None
        self.key_length = None
        self.signature_algorithm = None

        self.validation_error = None
        self.validation_error_mtasts = None
        self.validation_error_starttls = None

        self.validation_warning = None

        # todo RIDEFINIRE PARSE COME VALIDATE (metodo locale) + RITORNA VALIDATION ERROR oppure NONE

        def validate_certificate():
            try:
                _leaf_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate)

                # ===== CHECK DOMAIN (CN / SAN) =====

                # --- Extract CN
                _subject = _leaf_cert.get_subject()
                _cn = _subject.CN if hasattr(_subject, "CN") else None

                self.cn = _cn

                # --- Extract SAN
                _san_list = []
                for _i in range(_leaf_cert.get_extension_count()):
                    _ext = _leaf_cert.get_extension(_i)
                    if _ext.get_short_name() == b"subjectAltName":
                        _san_data = str(_ext)
                        for _entry in _san_data.split(', '):
                            if _entry.startswith("DNS:"):
                                _san_list.append(_entry[4:])

                self.san = _san_list

                if not _cn and len(_san_list) == 0:
                    return "No values found for CN and SAN"

                # --- Extract Key Type & Length
                _leaf_pubkey = _leaf_cert.get_pubkey()

                _key_type_map = {
                    crypto.TYPE_RSA: "RSA",
                    crypto.TYPE_DSA: "DSA",
                    crypto.TYPE_DH: "DH",
                    crypto.TYPE_EC: "EC",
                }

                _key_type = _leaf_pubkey.type()
                self.key_type = _key_type_map.get(_key_type, f"Unknown ({_key_type})")

                self.key_length = int(_leaf_pubkey.bits())

                # --- Extract Signature Algorithm
                self.signature_algorithm = _leaf_cert.get_signature_algorithm().decode()

                # --- Validates CN / SAN

                _matches_mtasts = False
                _matches_starttls = False

                # >>> MTA-STS Validation:
                for _name in _san_list[:]:
                    if fnmatch.fnmatch(self.host, _name):
                        _matches_mtasts = True
                        break

                _candidates = _san_list[:]
                _candidates.append(_cn)

                # >>> STARTTLS Validation:
                for _name in _candidates:
                    if fnmatch.fnmatch(self.domain, _name):
                        _matches_starttls = True
                        break

                if not _matches_starttls:
                    for _name in _candidates:
                        if fnmatch.fnmatch(self.host, _name):
                            _matches_starttls = True
                            self.validation_warning = "Certificate CN matches host name"

                if not _matches_mtasts:
                    self.validation_error_mtasts = "No matches for the requested hostname in SAN list"
                if not _matches_starttls:
                    self.validation_error_starttls = "No matches for the requested domain in CN"

                if not _matches_mtasts and not _matches_starttls:
                    return f"No matches for the requested domain in CN / SAN"

                # ===== CHECK EXPIRATION DATE =====

                _expiration_date = datetime.strptime(_leaf_cert.get_notAfter().decode("ascii"),
                                                     "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                _not_before = datetime.strptime(_leaf_cert.get_notBefore().decode("ascii"),
                                                "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

                self.expiration_date = _expiration_date
                self.not_before = _not_before

                if _expiration_date < datetime.now(timezone.utc):
                    return f"Expired certificate: {_expiration_date}"

                if _not_before > datetime.now(timezone.utc):
                    return f"Not valid-yet certificate: {_not_before}"

                # ===== CHECK CERTIFICATE CHAIN =====

                # --- Builds Store with Root CAs

                _store = crypto.X509Store()  # Root Store
                with open(certifi.where(), 'r') as _f:
                    _cert_data = _f.read()
                    _certs = _cert_data.split("-----END CERTIFICATE-----")

                    for _cert_text in _certs:
                        _cert_text = _cert_text.strip()
                        if _cert_text:
                            _cert_text += "\n-----END CERTIFICATE-----\n"
                            try:
                                _ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, _cert_text.encode("utf-8"))
                                _store.add_cert(_ca_cert)
                            except Exception as e:
                                return f"Invalid CA certificate: {e}"

                # ---

                _error = None

                def fetch_intermediates_recursive(cert, visited_urls=None):
                    if visited_urls is None:
                        visited_urls = set()

                    intermediates = []

                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        if ext.get_short_name() == b"authorityInfoAccess":
                            aia_str = str(ext)
                            aia_urls = re.findall(r'CA Issuers - URI:(http[s]?://[^\s]+)', aia_str)
                            for url in aia_urls:
                                if url in visited_urls:
                                    continue
                                visited_urls.add(url)

                                try:
                                    headers = {
                                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
                                        "Accept": "*/*",
                                    }

                                    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                                    content_type = response.headers.get("Content-Type", "").lower()

                                    if response.status_code == 200:
                                        if "html" in content_type or b"<html" in response.content.lower():
                                            _error = f"Invalid server response from {url}: HTML content"
                                            continue

                                        if b"-----BEGIN CERTIFICATE-----" in response.content:
                                            pem_data = response.content
                                        else:
                                            try:
                                                pem_data = ssl.DER_cert_to_PEM_cert(response.content).encode("utf-8")
                                            except Exception:
                                                _error = f"Invalid certificate format retrieved from url {url}: {response.content}"
                                                continue  # Invalid certificate format

                                        try:
                                            inter_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
                                            intermediates.append(inter_cert)
                                            # 🔁 Ricorsione: continua a risalire nella catena
                                            intermediates += fetch_intermediates_recursive(inter_cert, visited_urls)
                                        except Exception as e:
                                            _error = f"Unable to load PEM certificate: {e}"
                                            continue  # Non è un certificato valido
                                    else:
                                        _error = f"Unable to retrieve Intermediate Certificate from {url} -- response code: {response.status_code}"
                                        continue
                                except Exception as e:
                                    _error = f"Error while downloading intermediate certificates from url {url}: {e}"
                                    continue  # Errore di rete o parsing

                    return intermediates

                if _error is not None:          #todo FUNZIONA ???
                    return _error

                _intermediates = fetch_intermediates_recursive(_leaf_cert)

                _ctx = crypto.X509StoreContext(_store, _leaf_cert, _intermediates)
                _ctx.verify_certificate()

            except crypto.X509StoreContextError as e:
                return f"Unable to verify the certificate chain: {e}"
            except Exception as e:
                return f"Unhandled error: {e}"

            return None

        self.validation_error = validate_certificate()

    def is_invalid(self, _mtasts_validation=False) -> bool:
        return self.validation_error is not None or (
            self.validation_error_mtasts is not None if _mtasts_validation else self.validation_error_starttls is not None)

    def has_warning(self) -> bool:
        return self.validation_warning is not None

    def get_validation_error(self, _mtasts_validation=False) -> str:
        return f"{self.validation_error}: {self.validation_error_mtasts if _mtasts_validation else self.validation_error_starttls}"

    def get_validation_warning(self) -> str:
        return self.validation_warning
