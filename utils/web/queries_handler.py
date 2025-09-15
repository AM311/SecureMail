import socket
import ssl
from urllib.parse import urlparse

import requests

from classes.certificates.domain_certificate import Certificate
from classes.certificates.tls_status import TLS_Status_Entry


def get_mtasts_policy(_domain):

    def https_request(_url):
        _headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }

        # ---

        _parsed_url = urlparse(_url)
        _domain = _parsed_url.hostname

        # ---

        _cert = None
        _status = None
        _response = None

        try:
            _context = ssl.create_default_context()
            with socket.create_connection((_domain, 443)) as _sock:
                with _context.wrap_socket(_sock, server_hostname=_domain) as _ssock:
                    _der_cert = _ssock.getpeercert(binary_form=True)
                    _pem_cert = ssl.DER_cert_to_PEM_cert(_der_cert)

                    _cert = _pem_cert.encode("utf-8")
                    _cert = Certificate(_domain.split('.',1)[1], _domain, _cert)

                _status = TLS_Status_Entry(_domain, 443, _is_reachable=True, _is_enabled=True, _cert=_cert)

            # ---

            _response = requests.get(_url, headers=_headers, timeout=10, verify=True)
            if _response.status_code == 200:
                _response = _response.text
            else:
                _status = TLS_Status_Entry(_domain, 443, _is_reachable=True, _is_enabled=False, _cert=None, _error=f"Invalid HTTP Response status code: {_response.status_code}")

        except requests.exceptions.SSLError as ssl_error:
            _status = TLS_Status_Entry(_domain, 443, _is_reachable=True, _is_enabled= False, _cert=None, _error=f"SSL Error: {ssl_error}")
        except requests.RequestException as e:
            _status = TLS_Status_Entry(_domain, 443, _is_reachable=True, _is_enabled=False, _cert=None, _error=e)

        return _response, _status

    #####

    _mtasts_domain = f"mta-sts.{_domain}"

    _url = f"https://{_mtasts_domain}/.well-known/mta-sts.txt"

    return https_request(_url)
