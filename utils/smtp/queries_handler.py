import smtplib
import ssl
import time

from classes.certificates.domain_certificate import Certificate
from classes.certificates.tls_status import TLS_Status_Entry

from socket import timeout as SocketTimeout, error as SocketError


# todo VEDERE SE LOCAL HOSTNAME HA IMPATTO
def get_mailserver_tls_certificate(_domain, _host, _port=25, _local_hostname="tvb31.ddnsfree.com"):
    _is_reachable = False
    _is_enabled = False
    _cert = None

    _error = None

    for attempt in range(3):
        try:
            # SMTP Connection without SSL
            with smtplib.SMTP(host=_host, port=_port, local_hostname=_local_hostname, timeout=10) as _smtp:
                _is_reachable = True

                _smtp.ehlo(_local_hostname)

                if _smtp.has_extn("STARTTLS"):
                    _is_enabled = True

                    _context = ssl.create_default_context()
                    _context.check_hostname = False
                    _context.verify_mode = ssl.CERT_NONE                #todo VALIDAZIONE FATTA MANUALMENTE

                    _smtp.starttls(context=_context)

                    _smtp.ehlo(_local_hostname)

                    # --- Retrieves certificate
                    try:
                        _der_cert = _smtp.sock.getpeercert(binary_form=True)

                        if _der_cert is not None:
                            _pem_cert = ssl.DER_cert_to_PEM_cert(_der_cert)
                            _cert = _pem_cert.encode("utf-8")

                            _cert = Certificate(_domain, _host, _cert)
                    except Exception as e:
                        _error = e
                        pass

                break
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, SocketTimeout, SocketError) as e:
            _error = e
            time.sleep(0.5 + attempt*1)  # breve attesa prima del retry
        except Exception as e:
            _error = e
            break

    return TLS_Status_Entry(_host, _port, _is_reachable, _is_enabled, _cert, _error)
