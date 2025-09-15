import pandas as pd
from tqdm import tqdm

from classes.domain_status import DomainStatus


def analyze_mx_servers(_domain_statuses: list[DomainStatus]):
    _servers_statuses = []

    for _domain_status in tqdm(_domain_statuses, desc="MX Analysis", ncols=100, position=1, leave=False):
        for _mx in _domain_status.certificates.get_mx_certificates():
            _server_data = {}

            _server_data['domain'] = _domain_status.domain
            _server_data['host'] = _mx.domain
            _server_data['port'] = _mx.port
            _server_data['is_reachable'] = _mx.is_reachable
            _server_data['is_enabled'] = _mx.is_enabled
            _server_data['error'] = _mx.error

            _cert = _mx.certificate

            _server_data['certificate_key_type'] = (_cert.key_type if _cert else None)
            _server_data['certificate_key_length'] = (_cert.key_length if _cert else None)
            _server_data['certificate_signature_algorithm'] = (_cert.signature_algorithm if _cert else None)
            _server_data['certificate_validation_error'] = (_cert.validation_error if _cert else None)
            _server_data['certificate_validation_error_mtasts'] = (_cert.validation_error_mtasts if _cert else None)
            _server_data['certificate_validation_error_starttls'] = (_cert.validation_error_starttls if _cert else None)
            _server_data['certificate_validation_warning'] = (_cert.validation_warning if _cert else None)

            _servers_statuses.append(_server_data)

    _servers_statuses_df = pd.DataFrame(_servers_statuses)

    return _servers_statuses_df

