from collections import defaultdict

import pandas as pd
from tqdm import tqdm

from classes.domain_status import DomainStatus


def analyze_dkim_records(_domain_statuses: list[DomainStatus]):
    _dkim_statuses = []
    _key_counts = defaultdict(int)

    #todo RIVEDERE LOGICA ANNIDAMENTO DKIM

    for _domain_status in _domain_statuses:
        _dicts = _domain_status.dns_entries.get_rrs_dkim()

        if _dicts and len(_dicts) > 0:
            for _dict in _dicts:
                for _domain, _rrs in _dict.items():
                    for _rr in _rrs:
                        _key_counts[_rr.policy.publicKey] += 1

    for _domain_status in tqdm(_domain_statuses, desc="DKIM Analysis", ncols=100, position=1, leave=False):
        _dicts = _domain_status.dns_entries.get_rrs_dkim()

        if _dicts and len(_dicts) > 0:
            for _dict in _dicts:
                for _domain, _rrs in _dict.items():
                    _policy_data = {}

                    _multiple_rr = _rrs.size()

                    if _domain_status.dns_entries.get_rrs_cname(_domain).is_empty():
                        _cname = None
                    else:
                        _cname = _domain_status.dns_entries.get_rrs_cname(_domain).get(0).value

                    for _rr in _rrs:
                        _policy_data['domain'] = _domain_status.domain
                        _policy_data['rr_domain'] = _domain
                        _policy_data['multiple_rrs'] = (None if _multiple_rr == 1 else _multiple_rr)

                        _policy = _rr.policy

                        if _policy.is_invalid():
                            _policy_data['error'] = _policy.get_validation_error()
                        else:
                            _policy_data['error'] = None

                        _policy_data['cname'] = _cname

                        # ---

                        _policy_data['version'] = _policy.version
                        _policy_data['hashAlgs'] = _policy.hashAlgs
                        _policy_data['keyType'] = _policy.keyType
                        _policy_data['notes'] = _policy.notes
                        _policy_data['publicKey'] = _policy.publicKey
                        _policy_data['keyLength'] = _policy.keyLength
                        _policy_data['serviceTypes'] = _policy.serviceTypes
                        _policy_data['flags'] = _policy.flags
                        _policy_data['otherTerms'] = _policy.otherTerms

                        _policy_data['keyUsageCount'] = _key_counts[_policy.publicKey]

                        _dkim_statuses.append(_policy_data)

    _dkim_statuses_df = pd.DataFrame(_dkim_statuses)

    return _dkim_statuses_df
