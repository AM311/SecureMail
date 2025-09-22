from collections import defaultdict

import pandas as pd
from tqdm import tqdm

from classes.domain_status import DomainStatus


def analyze_spf_policies(_domain_statuses: list[DomainStatus]):
    policies_statuses = []
    _domain_counts = defaultdict(int)

    for _domain_status in _domain_statuses:
        _dict = _domain_status.dns_entries.get_rrs_spf()

        if _dict and len(_dict) > 0:
            for _domain, _rrs in _dict.items():
                for _rr in _rrs:
                    _domain_counts[_rr.policy.domain] += 1  # todo check se albero è corretto

    # ---

    _res = pd.DataFrame(
        columns=['Main Domain', 'Policy Domain', 'Level', 'Included/Redirected', 'Number of Usages',
                 'Policy Validation Error', 'Domain SPF Error'])

    for _domain_status in tqdm(_domain_statuses, desc="SPF Policies Includes Analysis", ncols=100, position=1,
                               leave=False):
        _spf_error = _domain_status.errorCode_spf

        def analyze_policy(_level, _policy_domain, _inc_red=None):
            try:
                _policy = _domain_status.dns_entries.get_rrs_spf(_policy_domain).get(0).policy
                _policy_error = _policy.get_validation_error()

                for _inc in _policy.included_policies:
                    _local_policy = _inc['policy']         #todo PROBLEMATICO

                    analyze_policy(_level + 1, _local_policy.domain, _inc_red='Include')

                for _red in _policy.redirected_policies:
                    _local_policy = _red['policy']

                    analyze_policy(_level + 1, _local_policy.domain, _inc_red='Redirect')

                # ---

                _row = {
                    'Main Domain': _domain_status.domain,
                    'Policy Domain': _policy_domain,
                    'Level': _level,
                    'Included/Redirected': _inc_red,
                    'Number of Usages': _domain_counts[_policy_domain],
                    'Policy Validation Error': _policy_error,
                    'Domain SPF Error': _spf_error
                }

                _res.loc[len(_res)] = _row

            except Exception as e:
                pass

        # ---

        analyze_policy(0, _domain_status.domain)

    # ---

    return _res
