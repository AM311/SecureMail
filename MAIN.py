import json
import pickle

import pandas as pd
from tqdm import tqdm

from classes.domain_status import DomainStatus
from utils.certificates.mx_analyzer import analyze_mx_servers
from utils.dkim.records_analyzer import analyze_dkim_records
from utils.dns.providers_analyzer import analyze_dns_results
from utils.mail.mail_parser import get_unique_domains
from utils.spf.ips_analyzer import analyze_ips
import concurrent.futures

#_prefix = "C:/Users/aless/OneDrive/UniTS/IN20 - Prova Finale/TEST_WebScraping/"
_prefix = ""

if __name__ == "__main__":
    csv_file = f"{_prefix}data/src/DOMAINS_DE.csv"

    _source = pd.read_csv(csv_file, delimiter=';', header=None)

    _mails = _source.iloc[:, 0].tolist()
    _domains = get_unique_domains(_mails)

    print(f"{len(_domains)} domains found\r\n")

    ################

    _domain_statuses = []
    _policies = []

    ################

    with tqdm(desc="PROGRESS", total=5, colour='blue', ncols=100, position=0) as total_progress:
        _res = pd.DataFrame(
            columns=['Domain', 'GeneralErrors', 'SPF Enabled', 'SPF Default Qualifier', 'SPF Use Include',
                     'SPF Use Redirect', 'SPF Errors', 'SPF Warnings', 'DKIM Enabled', 'DKIM nPolicies', 'DKIM Warning',
                     'DKIM Error', 'DMARC Enabled', 'DMARC Policy', 'DMARC is CNAME', 'DMARC Error',
                     'STARTTLS Enabled', 'STARTTLS Error', 'STARTTLS Warning', 'TLS-RPT Enabled',
                     'TLS-RPT Errors', 'MTA-STS Enabled', 'MTA-STS Mode', 'MTA-STS Errors', 'DNSSEC Enabled'])


        def process_domain(_domain):
            print(f"\r\nBEGIN: {_domain}\r\n")
            _domain_status = DomainStatus(_domain)
            _domain_statuses.append(_domain_status)
            _domain_status.analyze_domain()
            _policies.append({_domain: _domain_status.get_policies()})
            print(f"\r\nEND: {_domain}\r\n")

            _row = [[_domain, _domain_status.errorCode, _domain_status.use_spf, _domain_status.spf_policy_rule,
                     _domain_status.spf_policy_useInclude, _domain_status.spf_policy_useRedirect,
                     _domain_status.errorCode_spf, _domain_status.warningCode_spf, _domain_status.use_dkim,
                     _domain_status.dkim_nPolicies, _domain_status.warningCode_dkim, _domain_status.errorCode_dkim,
                     _domain_status.use_dmarc,
                     _domain_status.dmarc_policy_rule, _domain_status.dmarc_policy_isCname,
                     _domain_status.errorCode_dmarc,
                     _domain_status.use_starttls, _domain_status.errorCode_starttls,
                     _domain_status.warningCode_starttls,
                     _domain_status.use_tlsrpt, _domain_status.errorCode_tlsrpt, _domain_status.use_mtasts,
                     _domain_status.mtasts_policy_rule, _domain_status.errorCode_mtasts, _domain_status.use_dnssec]]

            return _row

        _rows = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            with tqdm(total=len(_domains), desc="Domains Analysis", ncols=100, colour='green', position=1,
                      leave=False) as pbar:
                _futures = {executor.submit(process_domain, _domain): _domain for _domain in _domains}

                for _row in concurrent.futures.as_completed(_futures):
                    _rows.extend(_row.result())
                    pbar.update()

        #_rows = []

        #for _domain in tqdm(_domains, desc="Domains Analysis", ncols=100, colour='green', position=1, leave=False):
        #    print(f"\r\nINIZIO: {_domain}\r\n")
        #    _res = process_domain(_domain)
        #    print(f"\r\nFINE: {_domain}\r\n")

        #    _rows.extend(_res)

        _res = pd.DataFrame(_rows, columns=_res.columns)
        _res.to_csv(f"{_prefix}data/OUT/Summary.csv", index=False)

        # === EXPORTS ===

        with open(f"{_prefix}data/OUT/DomainStatuses.pkl", "wb") as file:
            pickle.dump(_domain_statuses, file)

        with open(f"{_prefix}data/OUT/Policies.json", "w") as file:
            json.dump(_policies, fp=file, indent=2)

        total_progress.update()

        # ---

        _domains_dns_rrs = []

        for _domain_status in _domain_statuses:
            _dns_rrs = _domain_status.dns_entries
            _domains_dns_rrs.append(_dns_rrs)

        with open(f"{_prefix}data/OUT/DNS.json", "w") as file:
            json.dump([_drrs.to_dict() for _drrs in _domains_dns_rrs], fp=file, indent=2)

        _ip_counts = analyze_ips(_domain_statuses)

        with open(f"{_prefix}data/OUT/IPs.json", "w") as file:
            json.dump(_ip_counts, fp=file, indent=2)

        total_progress.update()

        # ---

        _autonomous_systems, _providers = analyze_dns_results(_domain_statuses)

        _providers.to_csv(f"{_prefix}data/OUT/Providers.csv", index=False)

        with open(f"{_prefix}data/OUT/AutonomousSystems.json", "w") as file:
            json.dump(_autonomous_systems, fp=file, indent=2)

        total_progress.update()

        # ---

        _mx_statuses = analyze_mx_servers(_domain_statuses)

        _mx_statuses.to_csv(f"{_prefix}data/OUT/MXs.csv", index=False)

        total_progress.update()

        # ---

        _dkim_statuses = analyze_dkim_records(_domain_statuses)

        _dkim_statuses.to_csv(f"{_prefix}data/OUT/DKIM.csv", index=False)

        total_progress.update()
