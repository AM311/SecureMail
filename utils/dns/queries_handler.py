import concurrent.futures

import dns.resolver

from classes.dns.rr import RR_MX, RR_CNAME, RR_A, RR_MTASTS, RR_NS, RR_SPF, RR_DMARC, RR_DMARC_REPORT, RR_TLSRPT, \
    RR_DKIM, RR_DNSKEY
from classes.dns.rr_list import RR_List
from utils.dkim.common_selectors_generator import generate_selectors
from utils.mail.organizational_domains import get_organizational_domain


# todo GESTIRE QUI DIRETTAMENTE MTASTS (e altri)

def query(_domain, _record_type="A"):
    try:
        if _record_type == 'NS':
            _domain_parts = _domain.split('.')

            while len(_domain_parts) > 2:
                _current_domain = '.'.join(_domain_parts)

                try:
                    _answers = dns.resolver.resolve(_current_domain, _record_type)

                    _rr_list = RR_List(_current_domain)
                    for _rr in _answers:
                        _rr_list.add_rr(RR_NS(_current_domain, _rr))
                    return _rr_list
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    _domain_parts.pop(0)

            _current_domain = '.'.join(_domain_parts)

            _answers = dns.resolver.resolve(_current_domain, _record_type)

            _rr_list = RR_List(_current_domain)
            for _rr in _answers:
                _rr_list.add_rr(RR_NS(_current_domain, _rr))
        elif _record_type == 'MTASTS':
            _domain = f"_mta-sts.{_domain}"

            _answers = dns.resolver.resolve(_domain, "TXT")

            _ok_rrs = [_rr for _rr in _answers if _rr.to_text().startswith("\"v=STSv1;")]

            if len(_ok_rrs) > 0:
                _rr_list = RR_List(_domain)
                for _rr in _ok_rrs:
                    _rr_list.add_rr(RR_MTASTS(_domain, _rr))
            else:
                raise dns.resolver.NoAnswer
        elif _record_type == 'TLSRPT':
            _domain = f"_smtp._tls.{_domain}"

            _answers = dns.resolver.resolve(_domain, "TXT")

            _ok_rrs = [_rr for _rr in _answers if _rr.to_text().startswith("\"v=TLSRPTv1;")]

            if len(_ok_rrs) > 0:
                _rr_list = RR_List(_domain)
                for _rr in _ok_rrs:
                    _rr_list.add_rr(RR_TLSRPT(_domain, _rr))
            else:
                raise dns.resolver.NoAnswer
        elif _record_type == 'SPF':
            _done = False

            try:
                _answers_spf = dns.resolver.resolve(_domain, "SPF")

                _ok_rrs = [_rr for _rr in _answers_spf if _rr.to_text().startswith("\"v=spf1")]

                if len(_ok_rrs) > 0:
                    _rr_list = RR_List(_domain)
                    for _rr in _ok_rrs:
                        _rr_list.add_rr(RR_SPF(_domain, _rr))

                    _done = True
            except dns.resolver.NoAnswer:
                pass

            if not _done:
                _answers_txt = dns.resolver.resolve(_domain, "TXT")

                _ok_rrs = [_rr for _rr in _answers_txt if _rr.to_text().startswith("\"v=spf1")]

                if len(_ok_rrs) > 0:
                    _rr_list = RR_List(_domain)
                    for _rr in _ok_rrs:
                        _rr_list.add_rr(RR_SPF(_domain, _rr))
                else:
                    raise dns.resolver.NoAnswer
        elif _record_type == 'DKIM':
            def process_selector(_selector, _domain):
                _query_domain = f"{_selector}._domainkey.{_domain}"

                try:
                    _answers = dns.resolver.resolve(_query_domain, "TXT")

                    _ok_rrs = [_rr for _rr in _answers if
                               (_rr.to_text().startswith("\"v=DKIM1;") or ("p=" in _rr.to_text()))]

                    if len(_ok_rrs) > 0:
                        _rr_list = RR_List(_query_domain)
                        for _rr in _ok_rrs:
                            _rr_list.add_rr(RR_DKIM(_query_domain, _rr))

                        return _rr_list  # Success flag
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                return None  # No result found

            # ---

            _selectors = generate_selectors(_domain)

            _found = False

            _res = []

            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Mappa ogni selector alla funzione da eseguire in parallelo
                futures = {executor.submit(process_selector, _selector, _domain): _selector for _selector in _selectors}

                # Gestisce i risultati quando sono pronti
                for future in concurrent.futures.as_completed(futures):
                    _rr_list = future.result()
                    if _rr_list is not None:
                        _res.append(_rr_list)
                        #break         # Interroga tutte

            if len(_res) == 0:
                _rr_list = RR_List(_domain)
                _rr_list.set_empty_cause('NOANSWER')
                return [_rr_list]

            return _res
        elif _record_type == 'DMARC':
            _dmarc_prefix = "_dmarc."

            _current_domain = f"{_dmarc_prefix}{_domain}"

            try:
                _answers = dns.resolver.resolve(_current_domain, 'TXT')

                _ok_rrs = [_rr for _rr in _answers if _rr.to_text().startswith("\"v=")]

                if len(_ok_rrs) > 0:
                    _rr_list = RR_List(_current_domain)
                    for _rr in _ok_rrs:
                        _rr_list.add_rr(RR_DMARC(_current_domain, _rr))
                    return _rr_list
                #else:
                #    raise dns.resolver.NoAnswer

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # ---

            _current_domain = f"{_dmarc_prefix}{get_organizational_domain(_domain)}"

            _answers = dns.resolver.resolve(_current_domain, 'TXT')

            _ok_rrs = [_rr for _rr in _answers if _rr.to_text().startswith("\"v=")]

            if len(_ok_rrs) > 0:
                _rr_list = RR_List(_current_domain)
                for _rr in _ok_rrs:
                    _rr_list.add_rr(RR_DMARC(_current_domain, _rr))
            else:
                raise dns.resolver.NoAnswer
        else:
            _rr_list = RR_List(_domain)

            _answers = dns.resolver.resolve(_domain, _record_type)

            if _record_type == 'MX':
                for _rr in _answers:
                    _rr_list.add_rr(RR_MX(_domain, _rr))

            elif _record_type == 'A':
                for _rr in _answers:
                    _rr_list.add_rr(RR_A(_domain, _rr))

            elif _record_type == 'CNAME':
                for _rr in _answers:
                    _rr_list.add_rr(RR_CNAME(_domain, _rr))

            elif _record_type == 'DNSKEY':
                for _rr in _answers:
                    _rr_list.add_rr(RR_DNSKEY(_domain, _rr))

            else:
                raise ValueError("Unhandled record type")

        return _rr_list

    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        _error_map = {
            dns.resolver.NoAnswer: "NOANSWER",
            dns.resolver.NoNameservers: "NONAMESERVERS",
            dns.resolver.NXDOMAIN: "NXDOMAIN",
            dns.resolver.Timeout: "TIMEOUT"
        }

        _error_type = _error_map.get(type(e))

        _rr_list = RR_List(_domain)
        _rr_list.set_empty_cause(_error_type)

        return _rr_list


def query_dmarc_delegation(_source_domain, _report_domain):
    _tokens_report = _report_domain.split('@')

    if len(_tokens_report) == 2:
        _report_domain = _tokens_report[1]

    #####

    _domain = f"{_source_domain}._report._dmarc.{_report_domain}"

    try:
        _answers = dns.resolver.resolve(_domain, "TXT")

        _rr_list = RR_List(_domain)
        for _rr in _answers:
            _rr_list.add_rr(RR_DMARC_REPORT(_domain, _rr))

        return _rr_list

    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        _error_map = {
            dns.resolver.NoAnswer: "NOANSWER",
            dns.resolver.NoNameservers: "NONAMESERVERS",
            dns.resolver.NXDOMAIN: "NXDOMAIN",
            dns.resolver.Timeout: "TIMEOUT"
        }

        _error_type = _error_map.get(type(e))

        _rr_list = RR_List(_domain)
        _rr_list.set_empty_cause(_error_type)

        return _rr_list
