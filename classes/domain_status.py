from classes.certificates.domain_certificate import Certificate
from classes.certificates.tls_status import TLS_Status, TLS_Status_Entry
from classes.dns.domain_rrs import DomainRRs
from classes.policies.mtasts_policy import MTASTS_Policy
from utils.smtp.queries_handler import get_mailserver_tls_certificate
from utils.web.queries_handler import get_mtasts_policy


class DomainStatus:
    def __init__(self, domain):
        self.domain = domain

        self.dns_entries = DomainRRs(domain)

        self.mtasts_policy = None

        self.mtasts_policy_rule = None
        self.spf_policy_rule = None
        self.dmarc_policy_rule = None

        self.spf_policy_useInclude = None
        self.spf_policy_useRedirect = None

        # self.dkim_policy_isCname = None
        self.dmarc_policy_isCname = None

        self.dkim_nPolicies = None

        self.certificates = TLS_Status(domain)

        self.use_tlsrpt = None
        self.use_mtasts = None
        self.use_spf = None
        self.use_dkim = None
        self.use_dmarc = None
        self.use_starttls = None
        self.use_dnssec = None

        self.errorCode = None
        self.errorCode_tlsrpt = None
        self.errorCode_mtasts = None
        self.errorCode_spf = None
        self.errorCode_dkim = None
        self.errorCode_dmarc = None
        self.errorCode_starttls = None

        self.warningCode_spf = None
        self.warningCode_dkim = None
        self.warningCode_starttls = None

    # =====

    def analyze_domain(self):
        def analyze_general():
            # ===== General =====
            try:
                self.dns_entries.query_std()

                if self.dns_entries.get_rrs_mx(self.domain).is_empty():
                    self.errorCode = f"No RR MX retrieved for the domain: {self.dns_entries.get_rrs_mx(self.domain).empty_cause}"
                    return

                if not self.dns_entries.get_rrs_ns() or self.dns_entries.get_rrs_ns().is_empty():
                    self.errorCode = f"No RR NS retrieved for the domain: {self.dns_entries.get_rrs_ns(self.domain).empty_cause if self.dns_entries.get_rrs_ns(self.domain) is not None else "???"}"
                    return
            except ValueError as e:
                self.errorCode = f"ValueError while performing STD DNS Queries: {e}"
                return

        def analyze_mtasts():
            # ===== MTA-STS =====

            # --- DNS
            try:
                _mtasts_dns_domain = f"_mta-sts.{self.domain}"
                _mtasts_policy_domain = f"mta-sts.{self.domain}"

                self.dns_entries.query_mtasts()

                if self.dns_entries.get_rrs_mtasts(_mtasts_dns_domain).is_empty():
                    self.use_mtasts = False
                    return

                self.use_mtasts = True

                if self.dns_entries.get_rrs_mtasts(_mtasts_dns_domain).size() > 1:
                    self.errorCode_mtasts = "Multiple MTA-STS RRs found"
                    return

                if self.dns_entries.get_rrs_mtasts(_mtasts_dns_domain).has_invalid_rr():
                    self.errorCode_mtasts = f"Invalid MTA-STS RR: {self.dns_entries.get_rrs_mtasts(_mtasts_dns_domain).get(0).get_validation_error()}"
                    return

                if self.dns_entries.get_rrs_a(_mtasts_policy_domain).is_empty():
                    self.errorCode_mtasts = f"No RR A retrieved for the MTA-STS policy subdomain: {self.dns_entries.get_rrs_mx().empty_cause}"
                    return

                # todo VOLENDO, VALORIZZARE FLAG PER SEGNALARE DIVERSI DOMINI

            except ValueError as e:
                self.errorCode_mtasts = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_mtasts = f"Exception : {e}"
                return

            # --- HTTPS
            try:
                _policy, _status = get_mtasts_policy(self.domain)
                self.certificates.add_web_certificate(_status)

                if not _status.is_reachable:
                    self.errorCode_mtasts = f"Unable to contact MTA-STS web server: {_status.error}"
                    return

                if not _status.is_enabled:
                    self.errorCode_mtasts = f"Unable to retrieve MTA-STS web server's certificate: {_status.error}"
                    return

                if not _status.certificate or _status.certificate.is_invalid(True):
                    self.errorCode_mtasts = f"Invalid MTA-STS Web Server Certificate: {_status.certificate.get_validation_error()}"

                if not _policy:
                    self.errorCode_mtasts = "Unable to retrieve MTA-STS Policy"
                    return

                self.mtasts_policy = MTASTS_Policy(_policy)

                if self.mtasts_policy.is_invalid():
                    self.errorCode_mtasts = f"Invalid MTA-STS policy: {self.mtasts_policy.get_validation_error()}"
                    return

            except ValueError as e:
                self.errorCode_mtasts = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_mtasts = f"Exception : {e}"
                return

            # --- Policy Type

            self.mtasts_policy_rule = self.mtasts_policy.mode

            # --- Alignment

            _aligned_mxs = self.mtasts_policy.get_aligned(self.dns_entries.get_rrs_mx(self.domain))

            if _aligned_mxs.size() == 0:
                self.errorCode_mtasts = "All RR MX are disaligned with the policy"
                return

            # --- Matching MXs certificates

            _aligned_mx_status = False  # True se almeno un allineato ha certificato valido (PREVISTO DA RFC -- cfr.)

            for _mx_rr in (_mx.value for _mx in _aligned_mxs):
                try:
                    _mx_status = False

                    _cert_status = self.certificates.get_mx_certificates(_mx_rr)

                    if _cert_status.certificate and not _cert_status.certificate.is_invalid(True):
                        _aligned_mx_status = True

                except Exception:
                    pass

            if not _aligned_mx_status:
                self.errorCode_mtasts = "No matching RR MX presented a valid certificate"
                return

        def analyze_spf():
            # ===== SPF =====
            try:
                self.dns_entries.query_spf()

                if self.dns_entries.get_rrs_spf(self.domain).is_empty():
                    self.use_spf = False
                    return

                self.use_spf = True

                if self.dns_entries.get_rrs_spf(self.domain).size() > 1:
                    self.errorCode_spf = "Multiple SPF RRs found"
                    return

                if self.dns_entries.get_rrs_spf(self.domain).has_invalid_rr():
                    self.errorCode_spf = f"Invalid SPF RR: {self.dns_entries.get_rrs_spf(self.domain).get(0).get_validation_error()}"
                    return

                _policy = self.dns_entries.get_rrs_spf(self.domain).get(0).policy

                # ---

                if len(_policy.get_includes()) > 0:
                    self.spf_policy_useInclude = True
                else:
                    self.spf_policy_useInclude = False

                if len(_policy.get_redirects()) > 0:
                    self.spf_policy_useRedirect = True
                else:
                    self.spf_policy_useRedirect = False

                # ---

                self.spf_policy_rule = _policy.get_default_policy()

                # ---

                # todo VOLENDO, VALORIZZARE FLAG PER SEGNALARE DIVERSI DOMINI

                # todo Vedere se implementato nel migliore dei modi (cfr) ...
                if _policy.check_overlaps():
                    self.warningCode_spf = f"SPF policy has overlapping IPs"
                    return

            except ValueError as e:
                self.errorCode_spf = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_spf = f"Exception : {e}"
                return

        def analyze_dkim():
            # ===== DKIM =====
            # todo OSS: non si filtra per dominio perché non si sa in quale sottodominio sia stata recuperata la policy
            try:
                self.dns_entries.query_dkim()

                if not self.dns_entries.get_rrs_dkim() or len(self.dns_entries.get_rrs_dkim()) == 0:
                    self.use_dkim = False
                    return

                self.use_dkim = True

                self.dkim_nPolicies = len(self.dns_entries.get_rrs_dkim())

                # todo RIVEDERE DA QUI -- Capire come validare --

                _err = None
                _status = False

                for _dict in self.dns_entries.get_rrs_dkim():
                    for _domain, _rrs in _dict.items():
                        #if _rrs.size() > 1:
                        #    _err = "Multiple DKIM RRs found for the same selector"
                        #    continue

                        if _rrs.has_invalid_rr():
                            _err = f"Invalid DKIM RR: {_rrs.get(0).get_validation_error()}"
                            continue

                        _status = True

                if _err:
                    if _status:
                        self.warningCode_dkim = f"Some DKIM policies have errors"
                    else:
                        self.errorCode_dkim = f"All DKIM policies have errors"

                # todo -- FINO A QUI --

            except ValueError as e:
                self.errorCode_dkim = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_dkim = f"Exception : {e}"
                return

        def analyze_dmarc():
            # ===== DMARC =====
            # todo OSS: non si filtra per dominio perché non si sa in quale sottodominio sia stata recuperata la policy
            try:
                self.dns_entries.query_dmarc()

                if not self.dns_entries.get_rrs_dmarc() or self.dns_entries.get_rrs_dmarc().is_empty():
                    self.use_dmarc = False
                    return

                self.use_dmarc = True

                if self.dns_entries.get_rrs_cname(self.dns_entries.get_rrs_dmarc().domain).is_empty():
                    self.dmarc_policy_isCname = False
                else:
                    self.dmarc_policy_isCname = True

                if self.dns_entries.get_rrs_dmarc().size() > 1:
                    self.errorCode_dmarc = "Multiple DMARC RRs found"
                    return

                if self.dns_entries.get_rrs_dmarc().has_invalid_rr():
                    self.errorCode_dmarc = f"Invalid DMARC RR: {self.dns_entries.get_rrs_dmarc().get(0).get_validation_error()}"
                    return

                _policy = self.dns_entries.get_rrs_dmarc().get(0).policy

                # -----

                self.dmarc_policy_rule = _policy.policy

                # -----

                if _policy.rua:
                    _policy_rua_tokens = str(_policy.rua).split('@')
                    if len(_policy_rua_tokens) > 1:
                        _policy_rua_domain = _policy_rua_tokens[1]
                    else:
                        _policy_rua_domain = _policy_rua_tokens[0]

                    if _policy_rua_domain != _policy.base_domain:
                        _report_domain = f"{_policy.base_domain}._report._dmarc.{_policy_rua_domain}"

                        self.dns_entries.query_dmarc_report(_policy.base_domain, _policy_rua_domain)

                        if self.dns_entries.get_rrs_dmarc_report(_report_domain).is_empty():
                            self.errorCode_dmarc = "Missing DMARC RR for RUA delegation"
                            return

                        if not self.dns_entries.get_rrs_dmarc_report(_report_domain).get(0).is_valid():
                            self.errorCode_dmarc = f"Invalid DMARC RR for RUA delegation: {self.dns_entries.get_rrs_dmarc_report(_report_domain).get(0).get_validation_error()}"
                            return

                if _policy.ruf:
                    _policy_ruf_tokens = str(_policy.ruf).split('@')
                    if len(_policy_ruf_tokens) > 1:
                        _policy_ruf_domain = _policy_ruf_tokens[1]
                    else:
                        _policy_ruf_domain = _policy_ruf_tokens[0]

                    if _policy_ruf_domain != _policy.base_domain:
                        _report_domain = f"{_policy.base_domain}._report._dmarc.{_policy_ruf_domain}"

                        self.dns_entries.query_dmarc_report(_policy.base_domain, _policy_ruf_domain)

                        if self.dns_entries.get_rrs_dmarc_report(_report_domain).is_empty():
                            self.errorCode_dmarc = "Missing DMARC RR for RUF delegation"
                            return

                        if not self.dns_entries.get_rrs_dmarc_report(_report_domain).get(0).is_valid():
                            self.errorCode_dmarc = f"Invalid DMARC RR for RUF delegation: {self.dns_entries.get_rrs_dmarc_report(_report_domain).get(0).get_validation_error()}"
                            return

                # todo VOLENDO, VALORIZZARE FLAG PER SEGNALARE DIVERSI DOMINI

            except ValueError as e:
                self.errorCode_dmarc = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_dmarc = f"Exception : {e}"
                return

        def analyze_starttls():
            # ===== STARTTLS =====

            self.use_starttls = False

            for _mx_rr in (_mx.value for _mx in self.dns_entries.get_rrs_mx(self.domain)):
                try:
                    self.certificates.add_mx_server(get_mailserver_tls_certificate(self.domain, _mx_rr))
                except Exception:
                    pass

            # --> TRUE if at least one MX passes checks

            _is_reachable = False
            _is_enabled = False
            _cert_valid = False

            _warning = True

            for _entry in self.certificates.get_mx_certificates():
                if _entry.is_reachable:
                    _is_reachable = True
                if _entry.is_enabled:
                    _is_enabled = True
                if _entry.certificate and not _entry.certificate.is_invalid():
                    _cert_valid = True

                if _entry.certificate and not _entry.certificate.has_warning():
                    _warning = False
                elif _entry.certificate and _entry.certificate.has_warning():
                    self.warningCode_starttls = _entry.certificate.get_validation_warning()

            if not _is_reachable:
                self.errorCode_starttls = f"No MX reachable"
                return

            if _is_enabled:
                self.use_starttls = True

                if not _cert_valid:
                    self.errorCode_starttls = "No MX server presented a valid certificate"
                    return

                # todo Volendo, si potrà iterare analisi sui singoli MX problematici per ottenere dettagli sull'errore di validazione

        def analyze_tlsrpt():
            # ===== TLS-RPT =====

            try:
                _tlsrpt_dns_domain = f"_smtp._tls.{self.domain}"

                self.dns_entries.query_tlsrpt()

                if self.dns_entries.get_rrs_tlsrpt(_tlsrpt_dns_domain).is_empty():
                    self.use_tlsrpt = False
                    return

                self.use_tlsrpt = True

                if self.dns_entries.get_rrs_tlsrpt(_tlsrpt_dns_domain).size() > 1:
                    self.errorCode_tlsrpt = "Multiple TLS-RPT RRs found"
                    return

                if self.dns_entries.get_rrs_tlsrpt(_tlsrpt_dns_domain).has_invalid_rr():
                    self.errorCode_tlsrpt = f"Invalid TLS-RPT RR: {self.dns_entries.get_rrs_tlsrpt(_tlsrpt_dns_domain).get(0).get_validation_error()}"
                    return

                # todo VOLENDO, VALORIZZARE FLAG PER SEGNALARE DIVERSI DOMINI

            except ValueError as e:
                self.errorCode_tlsrpt = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_tlsrpt = f"Exception : {e}"
                return

        def analyze_dnssec():
            # ===== DNSSEC =====

            try:
                self.dns_entries.query_dnssec()

                if self.dns_entries.get_rrs_dnskey(self.domain).is_empty():
                    self.use_dnssec = False
                    return

                self.use_dnssec = True

                # todo OSS: FATTA VERIFICA BASE!

            except ValueError as e:
                self.errorCode_tlsrpt = f"ValueError : {e}"
                return
            except Exception as e:
                self.errorCode_tlsrpt = f"Exception : {e}"
                return

        #####

        analyze_general()

        if not self.errorCode:
            #print(f"Domain: {self.domain} -- GENERAL finished")
            analyze_starttls()  # PRIMA di MTA-STS !!!
            #print(f"Domain: {self.domain} -- STARTTLS finished")
            analyze_spf()
            #print(f"Domain: {self.domain} -- SPF finished")
            analyze_dkim()
            #print(f"Domain: {self.domain} -- DKIM finished")
            analyze_dmarc()
            #print(f"Domain: {self.domain} -- DMARC finished")
            analyze_mtasts()
            #print(f"Domain: {self.domain} -- MTASTS finished")
            analyze_tlsrpt()
            #print(f"Domain: {self.domain} -- TLSRPT finished")
            analyze_dnssec()
            #print(f"Domain: {self.domain} -- DNSSEC finished")

    ##### ==========

    def get_policies(self):
        _policies = list()

        if self.use_spf:
            _policies_spf = list()
            for _dom, _rr_list in self.dns_entries.get_rrs_spf().items():
                _policies_domain = list()
                for _rr in _rr_list:
                    _policies_domain.append(_rr.policy.to_dict())

                _policies_spf.append({_dom: _policies_domain})
            _policies.append({'SPF': _policies_spf})

        if self.use_dkim:
            _policies_dkim = list()

            _dicts = self.dns_entries.get_rrs_dkim()

            for _dict in _dicts:
                for _dom, _rr_list in _dict.items():
                    for _rr in _rr_list:
                        _policies_dkim.append({_dom: [_rr.policy.to_dict()]})

            _policies.append({'DKIM': _policies_dkim})

        if self.use_dmarc:
            _policies_dmarc = list()
            for _dom, _rr_list in self.dns_entries.get_rrs_dmarc(False).items():
                _policies_domain = list()
                for _rr in _rr_list:
                    _policies_domain.append(_rr.policy.to_dict())

                _policies_dmarc.append({_dom: _policies_domain})
            _policies.append({'DMARC': _policies_dmarc})
        if self.use_mtasts:
            _rrs_mtasts = list()
            for _dom, _rr_list in self.dns_entries.get_rrs_mtasts().items():
                _policies_domain = list()
                for _rr in _rr_list:
                    _policies_domain.append(_rr.to_dict())

                _rrs_mtasts.append({_dom: _policies_domain})
            _policies.append({'MTA-STS-RR': _rrs_mtasts})

            # ---

            if self.mtasts_policy:
                _policies.append({'MTA-STS-Policy': self.mtasts_policy.to_dict()})
            else:
                _policies.append({'MTA-STS-Policy': None})
        if self.use_tlsrpt:
            _policies_tlsrpt = list()
            for _dom, _rr_list in self.dns_entries.get_rrs_tlsrpt().items():
                _policies_domain = list()
                for _rr in _rr_list:
                    _policies_domain.append(_rr.policy.to_dict())

                _policies_tlsrpt.append({_dom: _policies_domain})
            _policies.append({'TLS-RPT': _policies_tlsrpt})

        return _policies

    ##### ==========

    def __repr__(self):
        _str = f"[{self.domain}] analysis results:\r\n"

        if self.errorCode:
            _str += f"\t❌ GENERIC ERROR while analyzing the domain: {self.errorCode}"
        else:
            # --- SPF ---
            _str += "\t >>> SPF <<<\r\n"

            if not self.use_spf:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_spf:
                    _str += f"\t\t❌ ERROR in SPF configuration: {self.errorCode_spf}\r\n"
                elif self.warningCode_spf:
                    _str += f"\t\t⚠️ WARNING in SPF configuration: {self.warningCode_spf}\r\n"
                else:
                    _str += f"\t\t✅ SPF correctly configured\r\n"

            # --- DKIM ---
            _str += "\t >>> DKIM <<<\r\n"

            if not self.use_dkim:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_dkim:
                    _str += f"\t\t❌ ERROR in DKIM configuration: {self.errorCode_dkim}\r\n"
                elif self.warningCode_dkim:
                    _str += f"\t\t⚠️ WARNING in DKIM configuration: {self.warningCode_dkim}\r\n"
                else:
                    _str += f"\t\t✅ DKIM correctly configured\r\n"

            # --- DMARC ---
            _str += "\t >>> DMARC <<<\r\n"

            if not self.use_dmarc:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_dmarc:
                    _str += f"\t\t❌ ERROR in DMARC configuration: {self.errorCode_dmarc}\r\n"
                else:
                    _str += f"\t\t✅ DMARC correctly configured\r\n"

            # --- MTA-STS ---
            _str += "\t >>> MTA-STS <<<\r\n"

            if not self.use_mtasts:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_mtasts:
                    _str += f"\t\t❌ ERROR in MTA-STS configuration: {self.errorCode_mtasts}\r\n"
                else:
                    _str += f"\t\t✅ MTA-STS correctly configured\r\n"

            # --- STARTTLS ---
            _str += "\t >>> STARTTLS <<<\r\n"

            if not self.use_starttls:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_starttls:
                    _str += f"\t\t❌ ERROR in STARTTLS configuration: {self.errorCode_starttls}\r\n"
                elif self.warningCode_starttls:
                    _str += f"\t\t⚠️ WARNING in STARTTLS configuration: {self.warningCode_starttls}\r\n"
                else:
                    _str += f"\t\t✅ STARTTLS correctly configured\r\n"

            # --- TLS-RPT ---
            _str += "\t >>> TLS-RPT <<<\r\n"

            if not self.use_tlsrpt:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

                if self.errorCode_tlsrpt:
                    _str += f"\t\t❌ ERROR in TLS-RPT configuration: {self.errorCode_tlsrpt}\r\n"
                else:
                    _str += f"\t\t✅ TLS-RPT correctly configured\r\n"

            # --- DNSSEC ---
            _str += "\t >>> DNSSEC <<<\r\n"

            if not self.use_dnssec:
                _str += f"\t\t🔴 NOT IN USE\r\n"
            else:
                _str += f"\t\t💚 IN USE\r\n"

        return _str
