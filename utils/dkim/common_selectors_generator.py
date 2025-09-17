def generate_selectors(_domain):
    def tatang_selectors():
        _selectors = []

        # ---

        _common_words = ['default', 'dkim', 'google', 'selektor', 'selector', 'selector1', 's1024', 's2048', 's512',
                         's1', 'postout', 'alpha', 'beta', 'gamma', 'test', 'mandilla', 'mailjet', 'mail', 'mail2']

        _selectors.extend(_common_words)

        # ---

        _starting_year = 2019
        _ending_year = 2026

        for _year in range(_starting_year, _ending_year):
            for _month in range(1, 13):
                for _day in range(1, 32):
                    _selectors.append(f"{_year}{_month:02d}{_day:02d}")
                    _selectors.append(f"{_year}-{_month:02d}-{_day:02d}")

                _selectors.append(f"{_year}{_month:02d}")
                _selectors.append(f"{_year}-{_month:02d}")

            _selectors.append(f"{_year}")

        # ---

        return _selectors

    def extended_selectors():  # todo SISTEMARE PRIMA DI USARE
        # Funzioni di espansione
        def expand_N(range_spec, leading_zero=False):
            lo, hi = map(int, range_spec.split(','))
            if leading_zero:
                return [f"{i:02d}" for i in range(lo, hi + 1)]
            else:
                return [str(i) for i in range(lo, hi + 1)]

        def expand_L(list_vals):
            return list_vals

        # Definizioni statiche
        L_dkim = ["dkim", "dk", "testdkim", "proddkim"]
        L_year = [str(y) for y in range(2015, 2026)]
        L_month = [f"{i:02d}" for i in range(1, 13)]
        L_month_ab = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
        L_day = [f"{i:02d}" for i in range(1, 32)]

        # Regole "common strings"
        prefixes = [
            *(f"k{n}" for n in expand_N("1,20")),
            "default", "google", "mail", "class",
            *(f"s{n}" for n in expand_N("384,2048")),
            *(f"m{n}" for n in expand_N("384,2048")),
            "smtpapi", "dkim", "bfi", "spop", "spop1024", "beta", "domk", "dk", "ei",
            *(f"yesmail{n}" for n in expand_N("1,20")),
            "smtpout", "sm",
            *(f"selector{n}" for n in expand_N("1,20")),
            "authsmtp", "alpha",
            *(f"v{n}" for n in expand_N("1,5")),
            "mesmtp", "cm", "prod", "pm", "gamma", "dkrnt", "dkimrnt", "private",
            "gmmailerd", "pmta",
            *(f"m{n}" for n in expand_N("1,20")),
            "x", "selector", "qcdkim", "postfix", "mikd", "main", "m", "dk20050327",
            "delta", "yibm", "wesmail", "test", "stigmate", "squaremail", "sitemail",
            *(f"sel{n}" for n in expand_N("1,20")),
            "sasl", "sailthru",
            *(f"rsa{n}" for n in expand_N("1,20")),
            "responsys", "publickey", "proddkim", "my0", "my1", "my2",  # example myN
            "mail-in", *(f"ls{n}" for n in expand_N("1,20")), "key", "ED-DKIM",
            "ebmailerd", *(f"eb{n}" for n in expand_N("1,20")),
            *(f"dk{n}" for n in expand_N("1,20")),
            "Corporate", "care", "0xdeadbeef", "yousendit", "www", "tilprivate", "testdk",
            "snowcrash", "smtpcomcustomers", "smtpauth", "smtp", "sl1", "sl2", "sharedpool",
            "ses", "server", "scooby", "scarlet", "safe", "s",
            *(f"s{n}" for n in expand_N("1,20")),
            "pvt", "primus", "primary", "postfix.private", "outbound", "originating", "one",
            "neomailout", "mx", "msa", "monkey", "mkt", "mimi", "mdaemon", "mailrelay",
            "mailjet", "mail-dkim", "mailo", "mandrill", "lists", "iweb", "iport", "id",
            "hubris", "googleapps", "global", "gears", "exim4u", "exim", "et", "dyn", "duh",
            "dksel", "dkimmail", "corp", "centralsmtp", "ca", "bfi", "auth", "allselector",
            "zendesk1"
        ]

        # "search" patterns
        search_patterns = []

        # uncreative
        search_patterns += [f"dk{n}" for n in expand_N("01,20", leading_zero=True)]
        search_patterns += [f"dk{n}" for n in expand_N("1,9")]
        search_patterns += [f"dkim{n}" for n in expand_N("01,20", leading_zero=True)]
        search_patterns += [f"dkim{n}" for n in expand_N("1,9")]
        search_patterns += ["dkim", "proddkim", "testdkim"]
        search_patterns += [f"{x}{n}" for x in L_dkim for n in expand_N("256,2048")]

        # todo AGGIUNGERE TUTTE VARIANTI CON/SENZA TRATTINO E CON ORDINI INVERSI
        # todo AGGIUNGERE ANNO-MESE-GIORNO
        # todo AGGIUNGERE PAROLE COMUNI (TATANG)

        # year
        for prefix in ["", "mail", "mail-", "dkim", "dkim-", "sel", "sel-", "d", "dk", "s", "pfx"]:
            for y in L_year:
                search_patterns.append(f"{prefix}{y}")

        # year+month
        for prefix in ["", "mail", "mail-", "dkim", "dkim-", "sel", "sel-", "d", "dk", "s"]:
            for y in L_year:
                for m in L_month:
                    search_patterns.append(f"{prefix}{y}-{m}")

        # two-digit year+month
        for y in expand_N("05,18"):
            for m in L_month:
                search_patterns.append(f"scph{y}-{m}")

        # month abbrev + year
        for mo in L_month_ab:
            for y in L_year:
                search_patterns.append(f"{mo}{y}")

        # year + quarter
        for q in expand_N("1,4"):
            for y in L_year:
                search_patterns.append(f"q{q}-{y}")
                search_patterns.append(f"{y}-{q}")

        # Ora le regole con dominio

        # --- DOMINIO + LISTA DI PAROLE ---
        # da: %D% %L,-dkim,-google%
        affix_words = ["dkim", "google"]
        domain_word_suffixes = [f"-{w}" for w in affix_words]

        # --- DOMINIO + NUMERO ---
        # da: %D% %O-% %N1,20%
        number_suffixes = [f"-{n}" for n in range(1, 21)] + [str(n) for n in range(1, 21)]

        # --- DOMINIO + ANNO ---
        # da: %D% %O-% %N2005,2018%
        year_suffixes = [f"-{y}" for y in range(2005, 2019)] + [str(y) for y in range(2005, 2019)]

        # --- Unione di tutti i suffissi ---
        suffixes = sorted(set(
            domain_word_suffixes +
            number_suffixes +
            year_suffixes
        ))

        # output finale
        completa = sorted(set(prefixes + search_patterns))
        suffissi = sorted(set(suffixes))

        print(len(completa), "combinazioni 'completa'")
        print(len(suffissi), "suffissi dominio")

        # todo PASSARE DOMINIO E RITORNARE SINGOLA LISTA DI SELETTORI

    return tatang_selectors()
