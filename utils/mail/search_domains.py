import csv

import dns
import numpy as np
import pandas as pd
from tqdm import tqdm

from utils.dns.queries_handler import query
from utils.mail.mail_parser import get_unique_domains


def analyze_list(_list):
    _domains = get_unique_domains(_list)

    _valid_domains = []

    for _domain in tqdm(_domains, desc="Analyzing domains"):
        try:
            _res = query(_domain, 'MX')

            if _res and not _res.is_empty():
                _valid_domains.append(_domain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

    return _valid_domains


# ==========

def get_domains_ita_OLD():
    _regioni = pd.read_csv("../../data/geo_it_REGIONI.csv", delimiter=';').iloc[:, 0].tolist()
    _province = pd.read_csv("../../data/geo_it_PROVINCE.csv", delimiter=';').iloc[:, 0].tolist()
    _comuni = pd.read_csv("../../data/geo_it_COMUNI.csv", delimiter=';').iloc[:, 0].tolist()
    _gov = pd.read_csv("../../data/gov_it.csv", delimiter=';').iloc[:, 0].tolist()

    # --- PREFIX ---
    _regioni = _regioni + ['regione.' + _item for _item in _regioni]
    _province = _province + ['provincia.' + _item for _item in _province]
    _comuni = _comuni + ['comune.' + _item for _item in _comuni]
    _gov = _gov + [_item.replace('.gov', '') for _item in _gov]

    # ---

    _list_regioni = analyze_list(_regioni)
    _list_province = analyze_list(_province)
    _list_comuni = analyze_list(_comuni)
    _list_gov = analyze_list(_gov)

    # ---

    _list_pa_it = _list_regioni + _list_province + _list_comuni + _list_gov

    print(f"{len(_list_pa_it)} domains found")

    with open('../../data/src/DOMAINS_IT_old.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        for item in tqdm(_list_pa_it, desc="Exporting List", colour='green'):
            writer.writerow([item])


# ---

def get_domains_ita():
    _src = pd.read_csv("https://indicepa.gov.it/ipa-dati/datastore/dump/d09adf99-dc10-4349-8c53-27b1e5aa97b6?bom=True", delimiter=',',
                       header=0)

    _src['Sito_istituzionale'] = _src['Sito_istituzionale'].str.lower()

    _filter = (
            (_src['Tipologia'] == 'Pubbliche Amministrazioni') &
            (~_src['Sito_istituzionale'].str.contains(r'\.edu\.', na=False))            #todo LE SCUOLE VENGONO ESCLUSE
    )

    _src = _src.loc[_filter, 'Sito_istituzionale'].tolist()
    _src = [_x for _x in _src if _x and pd.notna(_x)]

    for _domain in _src:
        if '.gov.' in _domain:
            _domain_alt = _domain.replace('.gov', '')
            _src.append(_domain_alt)

    _domains = analyze_list(_src)

    print(f"{len(_domains)} domains found")

    with open('../../data/src/DOMAINS_IT.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        for item in tqdm(_domains, desc="Exporting List", colour='green'):
            writer.writerow([item])


def get_domains_usa():
    _src = pd.read_csv("https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv", delimiter=',',
                       header=1).iloc[:, 0].tolist()

    _domains = analyze_list(_src)

    print(f"{len(_domains)} domains found")

    with open('../../data/src/DOMAINS_USA.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        for item in tqdm(_domains, desc="Exporting List", colour='green'):
            writer.writerow([item])


# ---

def get_domains_uk():
    _src = pd.read_csv(
        "https://assets.publishing.service.gov.uk/media/6784f6eff029f40e508816d9/List_of_.gov.uk_domain_names_as_of_13_January_2025.csv",
        delimiter=',', header=1).iloc[:, 0].tolist()

    _domains = analyze_list(_src)

    print(f"{len(_domains)} domains found")

    with open('../../data/src/DOMAINS_UK.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        for item in tqdm(_domains, desc="Exporting List", colour='green'):
            writer.writerow([item])


# ---

def get_domains_de():
    _src = \
    pd.read_csv("https://raw.githubusercontent.com/robbi5/german-gov-domains/master/data/domains.csv", delimiter=',',
                header=1).iloc[:, 0].tolist()

    _domains = analyze_list(_src)

    print(f"{len(_domains)} domains found")

    with open('../../data/src/DOMAINS_DE.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        for item in tqdm(_domains, desc="Exporting List", colour='green'):
            writer.writerow([item])


# ==========


if __name__ == "__main__":
    print("Processing IT Domains")
    get_domains_ita()

    print("Processing USA Domains")
    get_domains_usa()

    print("Processing UK Domains")
    get_domains_uk()

    print("Processing DE Domains")
    get_domains_de()
