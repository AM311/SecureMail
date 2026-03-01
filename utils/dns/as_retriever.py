# as_retriever.py
import csv
import gzip
import ipaddress
import shutil
from pathlib import Path
from sortedcontainers import SortedDict


_ASN_DATA_CACHE = None
_ASN_FILEPATH = 'data/ip2asn-v4.tsv'
_ASN_URL = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz'


# --------------------------------------------------------
# 1) Caricamento e caching del database ASN
# --------------------------------------------------------
def _download_asn_dataset():
    import requests

    try:
        response = requests.get(_ASN_URL, stream=True)
        response.raise_for_status()

        with open(_ASN_FILEPATH + ".gz", 'wb') as f:
            shutil.copyfileobj(response.raw, f)

        with gzip.open(_ASN_FILEPATH + ".gz", 'rb') as f_in:
            with open(_ASN_FILEPATH, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    except Exception as e:
        print(f"[ASN DOWNLOAD ERROR] {e}")


def _load_asn_table():
    table = SortedDict()

    try:
        with open(_ASN_FILEPATH, newline='', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter="\t")

            for row in reader:
                if len(row) < 5:
                    continue

                ip_start = ipaddress.ip_address(row[0])
                ip_end = ipaddress.ip_address(row[1])

                table[ip_start] = {
                    "ip_end": ip_end,
                    "asn": row[2],
                    "country": row[3],
                    "org": row[4]
                }

    except Exception as e:
        print(f"[ASN LOAD ERROR] {e}")
        return None

    return table


def load_asn_data(force_reload=False):
    global _ASN_DATA_CACHE

    if force_reload or _ASN_DATA_CACHE is None:
        if force_reload or not Path(_ASN_FILEPATH).exists():
            _download_asn_dataset()

        _ASN_DATA_CACHE = _load_asn_table()

    return _ASN_DATA_CACHE


# --------------------------------------------------------
# 2) Lookup ASN di un singolo IP
# --------------------------------------------------------
def get_as(ip):
    """
    Ritorna {asn, org, country} per un IP.
    """
    table = load_asn_data()
    if not table:
        return None

    # Normalizza input
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip_obj = ip
    else:
        ip = str(ip)
        ip_obj = ipaddress.ip_address(ip)

    # Trova il massimo ip_start ≤ ip
    for ip_start in table.irange(maximum=ip_obj):
        entry = table[ip_start]
        if ip_start <= ip_obj <= entry["ip_end"]:
            return {
                "asn": entry["asn"],
                "org": entry["org"],
                "country": entry["country"]
            }

    return None


# --------------------------------------------------------
# 3) Lookup ASN per una SUBNET (nuova funzione)
# --------------------------------------------------------
def get_as_ranges_for_subnet(ip_start, ip_end):
    """
    Trova tutti gli AS che intersecano la subnet [ip_start, ip_end].
    Return: lista di intervalli ASN.
    """
    table = load_asn_data()
    if not table:
        return []

    if isinstance(ip_start, str):
        ip_start = ipaddress.ip_address(ip_start)
    if isinstance(ip_end, str):
        ip_end = ipaddress.ip_address(ip_end)

    results = []

    for as_ip_start in table.irange(maximum=ip_end):
        entry = table[as_ip_start]
        as_ip_end = entry["ip_end"]

        # Intersezione intervalli
        if as_ip_start <= ip_end and as_ip_end >= ip_start:
            results.append({
                "ip_start": as_ip_start,
                "ip_end": as_ip_end,
                "asn": entry["asn"],
                "org": entry["org"],
                "country": entry["country"],
            })

        if as_ip_start > ip_end:
            break

    return results
