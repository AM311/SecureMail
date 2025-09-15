import csv
import gzip
import ipaddress
import shutil
from pathlib import Path

import requests
from sortedcontainers import SortedDict

_ASN_DATA_CACHE = None


def get_as(_ip, _download_new=False):
    _filepath = 'data/ip2asn-v4.tsv'
    global _ASN_DATA_CACHE

    def download_as_dataset():
        _url = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz'
        try:
            _response = requests.get(_url, stream=True)
            _response.raise_for_status()

            # Saves .gz file
            with open(_filepath + ".gz", 'wb') as _file:
                shutil.copyfileobj(_response.raw, _file)

            # Decompress .gz into .tsv
            with gzip.open(_filepath + ".gz", 'rb') as _file_in:
                with open(_filepath, 'wb') as _file_out:
                    shutil.copyfileobj(_file_in, _file_out)

        except requests.exceptions.RequestException as e:
            print(f"Error while downloading file: {e}")
        except Exception as e:
            print(f"Error while decompressing file: {e}")

    def load_as_from_file():
        as_data_dict = SortedDict()

        try:
            with open(_filepath, newline='', encoding='utf-8') as f:
                _reader = csv.reader(f, delimiter='\t')

                for _row in _reader:
                    if len(_row) >= 5:
                        _ip_start = ipaddress.ip_address(_row[0])
                        _ip_end = ipaddress.ip_address(_row[1])
                        _asn = _row[2]
                        _country = _row[3]
                        _organization = _row[4]

                        #_as_data.append((_ip_start, _ip_end, _asn, _country, _organization))
                        as_data_dict[_ip_start] = {
                            'ip_end': _ip_end,
                            'asn': _asn,
                            'org': _organization,
                            'country': _country
                        }
                    else:
                        raise ValueError('Invalid row')
        except Exception as e:
            print(f"Error: {e}")
            return None
        return as_data_dict

    def search_as(_ip, _asn_data):
        _ip = ipaddress.ip_network(_ip, strict=False).network_address if '/' in _ip else ipaddress.ip_address(_ip)

        for _ip_start in _asn_data.irange(minimum=None, maximum=_ip):
            _entry = _asn_data[_ip_start]
            _ip_end = _entry['ip_end']
            if _ip_start <= _ip <= _ip_end:  # Confronta gli oggetti IPAddress
                return {'asn': _entry['asn'], 'org': _entry['org']}

        return None

    # =====

    try:
        if _download_new or _ASN_DATA_CACHE is None:
            if _download_new or not Path(_filepath).exists():
                download_as_dataset()

            _ASN_DATA_CACHE = load_as_from_file()

        _res = search_as(_ip, _ASN_DATA_CACHE)

        return _res
    except Exception as e:
        print(f"Error while managing dataset file: {e}")
