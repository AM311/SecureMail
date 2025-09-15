import pandas as pd

_public_suffixes_src = pd.read_csv(
    "../../data/public_suffixes_agg.csv", delimiter=';')
_public_suffixes = _public_suffixes_src.iloc[:, 0].tolist()


def get_organizational_domain(_domain):
    _domain_tokens = _domain.split('.')

    _max_index = -1

    for _idx, _token in enumerate(reversed(_domain_tokens)):
        _cur_domain = '.'.join(_domain_tokens[-(_idx + 1):])

        if _cur_domain in _public_suffixes:
            _max_index = _idx
        else:
            break

    return '.'.join(_domain_tokens[-(_max_index + 2):])
