import re


def get_unique_domains(_mail_addresses: list[str]):
    _domains = set()

    for _addr in _mail_addresses:
        _addr = _addr.lower()

        _addr = _addr.replace('http://', '')
        _addr = _addr.replace('https://', '')
        _addr = _addr.replace('www.', '')
        _addr = _addr.split('/')[0]

        _tokens = _addr.split('@')

        if len(_tokens) == 2:
            _dom = _tokens[1]
        else:
            _dom = _tokens[0]

        if re.match(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63}(?<!-))*$', _dom):
            _domains.add(_dom)

    return _domains
