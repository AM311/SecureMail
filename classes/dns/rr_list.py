from collections.abc import Iterable

from classes.dns.rr import RR


class RR_List(Iterable):
    def __init__(self, _domain : str):
        self.domain = _domain
        self.empty_cause = None
        self.rrs = list()

    def __iter__(self):
        return iter(self.rrs)

    def to_dict(self):
        return {
            #"domain": self.domain,
            "empty_cause": self.empty_cause,
            "rrs": [rr.to_dict() for rr in self.rrs]
        }

    # -----

    def add_rr(self, _rr: RR):
        self.rrs.append(_rr)
        self.empty_cause = None

    def extend(self, _rr_list):
        self.rrs.extend(_rr_list)
        self.empty_cause = None

    def size(self):
        return len(self.rrs)

    def get(self, _index):
        return self.rrs[_index]

    # -----

    def set_empty_cause(self, _empty_cause: str):
        self.empty_cause = _empty_cause

    def is_empty(self):
        return len(self.rrs) == 0

    def has_invalid_rr(self):
        for _rr in self.rrs:
            if not _rr.is_valid():
                return True

        return False

    # -----

    def __repr__(self):
        _str = f"{self.domain}:\r\n"

        if self.is_empty():
            _str += f"{self.empty_cause}\r\n"
        else:
            for _rr in self.rrs:
                _str += f"\t{_rr}\r\n"

        return _str

    def __str__(self):
        return self.__repr__()