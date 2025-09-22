from classes.certificates.domain_certificate import Certificate


class TLS_Status_Entry:
    def __init__(self, _domain: str, _port: int, _is_reachable: bool, _is_enabled: bool, _cert: (Certificate | None),
                 _error=None):
        self.domain = _domain
        self.port = _port
        self.is_reachable = _is_reachable
        self.is_enabled = _is_enabled  # For MX, means STARTTLS is enabled
        self.certificate = _cert

        self.error = _error

    def __str__(self):
        return (f"Domain: {self.domain},\r\n"
                f"Port: {self.port},\r\n"
                f"IsReachable: {self.is_reachable},\r\n"
                f"IsEnabled: {self.is_enabled},\r\n"
                f"Certificate: {self.certificate},\r\n"
                f"Error: {self.error}")


class TLS_Status:
    def __init__(self, _domain):
        self.domain = _domain

        self.mx_servers = []
        self.web_servers = []

    def __add_server(self, _collection: list, _entry: TLS_Status_Entry):
        _collection.append(_entry)

    def add_mx_server(self, _entry: TLS_Status_Entry):
        self.__add_server(self.mx_servers, _entry)

    def add_web_certificate(self, _entry: TLS_Status_Entry):
        self.__add_server(self.web_servers, _entry)

    #####

    # todo RIVEDERE DA QUI

    def __get_certificate(self, _collection: list, _domain=None):
        if _domain is None:
            return _collection
        else:
            _list = [_c for _c in _collection if _c.domain == _domain]

            if len(_list) == 0:
                return None
            else:
                return _list[0]

    def get_mx_certificates(self, _domain=None):
        return self.__get_certificate(self.mx_servers, _domain)

    def get_web_certificates(self, _domain=None):
        return self.__get_certificate(self.web_servers, _domain)
