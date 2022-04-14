import abc
import json
import logging
import time

import requests



logger = logging.getLogger(__name__)



class Client(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, host, verify: bool = False):
        self.host = host

        if not verify:
            requests.packages.urllib3.disable_warnings()

        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Version"] = "12"
        self.session.verify = verify

    def request(self, method: str, path: str, params: dict = None):
        assert method in ("GET", "POST", "DELETE")
        logger.info("{:s} {:s}".format(method, path))
        response = self.session.request(
            method = method,
            url = "https://" + self.host + path,
            params = params,
            timeout = 10.0,
        )
        response.raise_for_status()
        body = response.json()
        return body

    def search(self, aql: str, polling_frequency: float = 1.0):
        # POST /api/ariel/searches
        url = "https://{:s}/api/ariel/searches".format(self.host)
        logger.info("POST /api/ariel/searches")
        response = self.session.post(
            url = url,
            params = {
                "query_expression": aql,
            },
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 201:
            logger.critical(body["message"])
            return None

        # GET /api/ariel/searches/{search_id}
        url += "/" + body["search_id"]
        while body["status"] not in ["COMPLETED", "ERROR"]:
            time.sleep(polling_frequency)
            logger.info("GET /api/ariel/searches/" + body["search_id"])
            response = self.session.get(
                url = url,
                timeout = 10.0,
            )
            if response.status_code != 200:
                logger.warning(body["message"])
                continue
            body = response.json()
            logger.debug("{:s} ({:3d} %)".format(
                body["search_id"],
                body["progress"],
            ))
        if body["status"] == "ERROR":
            for error_message in body["error_messages"]:
                logger.critical(error_message["message"])
            return None

        # GET /api/ariel/searches/{search_id}/results
        url += "/results"
        logger.info("GET /api/ariel/searches/{:s}/results".format(body["search_id"]))
        response = self.session.get(
            url = url,
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 200:
            logger.critical(body["message"])
            return None
        return body

    def dns_lookup(self, ip: str, polling_frequency: float = 1.0):
        # POST /api/services/dns_lookups
        url = "https://{:s}/api/services/dns_lookups".format(self.host)
        logger.info("POST /api/services/dns_lookups")
        response = self.session.post(
            url = url,
            params = {
                "IP": ip,
            },
            timeout = 10.0,
        )
        body = response.json()
        if response.status_code != 201:
            logger.critical(body["message"])
            return None

        # GET /api/services/dns_lookups/{dns_lookup_id}
        url += "/{:d}".format(body["id"])
        while body["status"] not in ["COMPLETED", "ERROR"]:
            time.sleep(polling_frequency)
            logger.info("GET /api/services/dns_lookups/{:d}".format(body["id"]))
            response = self.session.get(
                url = url,
                timeout = 10.0,
            )
            if response.status_code != 200:
                logger.warning(body["message"])
                continue
            body = response.json()
            logger.debug("{:d} {:s}".format(
                body["id"],
                body["status"],
            ))
        if body["status"] == "ERROR":
            for error_message in body["error_messages"]:
                logger.critical(error_message["message"])
            return None
        message = json.loads(body["message"])
        return message[0]

    def __del__(self):
        self.session.close()

class CredentialClient(Client):

    def __init__(self, host, username, password, verify: bool = False):
        super().__init__(host, verify)
        self.session.auth = (username, password)

class TokenClient(Client):

    def __init__(self, host, token, verify: bool = False):
        super().__init__(host, verify)
        self.session.headers["SEC"] = token