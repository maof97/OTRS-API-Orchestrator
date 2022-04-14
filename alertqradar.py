#!/usr/bin/env python3

import argparse
import datetime
import json
import syslog

import dateutil.tz
import requests

import qradar_helper
import os


class QRadar():

    def __init__(self, config):
        self.client = qradar_helper.TokenClient(
            config["host"],
            os.environ['QRADAR_API_TOKEN'],
        )

    def get_offenses(self):
        fields = ["id", "description", "start_time", "rules", "categories", "credibility", "device_count", "log_sources", "magnitude", "offense_source", "relevance", "severity"]
        params = {
            "fields": ",".join(fields),
            "filter": "status = OPEN and follow_up = False",
            "sort": "+id",
        }
        try:
            offenses = self.client.request(
                method="GET",
                path="/api/siem/offenses",
                params=params,
            )
        except requests.exceptions.RequestException as e:
            print(str(e))
            syslog.syslog(str(e))
            syslog.syslog(e.response.text)
            exit()
        return offenses

    def get_rule(self, rule):
        fields = ["name", "type", "origin"]
        params = {
            "fields": ",".join(fields),
        }
        try:
            rule = self.client.request(
                method="GET",
                path="/api/analytics/rules/" + str(rule),
                params=params,
            )
        except requests.exceptions.RequestException as e:
            syslog.syslog(str(e))
            syslog.syslog(e.response.text)
        return rule

    def set_tag(self, offense):
        try:
            if os.environ["OTRS_ORCH_PROD"] == "True":
                _ = self.client.request(
                    method="POST",
                    path="/api/siem/offenses/" + str(offense),
                    params={
                        "fields": "",
                        "follow_up": "true",
                    },
                )
        except requests.exceptions.RequestException as e:
            syslog.syslog(str(e))
            syslog.syslog(e.response.text)

    def create_note(self, offense, ticket):
        try:
            _ = self.client.request(
                method="POST",
                path="/api/siem/offenses/{:d}/notes".format(offense),
                params={
                    "fields": "",
                    "note_text": "Ticket #" + str(ticket),
                },
            )
        except requests.exceptions.RequestException as e:
            syslog.syslog(str(e))
            syslog.syslog(e.response.text)

class OTRS():

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        self.session.headers["Content-Type"] = "application/json"
        if "CustomerUserLogin" in config:
            self.session.params["CustomerUserLogin"] = config["CustomerUserLogin"]
        else:
            self.session.params["UserLogin"] = config["UserLogin"]
        self.session.params["Password"] = os.environ['OTRS_USER_PW_QRADAR']
        self.url = "https://{:s}/otrs/nph-genericinterface.pl/Webservice/{:s}/Ticket".format(
            config["host"], config["webservice"],
        )
        self.template = {
                "Ticket": {
                        "Title": "",
                        "Queue": config["Queue"],
                "Type": "Unclassified",
                        "State": "new",
                        "PriorityID": config["PriorityID"],
                "CustomerUser": config["CustomerUser"],
                },
                "Article": {
                "CommunicationChannel": "Internal",
                "From": "\"IBM QRadar SIEM\" <qradar@cdc.consecur.de>",
                        "Subject": "",
                        "Body": "",
                "MimeType": "text/plain",
                "Charset": "utf8",
                },
            "DynamicField": [
                {
                    "Name": "ProcessManagementProcessID",
                    "Value": "Process-faaa29848b2a9fccaea0e5c1d9bb3be1",
                },
                {
                    "Name": "ProcessManagementActivityID",
                    "Value": "Activity-bb863fa19f703dcc84ef3265e76e1051",
                                },
            ],
        }

    def create_ticket(self, offense):

        data = self.template.copy()
        title = "QRadar SIEM: " + offense["description"].replace('\n', '')
        title += (" | Offender: "+offense["offense_source"])
        data["Ticket"]["Title"] = title
        data["Article"]["Subject"] = "[QRadar] Offense " + str(offense["id"])
        data["Article"]["Body"] = "A new QRadar Offense has been created.\n\nData:\n" + json.dumps(
            obj=offense,
            ensure_ascii=False,
            check_circular=False,
            indent=' '*4,
            default=default,
            sort_keys=False,
        )
        if os.environ["OTRS_ORCH_PROD"] == "True":
            response = self.session.post(
                self.url,
                json=data,
                timeout=10.0,
                verify=False,
            )
            response.raise_for_status()
            data = response.json()
            if "Error" in data:
                raise RuntimeError(str(data["Error"]))
            return data["TicketNumber"]
        else:
            print("Would sent ticket now, but debug mode is activated. Here is the ticket body that would have been sent:\n\n",data)



def default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError



#requests.packages.urllib3.disable_warnings()

# logging
syslog.openlog(logoption=syslog.LOG_PID)

# argparse
#parser = argparse.ArgumentParser()
#parser.add_argument("config", type=argparse.FileType('r'))
#args = parser.parse_args()

# settings
config = json.load(open('config.json'))

qradar = QRadar(config["QRadar"])

# QRadar Offenses
syslog.syslog("Connecting to {:s} ...".format(config["QRadar"]["host"]))
offenses = qradar.get_offenses()
syslog.syslog("{:d} new offenses".format(len(offenses)))
if not offenses:
    exit()

# QRadar Rules
rules = {}
for offense in offenses:
    for rule in offense["rules"]:
        rules[rule["id"]] = {}
for rule_id in rules.keys():
    rules[rule_id] = qradar.get_rule(rule_id)
for offense in offenses:
    for i in range(len(offense["rules"])):
        offense["rules"][i] = rules[offense["rules"][i]["id"]]
    offense["start_time"] = datetime.datetime.fromtimestamp(
        offense["start_time"]/1000,
        tz=dateutil.tz.gettz("Europe/Berlin"),
    )

# Link to offense
for offense in offenses:
    offense["url"] = "https://{:s}/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={:d}".format(
        config["QRadar"]["host"],
        offense["id"],
    )

otrs = OTRS(config["OTRS"])

for offense in offenses:
    try:
        ticket_number = otrs.create_ticket(offense)
    except requests.exceptions.RequestException as e:
        syslog.syslog(str(e))
        syslog.syslog(e.response.text)
    # QRadar Tag and Note
    qradar.set_tag(offense["id"])
    qradar.create_note(offense["id"], ticket_number)