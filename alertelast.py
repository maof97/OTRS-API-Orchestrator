#!/usr/bin/env python3
ELASTIC_HOST = "http://10.24.1.5:9200"
ELASTIC_USER = 'Martin'
CLIENT_DOMAIN = "http://otrs.cloud.swiftbird.de:8077"
CLIENT_URL = CLIENT_DOMAIN+"/otrs/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST"
OTRS_QUEUE = "Elastic SIEM (BOC) - T1"

host_map = {
  "10.24.0.1" : "pPfsense",
  "10.24.0.2" : "pProxySSL",
  "10.24.1.4" : "pWindowsServer2019",
  "10.24.1.5" : "pElasticsearch",
  "10.24.1.6" : "pKibana",
  "10.24.1.7" : "pLogstash",
  "10.24.1.8" : "pELK-Helper",
  "159.69.208.27" : "Cloud-OTRS",
  "192.168.178.1" : "FritzBox.local",
  "192.168.178.87" : "Pfsense.local",
  "192.168.178.86" : "ProxmoxServer.local",
  "192.168.178.95" : "WindowsServer.local",
  "10.26.0.10" : "MacBookPro von Martin",
  "10.26.0.3" : "iPhone von Martin",
  "10.26.0.5" : "DESKTOP-FAAPB3V",
  "10.26.0.99" : "Cloud OTRS (WG)"
}

# Start of Script #
from hashlib import new
from ssl import ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE, ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY
from termios import TIOCPKT_FLUSHWRITE
from typing import Dict, KeysView
from pyotrs import Client
from pyotrs.lib import Article, Ticket
import requests
import ipaddress
import pprint
from datetime import datetime
from datetime import timedelta
import re
import signal
import sys
from threading import Timer
import signal
import time
import traceback
from elasticsearch import Elasticsearch
import os
import validators
import base64
from distutils import util
from functools import reduce

DoneTitles = dict()

OTRS_USER_PW = os.environ['OTRS_USER_PW']
ELASTIC_PW = os.environ['ELASTIC_PW']

try:
    DRY_RUN = not bool(util.strtobool(os.environ['OTRS_ORCH_PROD']))
except:
    DRY_RUN = True

elastic_client = Elasticsearch(hosts=[ELASTIC_HOST], http_auth=(ELASTIC_USER, ELASTIC_PW))
client = Client(CLIENT_URL,"SIEMUser",OTRS_USER_PW)
client.session_create()


def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)


def mark_acknowledged(id):
  try:
    elastic_client.update(index='.internal.alerts-security.alerts-default-000001',id=id, body={"doc": {"kibana.alert.workflow_status": "acknowledged"}})
  except:
    print("Non-fatal Error, trying to update SIEM alert to acknowledged.")


def send_to_otrs(title, prio, queue, body):
  same_ticket_found = False

  last_day = datetime.utcnow() - timedelta(days=1)
  search_tickets = client.ticket_search(TicketCreateTimeNewerDate=last_day, StateType=['new', 'open'], Title=title)
  print(search_tickets)
  try:
    if search_tickets[0]:
      print("Found ticket with same title")
      same_ticket_found = True
      same_ticket_id = search_tickets[0]
  except:
    pass

  # Search if done locally:
  same_ticket_id = DoneTitles.get(title, False)
  if same_ticket_id:
    print("Found ticket with same title done by alertelast itself.")
    same_ticket_found = True

  # Map Elastic Prio to OTRS Prio
  prio_map = {"low": u"4 low", "medium" : u"3 normal", "high" : u"2 high", "critical" : u"1 very-high"}
  otrs_prio = prio_map[prio]

  article = Article({"Subject" : title, "Body" : body})
  if not same_ticket_found:
    new_ticket = Ticket.create_basic(Title=title, Queue=queue, Type="Alert", State=u"new", Priority=otrs_prio, CustomerUser="SIEM_API")
    result = client.ticket_create(new_ticket, article)
    print("Created new ticket.")
    DoneTitles[title] = result['TicketID']
  else:
    print(client.ticket_update(same_ticket_id, article=article))
    client.ticket_update(same_ticket_id, StateType="new", State="new")
    print("Updated ticket.")


def handle_alert(doc):
  is_suricata = False
  msg = ""
  prio = "medium"
  id = deep_get(doc, '_id')
  doc = deep_get(doc, '_source')
  print("Handling Alert with _id: "+id)


  # Parse params
  title = doc['kibana.alert.rule.name']

  try: # Fix Suricata Severity
    prio_suricata = deep_get(doc, 'suricata.eve.alert.metadata.signature_severity')
    if prio_suricata == "Major":
      prio = "critical"
  except:
    prio = deep_get(doc, 'kibana.alert.severity')

  #Check if Suricata Alert 
  src_port = deep_get(doc, 'suricata.eve.src_ip', default='')
  if src_port != '':
    is_suricata = True

  
  # Parse Title
  src = deep_get(doc, 'source.ip', default='')
  src = deep_get(doc, 'host.hostname', default=src)
  src = deep_get(host_map, src, default=src)
  try:
    a = host_map[src]
    if a != None:
      src = a
  except:
    pass
  dst = deep_get(doc, 'destination.ip', default='')
  try:
    a = host_map[dst]
    if a != None:
      dst = a
  except:
    pass

  if (((src or dst) == '') or ((src or dst) == None)):
    title = title + " | Host: "+src+dst
  else:
    title = title + " ["+src+" > "+dst+")"


  if not is_suricata:
    msg =  "Parsed info should be below.\n\nRULE NAME: {}\n\nRULE QUERY: {}\n\nRULE DESCRIPTION: {}\n\n\nPROCESS: {}\n\nPARENT PROC: {}\n\nSource IP: {}\n\nDestination IP: {}:{} \n\nDomain: {}".format(\
    doc['kibana.alert.rule.name'],doc["kibana.alert.rule.parameters"],doc['kibana.alert.rule.description'] ,deep_get(doc, "process"), deep_get(doc, "process.parent"), deep_get(doc, "source.ip"), deep_get(doc, "destination.ip"), deep_get(doc, "destination.port"), deep_get(doc, "dns.question.name"))
  else:
    msg = "Parsed info should be below.\n\nCATEGORY: {}\nRULE [SID) NAME: [{}] {}\n\n\nSOURCE IP: {} : {} ({})\nDESTINATION IP: {} : {} ({})\n\n\nPAYLOAD:\n{}\n\nHTTP:\n{}\n\nVirusTotal Lookup:\nSRC: https://www.virustotal.com/gui/ip-address/{} \nDST: https://www.virustotal.com/gui/ip-address/{}\n\nAlert Info Search:\nET: https://doc.emergingthreats.net/bin/view/Main/WebSearch?search={} \nSnort: https://snort.org/rule_docs?utf8=✓&rules_query={} (maybe trunc. to 5 numbers)\nSnort RAW: https://github.com/codecat007/snort-rules/search?q=sid%3A{} \n\nDNS Query: {}\
      ".format(deep_get(doc, "suricata.eve.alert.category"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature"),deep_get(doc, "suricata.eve.src_ip"),deep_get(doc, "suricata.eve.src_port"),deep_get(doc, "source.geo.geo.country_iso_code"),deep_get(doc, "suricata.eve.dest_ip") ,deep_get(doc, "suricata.eve.dest_port"),deep_get(doc, "destination.geo.geo.country_iso_code"),deep_get(doc, "suricata.eve.payload_printable"),deep_get(doc, "suricata.eve.http"),deep_get(doc, "suricata.eve.src_ip"),deep_get(doc, "suricata.eve.dest_ip"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature_id"), deep_get(doc, "suricata.eve.dns.query.rrname"))
  
  #print(msg)
  print(title)
  send_to_otrs(title, prio, OTRS_QUEUE, msg)
  mark_acknowledged(id)




def query_open_rules():
  print("Quering rules of ELastic SIEM...")
  # Take the user's parameters and put them into a Python
  # dictionary structured like an Elasticsearch query:
  query_body = {
    "query": {
      "bool": {
        "must": {
          "match": {      
            "kibana.alert.workflow_status" : "open"
          }
        }
      }
    }
  }

  # call the client's search() method, and have it return results
  result = elastic_client.search(index=".internal.alerts-security.alerts-default-*", body=query_body, size=999)

  # see how many "hits" it returned using the len() function
  print ("total hits:", len(result["hits"]["hits"]))
  all_hits = result['hits']['hits']

  # iterate the nested dictionaries inside the ["hits"]["hits"] list
  for num, doc in enumerate(all_hits):
      print ("DOC ID:", doc["_id"])

      handle_alert(doc)
      #print(doc.get('_source.source.ip', 'mssing'))

      # print a few spaces between each doc for readability
      print ("\n\n")
  print("Done Quering Elastic SIEM")
      


query_open_rules()
