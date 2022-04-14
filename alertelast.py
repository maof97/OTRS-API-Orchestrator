#!/usr/bin/env python3
ELASTIC_HOST = "https://10.20.1.6:9200"
ELASTIC_USER = 'Kibana-API'
CLIENT_DOMAIN = "https://otrs.cloud.swiftbird.de:8078"
CLIENT_URL = CLIENT_DOMAIN+"/otrs/nph-genericinterface.pl/Webservice/ALERTELAST_API"
OTRS_QUEUE = "SIEM - T1 (Bochum)"

host_map = {
  "10.24.0.1" : "pPfsense",
  "10.24.0.2" : "pProxySSL",
  "10.24.1.3" : "PVE-WINSRV-DC2",
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
  "10.26.0.4" : "iPad von Martin",
  "10.26.0.5" : "DESKTOP-FAAPB3V",
  "10.26.0.99" : "Cloud OTRS (WG)",
  "10.250.0.1" : "XLAB PfSense",
  "10.251.0.2" : "XLAB Kali-Linux",
  "10.252.0.1" : "XLAB UTMFW",
  "10.24.0.30" : "pMinecraft"
}

# Start of Script #
from hashlib import new
from queue import Queue
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
from rsa import verify
import validators
import base64
from distutils import util
from functools import reduce
from ssl import create_default_context
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging
import logging.handlers
import socket

DoneTitles = dict()

OTRS_USER_PW = os.environ['OTRS_USER_PW']
ELASTIC_PW = os.environ['ELASTIC_PW']


# Remote Logging setup
rlog = logging.getLogger('MyLogger')
rlog.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = ('127.0.0.1',514))
rlog.addHandler(handler)

def l(type, msg):
  print(f"(SYSLOG) ALERTELAST@{socket.gethostname()},logLevel=INFO, productive={not DRY_RUN}, msg={msg}")
  rlog.info(f"ALERTELAST@{socket.gethostname()},logLevel=INFO, productive={not DRY_RUN}, type={type}, {msg}")

try:
    DRY_RUN = not bool(util.strtobool(os.environ['OTRS_ORCH_PROD']))
except:
    DRY_RUN = True

context = create_default_context()
context.check_hostname = False
elastic_client = Elasticsearch(hosts=[ELASTIC_HOST], http_auth=(ELASTIC_USER, ELASTIC_PW),ssl_context=context,verify_certs=False)
client = Client(CLIENT_URL,"Kibana-SIEM",OTRS_USER_PW)



def deep_get(dictionary, keys, default=None):
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)


def mark_acknowledged(id):
  suc = False

  try:
    idx = requests.get(ELASTIC_HOST+"/_cat/indices/.internal.alerts-security.alerts-default-*?h=idx", auth=(ELASTIC_USER, ELASTIC_PW),verify=False)

    for index in idx.text.splitlines():
      headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
      }
      print("Found Kibana Security Index: "+index)
      dta  = '{"doc": {"kibana.alert.workflow_status": "acknowledged"}}'
      posturl = ELASTIC_HOST+"/"+index+"/_update/"+id
      res = requests.post(posturl,data=dta, headers=headers, auth=(ELASTIC_USER, ELASTIC_PW), verify=False)
      res = res.json()
      if deep_get(res, '_shards.successful', False):
        print("Successfully acknowledged alert.\n")
        suc = True
      else:
        print("Couldn't acknowledge alert for index '"+index+"'\n")
      
    if not suc:
      print("\n[WARNING] Failed acknowledging alert for document", id)

  except:
    print("[WARNING] Non-fatal Error, trying to update SIEM alert to acknowledged.")
    print((traceback.format_exc()))


def send_to_otrs(title, prio, queue, body):
  client.session_create()
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
  if not same_ticket_found:
    same_ticket_id = DoneTitles.get(title, False)
    if same_ticket_id:
      print("Found ticket with same title done by alertelast itself.")
      same_ticket_found = True

  # Map Elastic Prio to OTRS Prio
  try:
    prio_map = {"low": "4 low", "medium" : "3 normal", "high" : "2 high", "critical" : "1 very-high"}
    otrs_prio = prio_map[prio]
  except Exception as e:
    print("[WARNING] Non-Fatal Error in send_to_otrs()-Determine Prio. 'prio': "+prio)
    print((traceback.format_exc()))

  article = Article({"Subject" : title, "Body" : body})
  if not same_ticket_found:
    new_ticket = Ticket.create_basic(Title=title, Queue=queue, Type="Alert", State=u"new", Priority=otrs_prio, CustomerUser="Kibana_SIEM")
    if not DRY_RUN:
      result = client.ticket_create(new_ticket, article, Queue=queue)
      print("Created new ticket.")
      ticket_id = result['TicketID']
      DoneTitles[title] = ticket_id

      #Fix prio
      ticket = client.ticket_get_by_id(ticket_id,articles=True)
      current_prio = ticket.field_get("Priority")
      Title = ticket.field_get("Title")
      if not DRY_RUN:
          result = client.ticket_update(ticket_id, Priority=otrs_prio)
      print("Updated ticket priority from [" +(current_prio)+ "] to -> [" +prio+ "] for: "+Title)

    else:
      print("Would create ticket now but this is a dry run...")

  else:
    if not DRY_RUN:
      print(client.ticket_update(same_ticket_id, article=article))
      client.ticket_update(same_ticket_id, StateType="new", State="new", Queue=queue)
      print("Updated ticket.")
    else:
      print("Would update ticket now but this is a dry run...")


def handle_alert(doc):
  is_suricata = False
  msg = ""
  prio = "medium"
  id = deep_get(doc, '_id')
  doc = deep_get(doc, '_source')
  print("Handling Alert with _id: "+id)
  logline+=("alert_id=",id)


  # Parse params
  title = doc['kibana.alert.rule.name']
  prio = doc['kibana.alert.severity']

  try: # Fix Suricata Severity
    prio_suricata = deep_get(doc, 'suricata.eve.alert.metadata.signature_severity')
    if prio_suricata == "Major":
      prio = "critical"
  except:
    pass

  #Check if Suricata Alert 
  src_port = deep_get(doc, 'suricata.eve.src_ip', default='')
  if src_port != '':
    is_suricata = True

  
  # Parse Title
  try:
    src = deep_get(doc, 'source.ip', default='')
    src = deep_get(host_map, src, default=src)
    src = deep_get(doc, 'host.hostname', default=src)
  except:
    if src == None:
      src = "<Parsing Error>"
    if isinstance(src, list):
      src = ''.join(src)
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

  if isinstance(dst, list): #or isinstance(dst, )
    dst = dst[0]

  if (((src or dst) == '') or ((src or dst) == None) or not re.search('[0-9a-zA-Z]', dst)):
    title = title + " | Host: "+src+dst
  else:
    title = title + " ["+src+" > "+dst+"]"


  if not is_suricata:
    msg =  "Parsed info should be below.\n\nRULE NAME: {}\n\nRULE QUERY: {}\n\nRULE DESCRIPTION: {}\n\n\nPROCESS: {}\n\nPARENT PROC: {}\n\nSource IP: {}\n\nDestination IP: {}:{}\n\nDestination Organization Name: {} \n\nDomain: {}".format(\
    doc['kibana.alert.rule.name'],doc["kibana.alert.rule.parameters"],doc['kibana.alert.rule.description'] ,deep_get(doc, "process"), deep_get(doc, "process.parent"), deep_get(doc, "source.ip"), deep_get(doc, "destination.ip"), deep_get(doc, "destination.port"), deep_get(doc, "destination.as.organization.name"), deep_get(doc, "dns.question.name"))
  else:
    msg = "Parsed info should be below.\n\nCATEGORY: {}\nRULE [SID) NAME: [{}] {}\n\n\nSOURCE IP: {} : {} ({})\nSource Organization Name: {}\n\nDESTINATION IP: {} : {} ({})\nDestination Organization Name: {}\n\n\nPAYLOAD:\n{}\n\nHTTP:\n{}\n\nVirusTotal Lookup:\nSRC: https://www.virustotal.com/gui/ip-address/{} \nDST: https://www.virustotal.com/gui/ip-address/{}\n\nAlert Info Search:\nET: https://doc.emergingthreats.net/bin/view/Main/WebSearch?search={} \nSnort: https://snort.org/rule_docs?utf8=✓&rules_query={} (maybe trunc. to 5 numbers)\nSnort RAW: https://github.com/codecat007/snort-rules/search?q=sid%3A{} \n\nDNS Query: {}\
      ".format(deep_get(doc, "suricata.eve.alert.category"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature"),deep_get(doc, "suricata.eve.src_ip"),deep_get(doc, "suricata.eve.src_port"),deep_get(doc, "source.geo.geo.country_iso_code"),deep_get(doc, "source.as.organization.name"),deep_get(doc, "suricata.eve.dest_ip") ,deep_get(doc, "suricata.eve.dest_port"), deep_get(doc, "destination.geo.geo.country_iso_code"),deep_get(doc, "destination.as.organization.name"), deep_get(doc, "suricata.eve.payload_printable"),deep_get(doc, "suricata.eve.http"),deep_get(doc, "suricata.eve.src_ip"),deep_get(doc, "suricata.eve.dest_ip"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature_id"),deep_get(doc, "suricata.eve.alert.signature_id"), deep_get(doc, "suricata.eve.dns.query.rrname"))
  
  #print(msg)
  print(title)
  send_to_otrs(title, prio, OTRS_QUEUE, msg)
  mark_acknowledged(id)




def query_open_rules():
  print("\n\n## Quering rules of ELastic SIEM...\n")
  logline = ""
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
  thits = len(result["hits"]["hits"])
  print ("\ntotal hits:", thits)
  all_hits = result['hits']['hits']

  # iterate the nested dictionaries inside the ["hits"]["hits"] list
  for num, doc in enumerate(all_hits):
      print ("DOC ID:", doc["_id"])
      logline+="doc_id=", doc["_id"]

      handle_alert(doc)
      # print a few spaces between each doc for readability
      print ("\n\n")
  print("Done Quering Elastic SIEM")

  logline += f" result=Alertelast routine was successfull, total_alert_hits={thits}, END"
  print("Info", logline)


      


query_open_rules()