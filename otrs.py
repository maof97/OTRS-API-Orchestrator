from typing import KeysView
from pyotrs import Client
from pyotrs.lib import Article, Ticket
import requests
import ipaddress
import pprint
from datetime import datetime
from datetime import timedelta
import re

def up_prio(TicketID):
    ticket = client.ticket_get_by_id(ticket_id)
    CurrentPrio = ticket.field_get("Priority")
    print(CurrentPrio)

def hit_counter(input): 
    bad_hits = input['malicious']+input['suspicious']
    good_hits = input['harmless']
    return str(bad_hits)+"/"+str(good_hits), bad_hits

def checkIPinVT(IP):
    try:
        ip = ipaddress.ip_address(IP)
        if ipaddress.ip_address(IP).is_private:
            print(IP+" is not a public IP.")
            return "Fail"
    except:
        print(IP+" is not a valid IP. Cant check them in VT")
        return "Fail"

    url = 'https://www.virustotal.com/api/v3/ip_addresses/'+IP
    header = {'x-apikey' : '3e94557f84dc6b8b14f4e95118aeddb81473926c3b7773d230a3cc9dd0c176a7'}

    response = requests.get(url, headers=header, verify=False)
    res = response.json()
    #Check for hits in result
    result = (res['data']['attributes']['last_analysis_stats'])
    score = hit_counter(result)
    msg = ("## VirusTotal Scan of IP "+IP+" ##\n\n\nIP has a result of "+ score[0])
    if score[1]>0:
        msg += "\n\n"
        engine_res = res['data']['attributes']['last_analysis_results']
        for key in engine_res:
            if(engine_res[key]['category'] == "malicious"):
                msg+=pprint.pformat(engine_res[key])+"\n\n"
        for key in engine_res:
            if(engine_res[key]['category'] == "suspicious"):
                msg+=pprint.pformat(engine_res[key])+"\n\n"
    #Get the Passive DNS resolutions
    url_res = 'https://www.virustotal.com/api/v3/ip_addresses/'+IP+'/resolutions'
    response_res = requests.get(url_res, headers=header, verify=False)
    response_res = response_res.json()
    msg+="\n\n\nPassive DNS Reolutions:\n\n"
    for i in range(0,len(response_res['data'])):
        msg+= response_res['data'][i]['attributes']['host_name']+"\n"
        msg+= hit_counter(response_res['data'][i]['attributes']['host_name_last_analysis_stats'])[0]+"\n"
    print("### (VT) Prepared following note to OTRS: ### \n\n\n"+msg)
    return msg, score[1]

client = Client("http://10.24.1.2/otrs/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST","SIEMUser","9f5d8ccf63f8a3e9fb874d32ac5d6a4ca9cc88574b2fbfd3f4bca9a8bbf636cd")
client.session_create()
last_day = datetime.utcnow() - timedelta(days=1)
new_tickets = client.ticket_search(TicketCreateTimeNewerDate=last_day, StateType=['new'], QueueIDs=[7])
for ticket_id in new_tickets:
    ticket = client.ticket_get_by_id(ticket_id,articles=True)
    ticketDict = ticket.to_dct()
    Title = ticket.field_get("Title")
    print(Title)
    ArticleField = ticket.field_get("Article")
    if("Suricata" in Title):
        dst_ip = re.search('[\n\r].*SOURCE IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][0]['Body'])[1]
        msg_src = checkIPinVT(dst_ip)[0]
        if msg_src != "Fail": #Check if this was a valid IP
            msg_src+="\n\n\n"
        else:
            msg_src=""

        dst_ip = re.search('[\n\r].*DESTINATION IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][0]['Body'])[1]       
        msg_dst = checkIPinVT(dst_ip)[0]
        if msg_dst == "Fail" and msg_src == "Fail": #Check if this was a valid IP in both cases
            continue
        if msg_dst == "Fail":
            msg_dst == ""

        VT_Note = Article({"Subject" : "VirusTotal Scan Result", "Body" : msg_src+msg_dst})
        #result = client.ticket_update(ticket_id,VT_Note)
        pprint.pprint(VT_Note)
        
        #TODO make score dependent prio up/down






