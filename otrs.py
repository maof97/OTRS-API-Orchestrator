VT_UPPRIO_THRESHOLD = 1  # Needed VT hit-Counts for increased priority
VT_DEPRIO_THRESHOLD = 1  # Needed VT engine-Counts (with 0 hits) for de-priorization
Def_P4_Tickets = (
"SURICATA HTTP", 
"INDICATOR-COMPROMISE png file attachment without matching file magic", 
"INDICATOR-SHELLCODE", 
"Test Rule", 
"ET DNS Query for .to TLD", 
"ET DNS Query for .cloud TLD",
"alerts on Ipad"
)
DoneTickets = [1]

from typing import KeysView
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
import os

def every(delay, task):
  next_time = time.time() + delay
  while True:
    time.sleep(max(0, next_time - time.time()))
    try:
      task()
    except KeyboardInterrupt:
        print("Stopping service...")
        print("Stopped.")
        sys.exit()
    except Exception:
      traceback.print_exc()
      # in production code you might want to have this instead of course:
      # logger.exception("Problem while executing repetitive task.")
    # skip tasks if we are behind schedule:
    next_time += (time.time() - next_time) // delay * delay + delay
class GracefulInterruptHandler(object):

    def __init__(self, sig=signal.SIGINT):
        self.sig = sig

    def __enter__(self):

        self.interrupted = False
        self.released = False

        self.original_handler = signal.getsignal(self.sig)

        def handler(signum, frame):
            self.release()
            self.interrupted = True

        signal.signal(self.sig, handler)

        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):

        if self.released:
            return False

        signal.signal(self.sig, self.original_handler)

        self.released = True

        return True

def up_prio(TicketID):
    ticket = client.ticket_get_by_id(ticket_id)
    CurrentPrio = ticket.field_get("Priority")
    print(CurrentPrio)

def hit_counter(input): 
    bad_hits = input['malicious']+input['suspicious']
    good_hits = input['harmless']
    return str(bad_hits)+"/"+str(good_hits), bad_hits, good_hits

def checkIPinVT(IP):
    score = ("",0,0)
    try:
        ip = ipaddress.ip_address(IP)
        if ipaddress.ip_address(IP).is_private:
            print("Skipping IP-Check for "+IP+" (private IP)")
            return "Fail", score
    except:
        print(IP+" is not a valid IP. Cant check them in VT")
        return "Fail", score

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
    return msg, score

def AddNote_VT_Scan_IP(client, ticket):

        ticketDict = ticket.to_dct()
        Title = ticket.field_get("Title")
        print("AddNote_VT_Scan_IP for: "+Title+"\n")
        ticket_id = ticket.field_get("TicketID")
        msg_src = "Failed scan."
        msg_dst = "Failed scan."

        try:
            src_ip = re.search('[\n\r].*SOURCE IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][0]['Body'])[1]
            msg_src, score_src = checkIPinVT(src_ip)
        except:
            dst_ip = ""  


        if msg_src != "Fail": #Check if this was a valid IP
            msg_src+="\n\n\n"
        else:
            msg_src=""

        try:
            dst_ip = re.search('[\n\r].*DESTINATION IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][0]['Body'])[1] 
            msg_dst, score_dst = checkIPinVT(dst_ip)
        except:
            dst_ip = "" 
             

        if msg_dst == "Fail" and msg_src == "Fail": #Check if this was a valid IP in both cases
            return 0, 0, 0
        if msg_dst in ("Failed scan.", "Fail") and msg_src in ("Failed scan.", "Fail"):
            return 0, 0, 0
        if msg_dst == "Fail":
            msg_dst == ""
        try:
            all_hits = str(score_src[1]+score_dst[1])
            all_eng = str(score_src[2]+score_dst[2])
            end_score = all_hits+"/"+all_eng
            VT_Note = Article({"Subject" : "VirusTotal Scan Result "+end_score, "Body" : msg_src+msg_dst})
            result = "testing mode"
            result = client.ticket_update(ticket_id, VT_Note)
            pprint.pprint(VT_Note)

        except:
            return 0, 0, 0
        return result, (score_src[1]+score_dst[1]), (score_src[2]+score_dst[2])



def SetTicketPrio(client, ticket, prio):
    PrioStrings = []
    PrioStrings.append("0 emergency")
    PrioStrings.append("1 very-high")
    PrioStrings.append("2 high")
    PrioStrings.append("3 normal")
    PrioStrings.append("4 low")
    prio = PrioStrings[prio]

    current_prio = ticket.field_get("Priority")
    ticket_id = ticket.field_get("TicketID")
    Title = ticket.field_get("Title")
    result = client.ticket_update(ticket_id, Priority=prio)
    print("Updated ticket priority from [" +(current_prio)+ "] to -> [" +prio+ "] for: "+Title)



def CorrectDefaultPrio(client, ticket):
    Title = ticket.field_get("Title")
    ticket_id = ticket.field_get("TicketID")
    for Def_P4_Ticket in Def_P4_Tickets:
        if Def_P4_Ticket in Title:
            print("Changing ticket priority to default (low) value for: "+Title)
            SetTicketPrio(client, ticket, 4)
            return



def UpdatePrio(client, ticket, hits, engines):
    Title = ticket.field_get("Title")
    # Suricata
    if "Suricata" in Title:
        #Increase Prio if needed
        if hits >= VT_UPPRIO_THRESHOLD: #>=1
            Title = ticket.field_get("Title")
            ticket_id = ticket.field_get("TicketID")
            current_prio = int(ticket.field_get("Priority")[0])

            print("Increasing ticket priority because of VT hits for: "+Title)

            new_prio = (current_prio -1)
            SetTicketPrio(client, ticket, new_prio)
            Note = Article({"Subject" : "Increased Priority to "+str(new_prio), "Body" : "Because of too many VT hits for the given connection, the priority was increased."})
            result = "testing mode"
            result = client.ticket_update(ticket_id, Note)
            return

        if engines >= VT_DEPRIO_THRESHOLD and hits == 0:
            Title = ticket.field_get("Title")
            ticket_id = ticket.field_get("TicketID")
            current_prio = int(ticket.field_get("Priority")[0])

            print("Decreasing ticket priority because of unsuspicious connection for: "+Title)

            new_prio = (current_prio +1)
            if new_prio == 5:
                Note = Article({"Subject" : "Closed Ticket", "Body" : "Because of 0 VT hits for the given connection and the ticket already being priority 4 (low), the ticket was closed automatically."})
                result = "testing mode"
                result = client.ticket_update(ticket_id, Note) 

                result = client.ticket_update(ticket_id, StateType="closed", State="auto-closed (API)")
                print("Closed ticket: "+Title)    
                return "closed!"      
            else:
                SetTicketPrio(client, ticket, new_prio)
                Note = Article({"Subject" : "Decreased Priority to "+str(new_prio), "Body" : "Because of 0 VT hits for the given connection, the priority was decreased."})
                result = "testing mode"
                result = client.ticket_update(ticket_id, Note)
            return

        

def every_minute():
        print("Executing scheudeled task (1 min):\n\n")
        client = Client("http://10.24.1.2/otrs/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST","SIEMUser","9f5d8ccf63f8a3e9fb874d32ac5d6a4ca9cc88574b2fbfd3f4bca9a8bbf636cd")
        client.session_create()
        last_day = datetime.utcnow() - timedelta(days=10)
        new_tickets = client.ticket_search(TicketCreateTimeNewerDate=last_day, StateType=['new'])

        for ticket_id in new_tickets:
    
            ticket = client.ticket_get_by_id(ticket_id,articles=True)
            TicketNumber = ticket.field_get("TicketNumber")
            Title = ticket.field_get("Title")
            ticketDict = ticket.to_dct()
            ArticleArray = ticketDict['Ticket']['Article']
            skipTicket = False
            updated_state = ""

            # Skip already done tickets
            if TicketNumber in DoneTickets:
                skipTicket = True
            for i in range(len(ArticleArray)):
                if "API" in ArticleArray[i]["From"]:
                    skipTicket = True    
                    pass    
            if skipTicket:
                print("Ticket#"+TicketNumber+" already done. Skipping...")
                continue

            #Found new ticket:    
            print("\n--##  Got new ticket to update: "+Title+"  ##--")    

            CorrectDefaultPrio(client, ticket)

            result, hits_vt, engines_vt = AddNote_VT_Scan_IP(client, ticket)
            if result != 0:
                updated_state = UpdatePrio(client, ticket, hits_vt, engines_vt)
            
            if updated_state != "closed!":
                print("Result of final ticket update: "+str(client.ticket_update(ticket_id, StateType="new", State="new")))
            DoneTickets.append(TicketNumber)

        print("\n\nSheudled task (1min) done.\nNext start in 60 seconds...")
        return            

def main():
    print("Started OTRS-API-Orchestrator")
    try:
        every_minute()
        every(60, every_minute)
    except KeyboardInterrupt:
        print('\n\nStopped Program!\n')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)


if __name__ == "__main__":
    main()