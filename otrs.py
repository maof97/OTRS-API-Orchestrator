CLIENT_DOMAIN = "http://otrs.cloud.swiftbird.de:8077"
CLIENT_URL = CLIENT_DOMAIN+"/otrs/nph-genericinterface.pl/Webservice/GenericTicketConnectorREST"
VT_UPPRIO_THRESHOLD = 1  # Needed VT hit-Counts for increased priority
VT_DEPRIO_THRESHOLD = 1  # Needed VT engine-Counts (with 0 hits) for de-priorization
TELEGRAM_ALERT_PRIO = 4  # On which (exact or lower) priority level to send a Telegram Alert if a new ticket was processed. Default: 2

# You need to export the following env. vars like this:
# export OTRS_USER_PW="myotrsuserpw"
# export VT_API_KEY='myvtkey'

# For script to actually update tickets in OTRS also set:
# export OTRS_ORCH_PROD='True'

# For Telegram Alerts:
# export TELEGRAM_BOT_KEY="botXXX"
# export TELEGRAM_BOT_CHATID="-123456"

FP_Domains = (
    "api.telegram.org"
)

FP_IPs = (
    "1.1.1.1"
)

FP_Org_Names = (
    "APPLE"
    "Telegram Messenger Inc"
)

Def_P4_Tickets = (
"SURICATA HTTP",
"SURICATA TLS", 
"INDICATOR-COMPROMISE png file attachment without matching file magic", 
"INDICATOR-SHELLCODE", 
"Test Rule", 
"ET DNS Query for .to TLD", 
"ET DNS Query for .cloud TLD",
"alerts on Ipad"
)
DoneTickets = [1]
DoneIPArticles = [1]
DoneDNSArticles = [1]


# Start of Script #
from ssl import ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE, ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY
from termios import TIOCPKT_FLUSHWRITE
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
import validators
import base64
from distutils import util

from alertelast import query_open_rules

VT_API_KEY = os.environ['VT_API_KEY']
OTRS_USER_PW = os.environ['OTRS_USER_PW']
TELEGRAM_BOT_KEY = os.environ['TELEGRAM_BOT_KEY']
TELEGRAM_BOT_CHATID = os.environ['TELEGRAM_BOT_CHATID']
try:
    DRY_RUN = not bool(util.strtobool(os.environ['OTRS_ORCH_PROD']))
except:
    DRY_RUN = True


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


def hit_counter(input): 
    bad_hits = input['malicious']+input['suspicious']
    good_hits = input['harmless']
    return str(bad_hits)+"/"+str(good_hits), bad_hits, good_hits



def HandleFalsePositives(client, ticket, type, input):
    
    # Handle FP Domains
    if(type == ("Domain" or "IP")):
        try:
            if (input in FP_Domains) or (input in FP_IPs):
                Title = ticket.field_get("Title")
                ticket_id = ticket.field_get("TicketID")
                current_prio = int(ticket.field_get("Priority")[0])

                print("Strongly decreasing ticket priority (down 2) because of known false-positive domain/ip: "+input)

                new_prio = (current_prio +2)
                if new_prio == 5:
                    Note = Article({"Subject" : "Closed Ticket", "Body" : "Because of known false-positive domain/ip for the given connection and the ticket being priority 3 or 4, the ticket was closed automatically."})
                    result = "(dry run)"
                    if not DRY_RUN:
                        result = client.ticket_update(ticket_id, Note) 
                        result = client.ticket_update(ticket_id, StateType="closed", State="auto-closed (API)")
                    print("Closed ticket: "+Title)    
                    return "closed!"      
                else:
                    SetTicketPrio(client, ticket, new_prio)
                    Note = Article({"Subject" : "Decreased Priority to "+str(new_prio), "Body" : "Because of known false-positive domain/ip '"+input+"' for the given connection, the priority was drastically was decreased (minus 2)."})
                    result = "(dry run)"
                    if not DRY_RUN:
                        result = client.ticket_update(ticket_id, Note)
                return
        except Exception as e:
            print("[WARNING] Non-Fatal Error in HandleFalsePositives(DomainIP)")
            print((traceback.format_exc()))
            pass   


    if(type == "Org"):
        try:
            Org_Name = re.search('[\n\r].*Destination Organisation Name:\s([^\n:]*)', input['Ticket']['Article'][0]['Body'],re.IGNORECASE)[1]
            print("Found Ticket's Organisation name: "+Org_Name)

            if FP_Org_Names in Org_Name:
                Title = ticket.field_get("Title")
                ticket_id = ticket.field_get("TicketID")
                current_prio = int(ticket.field_get("Priority")[0])

                print("Closed ticket because of known false-positive ORG-NAME: "+Org_Name)            
                Note = Article({"Subject" : "Closed Ticket", "Body" : "Because of known false-positive organisation name for the given connection the ticket was closed automatically."})
                result = "(dry run)"
                if not DRY_RUN:
                    result = client.ticket_update(ticket_id, Note) 
                    result = client.ticket_update(ticket_id, StateType="closed", State="auto-closed (API)")
                print("Closed ticket: "+Title)    
                return "closed!"

        except Exception as e:
            print("[WARNING] Non-Fatal Error in HandleFalsePositives(Org)")
            print((traceback.format_exc()))
            pass       


def checkVT(type, input):
    score = ("",0,0)
    msg = ""
    header = {'x-apikey' : VT_API_KEY}
    
    if type == "IP":
        print("Scanning IP '"+input+"'...")

        try:
            ip = ipaddress.ip_address(input)
            if ipaddress.ip_address(input).is_private:
                print("Skipping IP-Check for "+input+" (private IP)")
                return msg, score, True
        except:
            print(input+" is not a valid IP. Cant check them in VT")
            return msg, score, True

        url = 'https://www.virustotal.com/api/v3/ip_addresses/'+input

        response = requests.get(url, headers=header, verify=True)

    elif type == "URL":
        print("Scanning URL '"+input+"'...")

        if not validators.url(input):
            print("[WARNING] URL to be scanned by VT seems to be invalid: "+input)
            return msg, score, True

        url_id = (input.encode()).decode().strip("=")

        vt_url = "https://www.virustotal.com/api/v3/urls"

        print("URL ID: " +input)

        payload = "url="+url_id

        headers = {
            "Accept": "application/json",
            "x-apikey": VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response_url_req = requests.request("POST", vt_url, data=payload, headers=headers)
            response_url_req_json = response_url_req.json()

            id_url_analysis = response_url_req_json["data"]["id"]
            print("Got URL Scan response. ID: "+id_url_analysis)

            url = 'https://www.virustotal.com/api/v3/analyses/'+id_url_analysis
            response = requests.get(url, headers=header, verify=True)


        except Exception as e:
            print("[WARNING] Non-Fatal Error in VT Scan URL result fetching.")
            print((traceback.format_exc()))
            return msg, score, True



    elif type == "Domain":
        print("Scanning Domain '"+input+"'...")

        url = 'https://www.virustotal.com/api/v3/domains/'+input
        response = requests.get(url, headers=header, verify=True)


    res = response.json()

    # Catch if API quota was exceeded: 
    try:
        if res['error']['message'] == "Quota exceeded":
            print("[WARNING] Exceeded quota for VirusTotal API. Got no result to work with.")
            return msg, score, True
    except KeyError:
        pass
    
    try:
        # Check for hits in result
        if type != "URL":
            result = (res['data']['attributes']['last_analysis_stats'])
        else:
            result = (res['data']['attributes']['stats'])       
    except Exception as e:
        print("[WARNING] Non-Fatal Error in VT Scan result fetching.")
        print((traceback.format_exc()))
        return msg, score, True

    score = hit_counter(result)
    msg = ("## VirusTotal Scan of Input "+input+" ##\n\n\nInput has a result of "+ score[0])
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
    if type == "IP":
        url_res = 'https://www.virustotal.com/api/v3/ip_addresses/'+input+'/resolutions'
        response_res = requests.get(url_res, headers=header, verify=False)
        response_res = response_res.json()
        msg+="\n\n\nPassive DNS Reolutions:\n\n"

        for i in range(0,len(response_res['data'])):
            msg+= response_res['data'][i]['attributes']['host_name']+"\n"
            msg+= hit_counter(response_res['data'][i]['attributes']['host_name_last_analysis_stats'])[0]+"\n"

    print("### (VT) Prepared following note to OTRS: ### \n\n\n"+msg)
    return msg, score, False


def AddNote_VT_Scan_IP(client, ticket):

        ticketDict = ticket.to_dct()
        Title = ticket.field_get("Title")
        print("AddNote_VT_Scan_IP for: "+Title+"\n")
        ticket_id = ticket.field_get("TicketID")
        ArticleArray = ticketDict['Ticket']['Article']
        score_src = [0, 0, 0]
        score_dst = [0, 0, 0]
        DoneIPs = []
        DoneIPs.clear()
        final_score = [0, 0]
        err_src = True
        err_dst = True

        print("Found "+str(len(ArticleArray))+" Articles in the ticket.")


        for i in range(len(ArticleArray)):

            # Skip already done Articles...
            ArticleID = ArticleArray[i]['ArticleID']

            if ArticleID in DoneIPArticles:
                print("Article#"+str(ArticleID)+" already done or other API response. Skipping...")
                continue
            else:
                print("Handling Article#"+str(ArticleID)+":\n")


            try:

                src_ip = re.search('[\n\r].*SOURCE IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][i]['Body'],re.IGNORECASE)[1]
                print("Parsed Source IP: "+src_ip)
                msg_src, score_src, err_src = checkVT("IP", src_ip)

            except TypeError: # If no IP was found...
                pass

            except Exception as e:
                print("[WARNING] Non-Fatal Error in AddNote_VT_Scan_IP > Regex Src_IP/ Return MSG for ArticleID: "+str(ArticleID))
                print((traceback.format_exc()))


            try:
                dst_ip = re.search('[\n\r].*DESTINATION IP:\s([^\s:]*)', ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)[1] 
                print("Parsed Destination IP: "+dst_ip)
                msg_dst, score_dst, err_dst = checkVT("IP", dst_ip)

            except TypeError:
                pass

            except Exception as e:
                print("[WARNING] Non-Fatal Error in AddNote_VT_Scan_IP > Regex Src_IP/ Return MSG for ArticleID: "+str(ArticleID))
                print((traceback.format_exc()))


            # Craft the Note to send to ticket
            try:
                all_hits = str(score_src[1]+score_dst[1])
                all_eng = str(score_src[2]+score_dst[2])
                end_score = all_hits+"/"+all_eng

                if(not err_src):
                    VT_Note = Article({"Subject" : "VirusTotal Scan Result for IP "+src_ip+" -> ("+end_score+")", "Body" : msg_src})
                    DoneIPs.append(src_ip)
                    pprint.pprint(VT_Note)

                    # Update Ticket
                    if not DRY_RUN:
                        result = client.ticket_update(ticket_id, VT_Note)
                    else:
                        print("(Would update ticket now, but this is a dry run...)")

                elif(not err_dst):
                    VT_Note = Article({"Subject" : "VirusTotal Scan Result for IP "+dst_ip+" -> ("+end_score+")", "Body" : msg_dst})
                    DoneIPs.append(dst_ip)
                    pprint.pprint(VT_Note)

                    # Update Ticket
                    if not DRY_RUN:
                        result = client.ticket_update(ticket_id, VT_Note)
                    else:
                        print("(Would update ticket now, but this is a dry run...)")

                else:
                    print("Skipped Article because of errors in both src_ip as well as dst_ip.")

                # Reset values
                src_ip = ""
                dst_ip = ""
                msg_src = ""
                msg_dst = ""

                DoneIPArticles.append(ArticleID)

            except Exception as e:
                print("[WARNING] Non-Fatal Error in AddNote_VT_Scan_IP > Add Note / Note Update for ArticleID: "+str(ArticleID))
                print((traceback.format_exc()))
                pass
            
            #Count final score
            final_score[0] += (score_src[1]+score_dst[1])
            final_score[1] += (score_src[2]+score_dst[2])
            print("Final score: "+str(final_score[0])+"/"+str(final_score[1]))


        ## Ticket done ##

        #Update state?
        updated_state = UpdatePrio(client, ticket, final_score[0], final_score[1])

        if updated_state != "closed!":
            if not DRY_RUN:
                print("Result of final ticket update: "+str(client.ticket_update(ticket_id, StateType="new", State="new")))
            else:
                print("Result of final ticket update: (dry run)") 


def AddNote_VT_Scan_Domain(client, ticket):

        ticketDict = ticket.to_dct()
        Title = ticket.field_get("Title")
        print("AddNote_VT_Scan_Domain for: "+Title+"\n")
        ticket_id = ticket.field_get("TicketID")
        ArticleArray = ticketDict['Ticket']['Article']
        score_src = [0, 0, 0]
        score_dst = [0, 0, 0]
        DoneDomains = []
        final_score = [0, 0]
        err_vt = True
        domain = None
        url = None
        foundURL = False

        print("Found "+str(len(ArticleArray))+" Articles in the ticket.")


        for i in range(len(ArticleArray)):

            # Skip already done Articles...
            ArticleID = ArticleArray[i]['ArticleID']

            if ArticleID in DoneDNSArticles:
                print("Article#"+str(ArticleID)+" already done or other API response (DNS). Skipping...")
                continue
            else:
                print("Handling Article#"+str(ArticleID)+":\n")

            try:
                path = re.search("'url':\s'([^']*)", ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                if path != None: # Url found - get hostname
                    domain = re.search("'hostname':\s'([^']*)", ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                    foundURL = True
                else:
                    domain = re.search('[\n\r].*Domain:\s([^\s:]*)', ticketDict['Ticket']['Article'][i]['Body'],re.IGNORECASE)
                    if domain == None or domain[1] == "<MISSING":
                        domain = re.search("'sni':\s'([^']*)", ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                        if domain == None:
                            domain = re.search("'hostname':\s'([^']*)", ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                            if domain == None:
                                domain = re.search('Host: ([^\n]*)', ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                                if domain == None:
                                    payload = re.search('[\n\r].*PAYLOAD:\n([^\n]*)', ticketDict['Ticket']['Article'][i]['Body'], re.IGNORECASE)
                                    if payload != None:
                                        domain = re.search('\.\.\.([a-z0-9\-].*)\.\.A', payload[1], re.IGNORECASE) 

            except Exception as e:
                print("[WARNING] Non-Fatal Error in AddNote_VT_Scan_Domain > Regex Domain/ Return MSG for ArticleID: "+str(ArticleID))
                print((traceback.format_exc()))


            if foundURL:
                if path[1].startswith("/"):
                    url_ = domain[1] + path[1]
                else:
                    url_ = path[1]
                print("Found URL: "+url_)
                msg_src, score_src, err_vt = checkVT("URL", "https://"+url_)

            if domain != None and domain[1] != "<MISSING":
                domain = domain[1]
                print("Found Domain: "+domain)
                msg_src, score_src, err_vt = checkVT("Domain", domain)
            else:
                print("No Domain/URL in Article.")
                continue



            # Craft the Note to send to ticket
            try:
                all_hits = str(score_src[1]+score_dst[1])
                all_eng = str(score_src[2]+score_dst[2])
                end_score = all_hits+"/"+all_eng

                if(not err_vt):
                    VT_Note = Article({"Subject" : "VirusTotal DNS Scan Result for '"+domain+"' ("+end_score+")", "Body" : msg_src})
                    DoneDNSArticles.append(ArticleID)
                    DoneDomains.append(domain)

                    pprint.pprint(VT_Note)

                    # Update Ticket
                    if not DRY_RUN:
                        result = client.ticket_update(ticket_id, VT_Note)
                    else:
                        print("(Would update ticket now, but this is a dry run...)")

                    # Is this a FP?
                    HandleFalsePositives(client, ticket, "Domain", domain)

                else:
                    print("Skipped Article because Domain could not be found/searched.")

                # Reset values
                domain = None
                path = None
                foundURL = False

                DoneIPArticles.append(ArticleID)

            except Exception as e:
                print("[WARNING] Non-Fatal Error in AddNote_VT_Domain > Add Note / Note Update for ArticleID: "+str(ArticleID))
                print((traceback.format_exc()))
                pass
            
            #Count final score
            final_score[0] += (score_src[1]+score_dst[1])
            final_score[1] += (score_src[2]+score_dst[2])
            print("Final score: "+str(final_score[0])+"/"+str(final_score[1]))


        ## Ticket done ##

        #Update state?
        updated_state = UpdatePrio(client, ticket, final_score[0], final_score[1])

        if updated_state != "closed!":
            if not DRY_RUN:
                print("Result of final ticket update: "+str(client.ticket_update(ticket_id, StateType="new", State="new")))
            else:
                print("Result of final ticket update: (dry run)") 



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
    if not DRY_RUN:
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
    if True:
        #Increase Prio if needed
        if hits >= VT_UPPRIO_THRESHOLD: #>=1
            Title = ticket.field_get("Title")
            ticket_id = ticket.field_get("TicketID")
            current_prio = int(ticket.field_get("Priority")[0])

            print("Increasing ticket priority because of VT hits for: "+Title)

            new_prio = (current_prio -1)
            SetTicketPrio(client, ticket, new_prio)
            Note = Article({"Subject" : "Increased Priority to "+str(new_prio), "Body" : "Because of too many VT hits for the given connection, the priority was increased."})
            result = "(dry run)"
            if not DRY_RUN:
                result = client.ticket_update(ticket_id, Note)
                Alert_Ticket(client, ticket, 1)
            return

        if engines >= VT_DEPRIO_THRESHOLD and hits == 0:
            Title = ticket.field_get("Title")
            ticket_id = ticket.field_get("TicketID")
            current_prio = int(ticket.field_get("Priority")[0])

            print("Decreasing ticket priority because of unsuspicious connection for: "+Title)

            new_prio = (current_prio +1)
            if new_prio == 5:
                Note = Article({"Subject" : "Closed Ticket", "Body" : "Because of 0 VT hits for the given connection and the ticket already being priority 4 (low), the ticket was closed automatically."})
                result = "(dry run)"
                if not DRY_RUN:
                    result = client.ticket_update(ticket_id, Note) 
                    result = client.ticket_update(ticket_id, StateType="closed", State="auto-closed (API)")
                print("Closed ticket: "+Title)    
                return "closed!"      
            else:
                SetTicketPrio(client, ticket, new_prio)
                Note = Article({"Subject" : "Decreased Priority to "+str(new_prio), "Body" : "Because of 0 VT hits for the given connection, the priority was decreased."})
                result = "(dry run)"
                if not DRY_RUN:
                    result = client.ticket_update(ticket_id, Note)



def Alert_Ticket(client, ticket, prio_change):
    try:
        Title = ticket.field_get("Title")
        ticket_id = ticket.field_get("TicketID")
        Priority = int(ticket.field_get("Priority")[0])
        print("Alerting ticket #"+str(ticket_id)+" "+Title)
        req_path = "/"+TELEGRAM_BOT_KEY+"/sendMessage?chat_id="+TELEGRAM_BOT_CHATID+"&parse_mode=markdown&text="
        #AT_PERSON = "@Martin "

        if(Priority <= TELEGRAM_ALERT_PRIO):
            if prio_change == 0:
                msg = " %2A%2ANew Ticket: _"+Title+"_%2A%2A%0A%0ACurrent Prio: "+str(Priority)+ "%0A%0ALink: "+CLIENT_DOMAIN+"/otrs/index.pl?Action=AgentTicketZoom;TicketID="+str(ticket_id)
            else:
                msg = " %2A%2AWARNING INCREASED TICKET PRIORITY%0A _"+Title+"_%2A%2A%0A%0A"

            if not DRY_RUN:
                res = requests.post("https://api.telegram.org"+req_path+msg)
                if(res != "<Response [200]>"):
                    print("[WARNING] Could not send Telegram Alert in Alert_Ticket() -> Reponse not OK (200)")
                    print(res.json())
            return
    except Exception as e:
        print("[WARNING] Non-Fatal Error in Alert_Ticket()")
        print((traceback.format_exc()))
        return   

        

        


def every_minute():

    print("Executing scheudeled task (1 min):\n\n")
    try:
        print("Executing alertelast.py...:\n")
        query_open_rules()
    except Exception as e:
        print("[ERROR] ALERTELAST FAILED:\n")
        print((traceback.format_exc()))

    try:
        client = Client(CLIENT_URL,"SIEMUser",OTRS_USER_PW)
        client.session_create()
        last_day = datetime.utcnow() - timedelta(days=1)
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
            try:
                if TicketNumber in DoneTickets:
                    skipTicket = True

                for i in range(len(ArticleArray)):
                    # If an Article from API was after an Article -> mark the article as done and skip
                    if "API" in ArticleArray[i]["From"] and (" IP " in ArticleArray[i]["Subject"]):
                        for j in range(len(ArticleArray)):
                            DoneIPArticles.append(ArticleArray[i - j]["ArticleID"])
                        pass

                for i in range(len(ArticleArray)):
                    # If an Article from API was after an Article -> mark the article as done and skip
                    if "API" in ArticleArray[i]["From"] and ("VirusTotal DNS Scan Result for" in ArticleArray[i]["Subject"]):
                        for j in range(len(ArticleArray)):
                            DoneDNSArticles.append(ArticleArray[i - j]["ArticleID"])
                            pass  


                if skipTicket:
                    print("Ticket#"+TicketNumber+" already done. Skipping...")
                    continue
            except:
                print("[WARNING] There was an Error in Skipping already done tickets (every_minute).\n")

            #Found new ticket:    
            print("\n\n---- Handling new ticket:----\n#"+ticket_id+" "+Title+"\n\n")  

            print("Correcting default priority if needed...")
            CorrectDefaultPrio(client, ticket)
            print("\nHandling Organization Name False positives...")
            HandleFalsePositives(client, ticket, "Org", ticketDict)

            print("\nScanning Ticket IP Addresses in VirusTotal...")
            AddNote_VT_Scan_IP(client, ticket)
            
            print("\nScanning Ticket Domain Names in VirusTotal...")
            AddNote_VT_Scan_Domain(client, ticket)

            ticket = client.ticket_get_by_id(ticket_id,articles=True)
            if ticket.field_get("State") == "new":
                Alert_Ticket(client, ticket, 0)
            else:
                print("\nSkipped alerting of already closed ticket.")
    

            DoneTickets.append(TicketNumber)

        print("\n# Done Tickets this round: #\n\n")
        print(DoneTickets)
        print("\n\nSheudled task (1min) done.\nNext start in 60 seconds...")
        return  

    except Exception as e:
        print("[WARNING] Non-Fatal Error in every_minute()")
        print((traceback.format_exc()))
        pass          

def main():
    print("Started OTRS-API-Orchestrator")
    if DRY_RUN:
        print("\nWARNING Dry Run -- No ticket will be updated!\n\n")

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