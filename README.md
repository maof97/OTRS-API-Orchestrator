# OTRS-API-Orchestrator
## About:
This is just my own API "Orchestrator" for OTRS to improve my SIEM Ticket-system.
The main feature at the moment is the auto VirusTotal scan of IPs in tickets.

I recently added "Alertelast" as part of the project, which is similar, to _yelp/Elastalert_, but only to alert SIEM rule detections in Elastic SIEM.
It fethces alerts from Elastic SIEM with the "open" state, every time the script runs and changes the affected alert state in Kibana from "open" to "acknowledged" and therefore completely mitigating the risk of duplicate alerts. Then the alert will be parsed for the Orchestrator _otrs.py_ to be used in OTRS and optionally also send via telegram bot API.
