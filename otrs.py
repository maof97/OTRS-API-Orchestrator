from pyotrs import Client
client = Client("http://10.24.1.2/otrs/nph-genericinterface.pl/Webservice/pyOTRS_","SIEMUser","9f5d8ccf63f8a3e9fb874d32ac5d6a4ca9cc88574b2fbfd3f4bca9a8bbf636cd")
client.session_create()
ticket1 = client.ticket_get_by_id(6982,articles=True)
print(ticket1.field_get("Title"))
#print(ticket1.to_dct())
print(ticket1.articles[0])
#client.ticket_update(6982,)