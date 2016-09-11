from datetime import datetime, date
from pyinvoice.models import InvoiceInfo, ServiceProviderInfo, ClientInfo, Item, Transaction
from pyinvoice.templates import SimpleInvoice

def createInvoice(excelContent):
    invoiceDict={}
    for line in excelContent[1:]:
        doc = SimpleInvoice('invoice'+str(line[0])+'.pdf')
        doc.invoice_info = InvoiceInfo(line[0], datetime.now(), line[6])  # Invoice info - id, invoice date, invoice due date
        clientEmail = line[2]
        doc.client_info = ClientInfo(email=clientEmail)
        doc.add_item(Item(line[4],line[5],line[7],'0'))
        invoiceDict['invoice'+str(line[0])+'.pdf']=clientEmail
        doc.finish()
    return invoiceDict