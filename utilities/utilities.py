from email import message_from_file
import whois
import re
from datetime import datetime, timezone
import json
import os
import mailparser


def extractFilenamesFromDirectory(email_directory):
    file_path=[]
    for filename in os.listdir(email_directory):
        if filename.endswith('.eml'):
            file_path.append(os.path.join(email_directory, filename))
    
    return file_path


def findDomainDetails(domain):
    try:
        domain_info = whois.whois(domain)
        print("in find domain details domain name:",domain_info["domain_name"])
        return domain_info
    except Exception as e:
            return None
    

def extractDomainName(message):
     match = re.search(r'@([a-zA-Z0-9.-]+)', message)
     if match:
         return match.group(1)
     else:
         return None

 #Domain age empty means no value in creation_date in whois result, None means domain does not exist in whois record  
def findDomainAge(domain_info,sent_date):
  try:
     print("in find domain age, domain name:",domain_info["domain_name"])
     creation_date = domain_info.creation_date
     if creation_date is None:
          return None
     if isinstance(creation_date,list):
         creation_date = creation_date[1]
    
     if creation_date.tzinfo is None:
         creation_date= creation_date.replace(tzinfo=timezone.utc)  
     domain_age = sent_date - creation_date
     return str(domain_age.days)
    
  except Exception as e:
        return "None"

def findDomainUpdate():
     pass


def extractAuthResults(auth_results):
     spf_r = r"spf=([^\s;(]+)(?: \(([^)]+)\))?"
     dkim_r = r"dkim=([^\s;(]+)(?: \(([^)]+)\))?"
     dmarc_r = r"dmarc=([^\s;(]+)(?: \(([^)]+)\))?"
     ip_r = r"\b(\d+\.\d+\.\d+\.\d+)\b"
     ip_v6 = r"(?:^|(?<=\s))((?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?:(?::[a-fA-F0-9]{1,4}){1,6})|:(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)|fe80:(?::[a-fA-F0-9]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-fA-F0-9]{1,4}:){1,4}:(?:[0-9]{1,3}\.){3}[0-9]{1,3}))(?:$|(?=\s))"
     auth_values ={}
     if isinstance(auth_results,list):
        auth_results = ";".join(auth_results)
     if isinstance(auth_results,str):
        auth_results = auth_results

     auth_results = re.sub(r"\n", " ", auth_results)   
     spf_match = re.search(spf_r,auth_results)
     dkim_match = re.search(dkim_r,auth_results)
     dmarc_match = re.search(dmarc_r,auth_results)
     if (spf_match.group(2) is None):
          ip_match = None
     else:
          ip_match = re.search(ip_r,spf_match.group(2))
          if ip_match is None:
              ip_match= re.search(ip_v6,spf_match.group(2))
          ip_match = ip_match.group(1)
     
     auth_values["spf"]=spf_match.group(1).lower() if spf_match is not None else "noValue"
     auth_values["dkim"]=dkim_match.group(1).lower() if dkim_match is not None else "noValue"
     auth_values["dmarc"]=dmarc_match.group(1).lower() if dmarc_match is not None else "noValue"
     auth_values["ip"]= ip_match
     return auth_values


def parseEmail(file_name):
    print("in parse file:",file_name)
    mail = mailparser.parse_from_file(file_name)
    headers = mail.headers_json
    headers_obj = json.loads(headers)
    with open(file_name, 'r', encoding='utf-8') as f:
        msg = message_from_file(f)
    
    input_string = msg["From"]

    frm= re.search(r'<([^<>@\s]+@[^<>@\s]+)>', input_string).group(1) if re.search(r'<([^<>@\s]+@[^<>@\s]+)>', input_string) else None
    return_path = re.sub(r'[<>]', '', msg['Return-Path']) if '<' in msg['Return-Path'] and '>' in msg['Return-Path'] else msg['Return-Path']
    message_id = re.sub(r'[<>]', '', mail.message_id) if '<' in mail.message_id and '>' in mail.message_id else mail.message_id
    x_sender_ip = headers_obj['X-Sender-IP'] if "X-Sender-IP" in headers_obj.keys() else None
    date = mail.date
    domain = extractDomainName(return_path)
    domain_info = findDomainDetails(domain)
    domain_age = findDomainAge(domain_info,date)
    auth_results = headers_obj['Authentication-Results']
    auth_values= extractAuthResults(auth_results)
    sender_ip = auth_values["ip"]
    received_spf = headers_obj["Received-SPF"] if "Received-SPF" in headers_obj.keys() else None
    received_spf_values =[]
    if (isinstance(received_spf,str)):
        received_spf_values.append(received_spf.split()[0].lower())
    elif(isinstance(received_spf,list)):
        received_spf_values = [(value.split()[0].lower()) for value in received_spf]
    else:
        received_spf_values = None

    received = mail.received
    number_of_hops = len(received)
    delays = [hop.get('delay', 0) for hop in received]  # Use .get() to handle missing delays
    max_delay = max(delays)
    keys = headers_obj.keys()
    arc_present = True if "ARC-Authentication-Results" in keys or "ARC-Seal" in keys or "ARC-Message-Signature" in keys else False
    if(arc_present):
        total_forwards = len(headers_obj['ARC-Seal']) if len(headers_obj['ARC-Seal']) == len(headers_obj['ARC-Authentication-Results']) == len(headers_obj['ARC-Message-Signature']) else None
    else:
        total_forwards = None

    if "Content-Type" in headers_obj.keys():
          content_type = headers_obj["Content-Type"] 
          content_type = content_type.split(";")[0] if ";" in content_type else content_type

    elif "Content-type" in headers_obj.keys():
         content_type = headers_obj["Content-type"] 
         content_type = content_type.split(";")[0] if ";" in content_type else content_type

    elif "content-type" in headers_obj.keys():
         content_type = headers_obj["content-type"] 
         content_type = content_type.split(";")[0] if ";" in content_type else content_type
    else:
        content_type = None

    phishing = 0 if "ham" in file_name else 1
    
    row={
        "filename":file_name,
        "from":frm,
        "domain":domain,
        "sender_ip":sender_ip,
        "x_sender_ip":x_sender_ip,
        "return_path":return_path,
        "return_path_matched_from":True if frm == return_path else False,
        "message_id":message_id,
        "date":date,
        "domain_age":domain_age,
        "spf": auth_values["spf"],
        "dkim":auth_values["dkim"],
        "dmarc":auth_values["dmarc"],
        "received-spf":received_spf_values,
        "number_of_hops":number_of_hops,
        "max_delay_between_hops":max_delay,
        "has_been_forwarded":1 if arc_present else 0,
        "total_forwarded_times":total_forwards,
        "content_type":content_type,
        "phishing":phishing

    }
    print("out :",file_name)
    return row
