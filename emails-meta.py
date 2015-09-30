import sys
import nids
import email
import hashlib
import json
from bs4 import BeautifulSoup

source_ip = ''
source_port = ''

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def tcp_callback(tcp):
    if tcp.nids_state == nids.NIDS_JUST_EST:
        ((src, sport), (dst, dport)) = tcp.addr
        if dport == 25:
            tcp.server.collect = 1
            tcp.client.collect = 1  
            global source_ip
            global source_port
            source_ip = src
            source_port = sport

    elif tcp.nids_state == nids.NIDS_DATA:
        tcp.discard(0)
    
    elif tcp.nids_state in end_states:
        value = tcp.server.data[:tcp.server.count]
    
        if '\r\nDATA\r\n' not in value:
            return
        
        if '\r\n\r\n' not in value:
            return
        
        temp = value
        envelope_header = temp[:temp.index('\r\nDATA\r\n')]

        smtp_header = temp[temp.index('\r\nDATA\r\n')+len('\r\nDATA\r\n'):temp.index('\r\n\r\n')]

        envelope_helo = ''
        envelope_sender = ''
        recipients = []
        
        for line in envelope_header.splitlines():
            if 'MAIL FROM:' in line.upper():
                try:
                    envelope_sender = line.split(':')[1].strip().split(' ')[0].replace('<', '').replace('>', '')

                except:
                    pass
            elif 'RCPT TO:' in line.upper():
                try:
                    recipient = line.split(':')[1].strip().split(' ')[0].replace('<', '').replace('>', '')
                    recipients.append(recipient)
                except:
                    pass
            elif 'HELO' or 'EHLO' in line.upper():
                try:
                    envelope_helo = line.split(' ')[1]
                except:
                    pass
        
        msg = email.message_from_string(temp[temp.index('\r\nDATA\r\n')+len('\r\nDATA\r\n'):])
        
        smtp_subject = ''
        smtp_from = ''
        smtp_to = ''
        message_id = ''
        smtp_xmailer = ''
        smtp_date = ''
        
        if msg.has_key('from'):
            smtp_from = msg.get('from')
        
        if msg.has_key('subject'):
            smtp_subject = msg.get('subject')
        
        if msg.has_key('message-id'):
            message_id = msg.get('message-id').replace('<', '').replace('>', '')
        
        if msg.has_key('x-mailer'):
            smtp_xmailer = msg.get('x-mailer')
        
        if msg.has_key('to'):
            smtp_to = msg.get('to')

        if msg.has_key('date'):
            smtp_date = msg.get('date')

        links = []

        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                soup = BeautifulSoup(part.get_payload(decode=True))
                for link in soup.findAll('a'):
                    if link.get('href'):
                        links.append(link.get('href'))

        attachments = []
    
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                content_type = part.get_content_type()
                tempfile = part.get_payload(decode=True)
                if tempfile is not None:
                    try:
                        filesize = len(tempfile)
                    except:
                        filesize = 0
                    md5 = hashlib.md5(tempfile).hexdigest()
                    sha1 = hashlib.sha1(tempfile).hexdigest()
                    sha256 = hashlib.sha256(tempfile).hexdigest()
                    attachment = {
                        "filename": filename,
                        "content_type": content_type,
                        "filesize": filesize,
                        "md5": md5,
                        "sha1": sha1,
                        "sha256": sha256
                    }
                    attachments.append(attachment)

        email_details = {
            "source_ip": source_ip,
            "source_port": source_port,
            "envelope_helo": envelope_helo,
            "envelope_sender": envelope_sender,
            "recipients": recipients,
            "smtp_from": smtp_from,
            "smtp_to": smtp_to,
            "smtp_subject": smtp_subject,
            "message_id": message_id,
            "smtp_xmailer": smtp_xmailer,
            "attachments": attachments,
            "envelope_header": envelope_header,
            "smtp_header": smtp_header,
            "links": links,
            "date": smtp_date
        }

        print json.dumps(email_details, sort_keys=True, indent=4)

def main():
    nids.param("pcap_filter", "vlan and port 25")
    nids.param("scan_num_hosts", 0)
    nids.chksum_ctl([('0.0.0.0/0', False)])
    nids.param("filename", sys.argv[1])

    nids.init()
    nids.register_tcp(tcp_callback)
    nids.run()

if __name__ == '__main__':
    main()