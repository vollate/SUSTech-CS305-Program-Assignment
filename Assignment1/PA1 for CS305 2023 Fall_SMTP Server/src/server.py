from __future__ import annotations

from argparse import ArgumentParser
# from email.mime.text import MIMEText
from queue import Queue
import socketserver
from email.mime.text import MIMEText
from email import parser as email_parser
import socket
import re
from socketserver import ThreadingTCPServer, BaseRequestHandler
from threading import Thread

import tomli


def student_id() -> int:
    return 12111224


parser = ArgumentParser()
parser.add_argument('--name', '-n', type=str, required=True)
parser.add_argument('--smtp', '-s', type=int)
parser.add_argument('--pop', '-p', type=int)

args = parser.parse_args()
SMTP_DOMAIN = ''
with open('data/config.toml', 'rb') as f:
    _config = tomli.load(f)
    for agent_domain_postfix in _config['agent']:
        if _config['agent'][agent_domain_postfix]['smtp'].split('.', 1)[1] == args.name:
            SMTP_DOMAIN = agent_domain_postfix
    SMTP_PORT = args.smtp or int(_config['server'][args.name]['smtp'])
    POP_PORT = args.pop or int(_config['server'][args.name]['pop'])
    ACCOUNTS = _config['accounts'][args.name]
    MAILBOXES = {account: [] for account in ACCOUNTS.keys()}
    TO_DELETE = {account: [] for account in ACCOUNTS.keys()}

with open('data/fdns.toml', 'rb') as f:
    FDNS = tomli.load(f)

ThreadingTCPServer.allow_reuse_address = True


def fdns_query(domain: str, type_: str) -> str | None:
    domain = domain.rstrip('.') + '.'
    res = ''
    try:
        res = FDNS[type_][domain]
        return res
    except:
        return None


def authorization(account, password) -> bool:
    return ACCOUNTS[account] == password


class POP3Server(BaseRequestHandler):

    def handle(self):
        self.send_response(f"+OK POP3 server ready")
        account = None
        password = None
        login = False
        while True:
            data = self.request.recv(1024).decode('utf-8').strip()
            if not data:
                break
            print(data)
            msg = data.split()
            if not login:
                if msg[0].upper() == "USER":
                    account = msg[1]
                    if account not in ACCOUNTS:
                        self.send_response(f"-ERR no mailbox for {account}")
                        break
                    self.send_response("+OK User accepted")
                elif data.startswith("PASS"):
                    password = msg[1]
                    if not account:
                        self.send_response("-ERR Please enter account first")
                        break
                    elif not authorization(account, password):
                        self.send_response("-ERR Authentication failed")
                        break
                    login = True
                    self.send_response("+OK Password accepted")
                else:
                    self.send_response("-ERR you need to login first")
                    break
            elif data.startswith("LIST"):
                response = ""
                if len(msg) == 1:
                    # response = f"+OK {len(MAILBOXES[account])} emails\r\n"
                    # for i, mail in enumerate(MAILBOXES[account], 1):
                    #     response += f"{i} {len(mail)}\r\n"
                    valid_emails = [(i, mail) for i, mail in enumerate(MAILBOXES[account], 1) if
                                    i not in TO_DELETE.get(account, [])]
                    response = f"+OK {len(valid_emails)} emails\r\n"
                    for i, mail in valid_emails:
                        response += f"{i} {len(mail)}\r\n"
                    response += "."
                elif len(msg) == 2:
                    index = int(msg[1])
                    if 1 <= index <= len(MAILBOXES[account]) and index - 1 not in TO_DELETE[account]:
                        response = f"+OK {index} {len(MAILBOXES[account][index - 1])}"
                    else:
                        response = "-ERR no such email"
                self.send_response(response)
            elif data.startswith("STAT"):
                self.send_response(
                    f"+OK {len(MAILBOXES[account]) - len(TO_DELETE[account])} {sum(map(len, MAILBOXES[account]))}")
            elif data == "NOOP":
                self.send_response("+OK")
            elif data.startswith("DELE"):
                _, index = data.split()
                index = int(index)
                if 1 <= index <= len(MAILBOXES[account]):
                    if index - 1 in TO_DELETE[account]:
                        self.send_response(
                            f"-ERR email is already marked as deleted")
                    else:
                        TO_DELETE[account].append(index - 1)
                        self.send_response(
                            f"+OK email {index} is marked as deleted")
                else:
                    self.send_response("-ERR no such email")
            elif data.startswith("RETR"):
                _, index = data.split()
                index = int(index)
                valid_emails = [(i, mail) for i, mail in enumerate(MAILBOXES[account], 1) if
                                i not in TO_DELETE.get(account, [])]
                if 1 <= index <= len(valid_emails):
                    _, mail_content = valid_emails[index - 1]
                    escaped_mail_content = '\r\n'.join(
                        ('.' + line) if line.startswith('.') else line
                        for line in mail_content.split('\r\n')
                    )

                    self.send_response(
                        f"+OK {len(escaped_mail_content)} octets\r\n{escaped_mail_content}\r\n.")
                else:
                    self.send_response("-ERR no such email")
            elif data == "RSET":
                TO_DELETE[account].clear()
                self.send_response("+OK all deleted emails are reset")
            elif data == "QUIT":
                self.send_response("+OK bye")
                TO_DELETE[account].sort(reverse=True)
                for index in TO_DELETE[account]:
                    del MAILBOXES[account][index]
                TO_DELETE[account].clear()
                break
            else:
                self.send_response("-ERR command not supported")

    def send_response(self, msg):
        self.request.sendall((msg + "\r\n").encode('utf-8'))


def parse_mime_message(raw_message):
    msg = email_parser.Parser().parsestr(raw_message)
    subject = msg.get("Subject", "(No Subject)")
    content = ""
    sender = msg.get("From", "(No Sender)")
    # receiver=msg.get("To", "(No Receiver)")
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if "text" in content_type:
                content = part.get_payload(decode=True).decode(
                    part.get_content_charset())
    else:
        content = msg.get_payload(decode=True).decode(
            msg.get_content_charset())
    return 'From: ' + sender + '\nSubject: ' + subject + '\nContent: ' + content


def match_email(raw_message):
    match = re.search(r'<(.+?)>', raw_message)
    if match:
        return match.group(1)


def is_ip_address(string) -> bool:
    ipv4_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ipv6_pattern = r'\b[0-9a-fA-F:]+\b'
    if re.match(ipv4_pattern, string):
        return True
    elif re.match(ipv6_pattern, string):
        return True
    else:
        return False


def is_valid_email_address(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_pattern, email):
        return True
    else:
        return False


class CustomTCPServer(ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, email_domain, bind_and_activate=True):
        super(CustomTCPServer, self).__init__(
            server_address, RequestHandlerClass, bind_and_activate)
        self.email_domain = email_domain


class SMTPServer(BaseRequestHandler):
    def check_exception(self, response, exception):
        if response.startswith('550'):
            exception[0] += 1

    def send_email(self, sender, receiver, mail):
        des_domain = fdns_query(receiver.split('@')[1], 'MX')
        if des_domain is None:
            return b'550 Unable to find SMTP server for the domain\r\n'
        des_port = fdns_query(des_domain, 'P')
        msg = MIMEText(mail.split('Content:')[1], 'plain', 'utf-8')
        subject_pattern = r'Subject: (.*?)\n'
        match = re.search(subject_pattern, mail)
        msg['Subject'] = match.group(1)
        msg['From'] = sender
        msg['To'] = receiver
        print(msg.as_string())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            have_exception = [0]
            s.connect(('localhost', int(des_port)))
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            s.sendall(b'HELO ' + self.server.email_domain.encode() + b'\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            s.sendall(b'MAIL FROM:<' + sender.encode() + b'>\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            s.sendall(b'RCPT TO:<' + receiver.encode() + b'>\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            s.sendall(b'DATA\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            # s.sendall(mail.encode() + b'\r\n.\r\n')
            s.sendall(msg.as_string().encode() + b'\r\n.\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            s.sendall(b'QUIT\r\n')
            self.check_exception(s.recv(1024).decode(
                'utf-8'), exception=have_exception)
            return b'550 Unable to send mail\r\n' if have_exception[0] > 0 else b'250 OK\r\n'

    def handle(self):
        self.request.sendall(b'220 SMTP Server Ready\r\n')
        sender = None
        is_client = False
        had_helo = False
        receivers = []
        while True:
            data = self.request.recv(1024).decode('utf-8').strip()
            if not data:
                break
            msg = data.split()
            print(msg)
            if len(msg) == 1 and had_helo:
                if msg[0].upper() == "DATA":
                    if sender is None or len(receivers) == 0:
                        self.request.sendall(
                            b'503 You need set sender/receiver first\r\n')
                        continue
                    self.request.sendall(
                        b'354 Enter mail, end with "." on a line by itself\r\n')
                    mail = parse_mime_message(
                        self.request.recv(1024).decode('utf-8').strip())
                    # mail = self.request.recv(1024).decode('utf-8').strip()
                    failed_send = []
                    for receiver in receivers:
                        print(f"sender {sender} receiver {receiver}")
                        if receiver.split('@')[1] == self.server.email_domain:
                            if receiver not in ACCOUNTS:
                                failed_send.append(sender)
                            else:
                                MAILBOXES[receiver].append(mail)
                        else:
                            print(
                                f"Sending mail to {receiver}'s SMTP server...")
                            if self.send_email(sender, receiver, mail).decode().startswith('550'):
                                failed_send.append(receiver)
                    self.request.sendall(b'250 mail(s) had been send\r\n')
                    for receiver in failed_send:
                        self.send_email(receiver, sender, mail)
                elif msg[0].upper() == "QUIT":
                    self.request.sendall(b'221 Bye\r\n')
                    break
                else:
                    self.request.sendall(b'500 Command not recognized\r\n')
            else:
                if msg[0].upper() == "HELO":
                    is_client = is_ip_address(msg[1])
                    had_helo = True
                    self.request.sendall(b'250 Hello, pleased to meet you\r\n')
                elif had_helo and msg[0].upper() == "MAIL" and msg[1].upper().startswith("FROM:"):
                    tmp_sender = match_email(msg[1])
                    if is_client and tmp_sender not in ACCOUNTS:
                        self.request.sendall(
                            b'550 No such sender username here\r\n')
                        continue
                    if tmp_sender.split('@')[1] + '.' not in FDNS['MX'].keys():
                        self.request.sendall(
                            b'550 Unable to find SMTP server for the domain\r\n')
                        continue
                    if tmp_sender.split('@')[0] == 'error':
                        self.request.sendall(
                            b'550 invalid sender\r\n')
                        continue
                    sender = tmp_sender
                    print(f"sender {sender}")
                    self.request.sendall(b'250 sender OK\r\n')
                elif had_helo and msg[0].upper() == "RCPT" and msg[1].upper().startswith("TO:"):
                    tmp_receiver = match_email(msg[1])
                    if not is_valid_email_address(tmp_receiver):
                        self.request.sendall(
                            b'550 you input a wrong mail address\r\n')
                        continue
                    receivers.append(tmp_receiver)
                    print(f"receiver {receivers}")
                    self.request.sendall(b'250 OK\r\n')
                else:
                    self.request.sendall(b'500 Command not recognized\r\n')


if __name__ == '__main__':
    if student_id() % 10000 == 0:
        raise ValueError('Invalid student ID')

    smtp_server = CustomTCPServer(
        ('', SMTP_PORT), SMTPServer, email_domain=SMTP_DOMAIN)
    pop_server = ThreadingTCPServer(('', POP_PORT), POP3Server)
    Thread(target=smtp_server.serve_forever).start()
    Thread(target=pop_server.serve_forever).start()
