#!./venv/bin/python

from __future__ import annotations
from channel import Channel
from typing import Any
import datetime as dt
from utils import random_key, deserialize_decrypt, serialize_encrypt, lt_now
from ktypes import Event, Message, ServerTicket, ClientTicket, TGT, Authenticator

class Entity:
    session_keys = {}
    channel = Channel()

    def __init__(self, name: str, key: str=random_key()):
        self.name = name
        self.key = key
        Entity.channel.subscribe(name, self.handle_message)

    def send(self, event:Event, receiver:str, body:Any):
        message = Message(source=self.name, event=event, body=body)
        Entity.channel.publish(receiver, message)

    def get_session_key(self, name:str):
        session_key, expiry = self.session_keys.get(name, (None, None))

        if lt_now(expiry):
            return

        return session_key

class KDC(Entity):
    database = {}

    def handle_message(self, message: Message):
        match message.event:
            case Event.AUTHN:
                client_name = message.body
                print(f"%s: Authenticating {client_name}..." % self.name)
                client_key = self.get_key(client_name)

                if not client_key:
                    print("%s is not in the database" % client_name)
                    return

                expiry = dt.datetime.now() + dt.timedelta(hours=8)
                client_session_key = self.generate_key(client_name, expiry)
                client_ticket = ClientTicket(session_key=client_session_key, expiry=expiry.isoformat())
                enc_client_ticket = serialize_encrypt(client_ticket, client_key)

                tgt = TGT(session_key=client_session_key, expiry=expiry.isoformat(), name=client_name)
                enc_tgt = serialize_encrypt(tgt, self.key)

                self.send(Event.REPLY_AUTHN, client_name, (enc_client_ticket, enc_tgt))
                return
            case Event.AUTHZ:
                print(f"%s: Authorizing {message.source}..." % self.name)

                (enc_tgt, server_name), enc_authenticator = message.body
                tgt:TGT = deserialize_decrypt(enc_tgt, self.key, TGT)

                if lt_now(tgt.expiry):
                    print("TGT by %s has expired" % tgt.name)
                    return
                
                authenticator: Authenticator = deserialize_decrypt(enc_authenticator, tgt.session_key, Authenticator)
                
                if authenticator.name != tgt.name:
                    print("TGT impersonated!")
                    return

                session_key = random_key()
                server_ticket_expiry = dt.datetime.now() + dt.timedelta(hours=18)
                server_ticket: ServerTicket = ServerTicket(session_key=session_key, name=message.source, expiry=server_ticket_expiry.isoformat())
                server_key = self.get_key(server_name)

                if not server_key:
                    print("Server %s does not exist in database" % server_name)
                    return

                server_ticket_enc = serialize_encrypt(server_ticket, server_key)
                client_session_key = self.get_session_key(tgt.name)

                if not client_session_key:
                    print("Session key for %s does not exist or has expired" % tgt.name)
                    return
                
                session_key_enc = serialize_encrypt(session_key, client_session_key)

                self.send(Event.REPLY_AUTHZ, message.source, ((server_name, server_ticket_enc), session_key_enc))

            case unknown:
                print("Unknown event %s" % unknown)

    def generate_key(self, client_name, expiry):
        session_key = random_key()
        self.session_keys[client_name] = (session_key, expiry)
        return session_key

    def get_key(self, name):
        key = self.database.get(name)
        return key

    def add_entity(self, entity:(Client|Server)): 
        self.database[entity.name] = entity.key

class Client(Entity):
    tgts = {}
    server_tickets = {}

    def handle_message(self, message: Message):
        match message.event:
            case Event.REPLY_AUTHN:
                enc_client_ticket, tgt = message.body
                client_ticket:ClientTicket = deserialize_decrypt(enc_client_ticket, self.key, ClientTicket)
                self.tgts[message.source] = (tgt, dt.datetime.fromisoformat(client_ticket.expiry))
                self.session_keys[message.source] = (client_ticket.session_key, dt.datetime.fromisoformat(client_ticket.expiry))
            case Event.REPLY_AUTHZ:
                (server_name, server_ticket), session_key_enc = message.body

                kdc_session_key = self.get_session_key(message.source)
        
                if not kdc_session_key:
                    print("Session key for (%s, %s) has expired" % (self.name, message.source))
                    return

                server_session_key: str = deserialize_decrypt(session_key_enc, kdc_session_key)
                self.server_tickets[server_name] = (server_ticket, server_session_key)
            case Event.REPLY_REQUEST:
                _, session_key = self.server_tickets.get(message.source, (None, None))
    
                if not session_key:
                    print("Session key for (%s, %s) has expired" % (self.name, message.source))
                    return

                timestamp = deserialize_decrypt(message.body, session_key)
                
                # TODO: verify correctly?
                if lt_now(dt.datetime.fromisoformat(timestamp) + dt.timedelta(minutes=5)):
                    print("Verification has expired")
                    return

                print("%s: Server verified successfully!" % self.name)
                
    def authenticate(self, kdc):
        self.send(Event.AUTHN, kdc.name, self.name)

    def authorize(self, kdc:KDC, server_name:str):
        tgt = self.get_tgt(kdc.name)
        if not tgt:
            print("TGT for (%s, %s) has expired" % (self.name, kdc.name))
            return

        session_key = self.get_session_key(kdc.name)
        
        if not session_key:
            print("Session key for (%s, %s) has expired" % (self.name, kdc.name))
            return

        enc_authenticator = self.generate_authenticator(session_key)

        self.send(Event.AUTHZ, kdc.name, ((tgt, server_name), enc_authenticator))

    def generate_authenticator(self, key) -> str:
        authenticator:Authenticator = Authenticator(name=self.name, expiry=dt.datetime.now().isoformat())
        enc_authenticator = serialize_encrypt(authenticator, key)
        return enc_authenticator
    
    def request(self, server_name:str):
        ticket, session_key = self.get_ticket(server_name)

        if not ticket:
            print("No ticket available for server %s" % server_name)

        enc_authenticator = self.generate_authenticator(session_key)
        self.send(Event.REQUEST, server_name, (ticket, enc_authenticator))

    def get_ticket(self, server_name):
        server_ticket, server_session_key = self.server_tickets.get(server_name, (None, None))

        if not server_ticket:
            return None, None

        return server_ticket, server_session_key

    def get_tgt(self, kdc_name:str):
        session_key, expiry = self.tgts.get(kdc_name, (None, None))

        if lt_now(expiry):
            return

        return session_key

class Server(Entity):
    def handle_message(self, message: Message):
        match message.event:
            case Event.REQUEST:
                enc_ticket, enc_authenticator = message.body
                ticket: ServerTicket = deserialize_decrypt(enc_ticket, self.key, ServerTicket)
                session_key = ticket.session_key

                if lt_now(ticket.expiry):
                    print("Ticket for (%s, %s) has expired" % (self.name, ticket.name))
                    return

                authenticator: Authenticator = deserialize_decrypt(enc_authenticator, session_key, Authenticator)

                if authenticator.name != ticket.name:
                    print(authenticator.name, ticket.name)

                    print("Ticket impersonated!")
                    return

                if lt_now(dt.datetime.fromisoformat(authenticator.expiry) + dt.timedelta(minutes=5)):
                    print("Authenticator has expired")
                    return

                print("%s: Client authorized successfully!" % self.name)
                
                enc_verification = serialize_encrypt((dt.datetime.fromisoformat(authenticator.expiry) + dt.timedelta(milliseconds=1)).isoformat(), session_key)
                self.send(Event.REPLY_REQUEST, message.source, enc_verification)


if __name__ == "__main__":
    # demo run
    
    cli1 = Client(name="cli1")
    serv1 = Server(name="serv1")
    kdc = KDC(name="kdc")

    kdc.add_entity(cli1)
    kdc.add_entity(serv1)

    cli1.authenticate(kdc)
    cli1.authorize(kdc, serv1.name)
    cli1.request(serv1.name)
