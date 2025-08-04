"""A combined HTTP + DNS server for ACME DNS-01 testing with lego.

This server:
  - Listens on /present and /cleanup to register/clear DNS-01 TXT challenges.
  - Serves DNS requests for TXT records based on registered challenges.
  - Intercepts DNS requests related to verifying whether the records have propagated.
  - Forwards all other DNS requests to the cluster DNS.

Run as root or with CAP_NET_BIND_SERVICE to bind to port 53.
"""

import logging

import dns.exception
import dns.message
import dns.query
import dns.rdtypes
from dnslib import AAAA, NS, QTYPE, RR, SOA, TXT, A
from dnslib.dns import DNSRecord
from dnslib.server import BaseResolver, DNSHandler, DNSServer
from flask import Flask, request

# --- Configuration ---
LISTEN_IP = "127.0.0.1"
DNS_PORT = 53
DNS_UPSTREAM = "10.152.183.10"  # Cluster DNS IP (adjust as needed)
HTTP_PORT = 8080

# --- Global challenge map ---
challenge_map = {}

# --- Flask HTTP server ---
app = Flask(__name__)


@app.route("/present", methods=["POST"])
def present():
    data = request.json
    app.logger.info("/present %s", data)
    assert data is not None
    fqdn = data["fqdn"].rstrip(".")
    value = data["value"]
    challenge_map[fqdn] = value
    app.logger.info("Stored TXT record: %s -> %s", fqdn, value)
    return "", 200


@app.route("/cleanup", methods=["POST"])
def cleanup():
    data = request.json
    app.logger.info("/cleanup %s", data)
    assert data is not None
    fqdn = data["fqdn"].rstrip(".")
    removed = challenge_map.pop(fqdn, None)
    if removed:
        app.logger.info("Removed TXT record: %s", fqdn)
    return "", 200


# --- DNS resolver ---
class AcmeResolver(BaseResolver):
    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        logging.info("\n>>>%s\nresolve %s", challenge_map, request)
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        logging.info("DNS query: %s %s\n<<<\n", qtype, qname)
        reply = request.reply()
        if qtype == "TXT" and qname in challenge_map:
            txt_value = challenge_map[qname]
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(txt_value), ttl=30))
            logging.info("Resolved TXT %s -> %s", qname, txt_value)
            return reply
        elif qtype == "SOA":  # and any(qname.endswith(k) for k in challenge_map):
            # Construct a synthetic SOA record
            soa_record = SOA(
                mname="ns.mock.",  # Primary name server
                rname="admin.mock.",  # Responsible party
                times=(
                    2025080101,
                    3600,
                    1800,
                    604800,
                    86400,
                ),  # Serial, Refresh, Retry, Expire, Minimum
            )
            reply.add_answer(RR(qname, QTYPE.SOA, rdata=soa_record, ttl=300))
            logging.info("Responded with SOA for %s", qname)
            return reply
        elif qtype == "NS" and any(qname.endswith(k) for k in challenge_map):
            ns_record = NS("ns.mock.")
            reply.add_answer(RR(qname, QTYPE.NS, rdata=ns_record, ttl=300))
            logging.info("Responded with NS for %s with %s", qname, ns_record)
            return reply
        elif qtype == "A" and qname == "ns.mock":
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=300))
            return reply
        elif qtype == "AAAA" and qname == "ns.mock":
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::1"), ttl=300))
            return reply
        elif qtype == "CNAME" and qname != "ns.mock":
            logging.info(
                "Received CNAME query for %s, responding with NOERROR and no answer: %s",
                qname,
                reply,
            )
            # No CNAME means no answer, but we explicitly return NOERROR
            return reply
        else:
            # Fallback with dnspython
            upstream_response = query_upstream(qname, qtype)
            return dns_to_dnslib(upstream_response, request)


def query_upstream(qname: str, qtype: str, timeout: float = 1.0) -> dns.message.Message:
    logging.info("query_upstream %s %s", qname, qtype)
    name = qname if "." in qname else f"{qname}.model.svc.cluster.local"
    dns_request = dns.message.make_query(name, qtype)
    response = dns.query.udp(dns_request, DNS_UPSTREAM, timeout=timeout)
    logging.info("query_upstream %s %s response: %s", name, qtype, response)
    return response


def dns_to_dnslib(
    dnspython_response: dns.message.Message, original_dnslib_request: DNSRecord
) -> DNSRecord:
    reply = original_dnslib_request.reply()
    for answer in dnspython_response.answer:
        logging.info("dns_to_dnslib: %s", answer)
        for item in answer.items:
            logging.info("dsn_to_dislib: item: %s %s", type(item), item)
            rdata = None
            if isinstance(item, dns.rdtypes.IN.A.A):  # type: ignore
                logging.info("dsn_to_dislib: A")
                rdata = A(str(item.address))
                logging.info("dsn_to_dislib: A: %s", rdata)
            elif isinstance(item, dns.rdtypes.IN.AAAA.AAAA):  # type: ignore
                logging.info("dsn_to_dislib: AAAA")
                rdata = AAAA(str(item.address))
                logging.info("dsn_to_dislib: AAAA: %s", rdata)
            # Add other types as needed
            logging.info("dsn_to_dislib: rdata: %s", rdata)
            if rdata:
                reply.add_answer(
                    RR(
                        str(answer.name),
                        getattr(QTYPE, answer.rdtype.name),
                        rdata=rdata,
                        ttl=answer.ttl,
                    )
                )
    return reply


# --- Run both servers ---
def start_dns_server():
    resolver = AcmeResolver()
    dns_tcp = DNSServer(resolver, port=DNS_PORT, address=LISTEN_IP, tcp=True)
    dns_udp = DNSServer(resolver, port=DNS_PORT, address=LISTEN_IP, tcp=False)
    dns_tcp.start_thread()
    dns_udp.start_thread()
    logging.info("DNS server running on %s:%s", LISTEN_IP, DNS_PORT)


def start_http_server():
    logging.info("HTTP server running on 0.0.0.0:%s", HTTP_PORT)
    app.run(host="0.0.0.0", port=HTTP_PORT)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, handlers=[logging.FileHandler("/server.log", mode="a")]
    )
    start_dns_server()
    # Run HTTP server on main thread
    start_http_server()
