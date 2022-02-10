#!/usr/bin/python3
import multiprocessing
import sys
import time
from collections import defaultdict
from typing import List, Dict, Tuple

from dnslib import DNSRecord, DNSQuestion, DNSHeader, RR, QTYPE, CLASS, RCODE

# Hardcode name and address of root NS
# ROOTNS_DN = "root.netxample."
# ROOTNS_IN_ADDR = "1.102.0.1"

# real internet dns
ROOTNS_DN = 'f.root-servers.net.'
ROOTNS_IN_ADDR = '192.5.5.241'

PORT = 53


class Question:
    """A class representing a DNS question"""

    def __init__(self, record: DNSQuestion):
        self._record = record

    def is_ip_question(self):
        return self._record.qclass == CLASS.IN and self._record.qtype == QTYPE.A

    def __hash__(self):
        return hash((self._record.qname, self._record.qtype, self._record.qclass))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not (self.__eq__(other))


class Record:
    """A class representing a resource records"""

    def __init__(self, record: RR):
        self.start_time = time.time()
        self._record = record

    def get_updated_record(self):
        time_elapsed = time.time() - self.start_time
        time_remaining = int(self.ttl - time_elapsed)
        r = self._record
        return RR(rname=r.rname, rtype=r.rtype, rclass=r.rclass, ttl=time_remaining, rdata=r.rdata)

    def is_expired(self):
        time_elapsed = time.time() - self.start_time
        return time_elapsed > self.ttl

    def is_name_server(self):
        return self._record.rclass == CLASS.IN and self._record.rtype == QTYPE.NS

    def is_ip_address(self):
        return self._record.rclass == CLASS.IN and self._record.rtype == QTYPE.A

    def is_canonical_name(self):
        return self._record.rclass == CLASS.IN and self._record.rtype == QTYPE.CNAME

    @property
    def rname(self):
        return str(self._record.rname)

    @property
    def rtype(self):
        return str(QTYPE.get(self._record.rtype))

    @property
    def rclass(self):
        return str(CLASS.get(self._record.rclass))

    @property
    def rdata(self):
        return str(self._record.rdata)

    @property
    def ttl(self):
        return int(self._record.ttl)

    def __hash__(self):
        # intentionally skipped ttl as it may vary
        return hash((self.rname, self.rtype, self.rclass, self.rdata))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not (self.__eq__(other))

    def __str__(self):
        return 'Record({:.2f} {} {} {} {} {})' \
            .format(self.start_time, self.rname, self.rclass, self.rtype, self.rdata, self.ttl)

    def __repr__(self):
        return str(self)


class ResourceRecordPool:
    """A class to store multiple resource records and manipulation function"""

    def __init__(self, records=None, update_interval=0.1):

        self.records = set()
        self._last_update_time = time.time()
        self._update_interval = update_interval  # unit seconds

        if records is not None:
            self.add_all(records)

    def add(self, record):
        if not isinstance(record, Record):
            record = Record(record)
        self.records.add(record)

    def add_all(self, records):
        for r in records:
            self.add(r)

    def __contains__(self, item):
        return item in self.records

    def merge_pool(self, other):
        self.records = self.records.union(other.records)

    def merge_response(self, response):
        if not isinstance(response, Response):
            response = Response(response)
        self.merge_pool(response.rr_pool)

    def __getattribute__(self, item):
        last_update_time = object.__getattribute__(self, '_last_update_time')
        update_interval = object.__getattribute__(self, '_update_interval')
        current_time = time.time()

        # if time elapsed more than min refresh interval
        if current_time - last_update_time >= update_interval:
            # remove records that had expired
            records = object.__getattribute__(self, 'records')
            for r in records:
                if r.is_expired():
                    records.remove(r)
            # update last update time
            object.__setattr__(self, '_last_update_time', current_time)
        return object.__getattribute__(self, item)

    @staticmethod
    def _get_multimap(records: List[Record], map2record=False) -> Dict[str, list]:
        multimap = defaultdict(list)
        for record in records:
            multimap[record.rname].append(record if map2record else record.rdata)
        return multimap

    def get_enclosed_cnames(self, sname, records=False, visited=None):
        if visited is None:
            visited = set()

        for cname in self.get_name2cnames(records)[sname]:
            if cname not in visited and cname != sname:
                # avoid infinite recursion cname
                # e.g. we have two cnames such that A <-> B
                visited.add(cname)
                visited = visited.union(self.get_enclosed_cnames(cname))

        return visited

    def get_name2cnames(self, map2record=False) -> Dict[str, list]:
        return self._get_multimap([r for r in self.records if r.is_canonical_name()], map2record)

    def get_zone2names(self, map2record=False) -> Dict[str, list]:
        return self._get_multimap([r for r in self.records if r.is_name_server()], map2record)

    def get_name2ips(self, map2record=False) -> Dict[str, list]:
        return self._get_multimap([r for r in self.records if r.is_ip_address()], map2record)

    def resolve(self, sname, skip_cnames=False):
        resolved_ips = []

        if not skip_cnames:
            # NOTE: it is possible for two CNAME records to be: A -> B and B -> A,
            # we should avoid the potential infinite recursion here
            for cname in self.get_enclosed_cnames(sname):
                resolved_ips.extend(self.resolve(cname, skip_cnames=True))

        name2ips = self.get_name2ips()
        if sname in name2ips:
            resolved_ips.extend(name2ips[sname])

        return resolved_ips

    def get_ip_records(self, sname: str) -> List[Record]:
        ips = []
        name2ips = self.get_name2ips(map2record=True)
        for name in self.get_enclosed_cnames(sname).union({sname}):
            if name in name2ips:
                ips.extend(name2ips[name])
        return ips

    def get_cname_records(self, sname: str) -> List[Record]:
        return self.get_enclosed_cnames(sname, records=True)

    def get_bottom_level_domain(self, n: str) -> List[Record]:
        zone2servers = self.get_zone2names(map2record=True)

        parts = n.split('.')
        for i in range(len(parts) - 1):
            zone = '.'.join(parts[i:])
            if zone in zone2servers:
                return zone2servers[zone]

        return []

    def get_servers_to_ask(self, sname, skip_cnames=False):
        if not skip_cnames:
            for cname in self.get_enclosed_cnames(sname):
                yield from self.get_servers_to_ask(cname, skip_cnames=True)

        # resolve from the bottom to top level domain
        parts = sname.split('.')
        for i in range(len(parts) - 1):  # -1 to skip ending .
            zone = '.'.join(parts[i:])
            ns_no_ip = []
            for ns in self.get_zone2names()[zone]:
                name2ips = self.get_name2ips()
                if ns in name2ips:
                    yield ns, name2ips[ns]  # return those ns with ip address first
                else:
                    ns_no_ip.append((ns, []))  # ns without ip, save for later, lower priority
            yield from ns_no_ip

    def __str__(self):
        return str(self.records)

    def __repr__(self):
        return str(self)


CACHE = ResourceRecordPool()


class Response:
    """A class representing a DNS response"""

    def __init__(self, response: DNSRecord, request_name=None, server_name=None, server_ip=None):

        # housekeeping
        self.response = response
        self.name = request_name
        self.server_name = server_name
        self.server_ip = server_ip

        # response = question + resource records
        self.ip_questions = [str(r.get_qname()) for r in response.questions if Question(r).is_ip_question()]
        self.rr_pool = ResourceRecordPool(response.rr + response.auth + response.ar)

    def contains_cname(self, sname):
        return len(self.rr_pool.get_enclosed_cnames(sname)) > 0

    def resolve(self, sname):
        return self.rr_pool.resolve(sname)

    def get_servers_to_ask(self, n):
        return self.rr_pool.get_servers_to_ask(n)

    def __str__(self):
        return 'Response(name={} server={} server_ip={})'.format(self.name, self.server_name, self.server_ip)

    def __repr__(self):
        return str(self)


def dns_request(req_name, server_name, server_ip):
    """Send a DNS request and return response and return code"""
    query = DNSRecord.question(req_name)
    raw_response = query.send(server_ip, port=PORT, tcp=False)
    response = DNSRecord.parse(raw_response)
    return_code = response.header.get_rcode()
    return Response(response, req_name, server_name, server_ip), return_code


def dns_reply(question, rr_pool=CACHE):
    """Build a DNS Reply of the given question from the given resource record pool"""

    reply = DNSRecord(DNSHeader(qr=1, rd=1, ra=1))

    def add_auth_ar(sname):
        max_name_servers = rr_pool.get_bottom_level_domain(sname)
        for name_server in max_name_servers:
            if name_server not in ResourceRecordPool(reply.auth):
                reply.add_auth(name_server.get_updated_record())
            for r in rr_pool.get_ip_records(name_server.rdata):
                if r not in ResourceRecordPool(reply.ar):
                    reply.add_ar(r.get_updated_record())

    reply.add_question(DNSQuestion(question))
    names = rr_pool.get_cname_records(question)
    for answer in rr_pool.get_ip_records(question):
        for name in names:
            if name.rdata == answer.rname:
                if name not in ResourceRecordPool(reply.rr):
                    reply.add_answer(name.get_updated_record())
                add_auth_ar(name.rdata)
        if answer not in ResourceRecordPool(reply.rr):
            reply.add_answer(answer.get_updated_record())
        add_auth_ar(answer.rname)

    return Response(reply)


def get_best_server_to_ask(sname):
    try:
        return next(CACHE.get_servers_to_ask(sname))
    except StopIteration:
        return ROOTNS_DN, [ROOTNS_IN_ADDR]  # last resort


def resolve(sname, use_cache=True, trace=None) -> Tuple[Response, List[Response]]:
    """
    Derived from:
        RFC 1034: https://datatracker.ietf.org/doc/html/rfc1034
        RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035
    """

    if trace is None:
        trace = []

    # 1. See if the answer is in local information, and if so return it to the client.
    if use_cache and CACHE.resolve(sname):
        return dns_reply(sname), trace

    # 2. Find the best servers to ask.
    server_name, server_ips = get_best_server_to_ask(sname)
    if not server_ips:
        server_reply, _ = resolve(server_name, trace=trace)
        server_ips = server_reply.resolve(server_name)

    # 3. Send them queries until one returns a response.
    for server_ip in server_ips:
        response, return_code = dns_request(sname, server_name, server_ip)
        trace.append(response)

        # 4. Analyze the response.
        if return_code != RCODE.NOERROR:
            if return_code == RCODE.NXDOMAIN:
                # 4a. if the response answers the question or contains a name error,
                # cache the data as well as returning it back to the client.
                return response, trace
            # 4d. if the response shows a servers failure or other bizarre contents,
            # delete the server from the SLIST and go back to step 3.
            continue

        # If resolved, return reply and trace
        if response.resolve(sname):
            CACHE.merge_response(response)
            return dns_reply(sname), trace

        # 4c. if the response shows a CNAME and that is not the answer itself,
        # cache the CNAME, change the SNAME to the canonical name in the CNAME RR and go to step 1.
        if response.contains_cname(sname):
            CACHE.merge_response(response)
            for cname in CACHE.get_enclosed_cnames(sname):
                reply, _ = resolve(cname, trace=trace)
                if reply.resolve(cname):
                    return dns_reply(sname), trace

        # 4b. if the response contains a better delegation to other servers,
        # cache the delegation information, and go to step 2.
        try:
            _better_delegate = next(response.get_servers_to_ask(sname))
            CACHE.merge_response(response)
            return resolve(sname, use_cache=False, trace=trace)
        except StopIteration:
            pass

    # impossible fallback, worst case the root server should resolve everything
    return dns_reply(sname), trace


def trace_log_format(record):
    """Format a resource record similar to given coursework trace log"""
    def max_length(records):
        return max(len(str(r.rname)) for r in records) if len(records) > 0 else 0

    max_q = max(len(str(r.qname)) for r in record.questions) if len(record.questions) > 0 else 0
    max_rr = max_length(record.rr)
    max_ar = max_length(record.ar)
    max_auth = max_length(record.auth)
    max_len = max([max_q, max_ar, max_auth, max_rr])

    def format_rr(rr):
        return '%-{}s\t%s\t%s\t%s\t%s'.format(max_len) \
               % (rr.rname, rr.ttl, CLASS.get(rr.rclass), QTYPE.get(rr.rtype), rr.rdata.toZone())

    def format_q(q):
        return ';%-{}s\t\t%s\t%s'.format(max_len) % (q.qname, CLASS.get(q.qclass), QTYPE.get(q.qtype))

    z = record.header.toZone().split("\n")
    if record.questions:
        z.append("\n;; QUESTION SECTION:")
        [z.extend(format_q(q).split("\n")) for q in record.questions]
    if record.rr:
        z.append("\n;; ANSWER SECTION:")
        [z.extend(format_rr(rr).split("\n")) for rr in record.rr]
    if record.auth:
        z.append("\n;; AUTHORITY SECTION:")
        [z.extend(format_rr(rr).split("\n")) for rr in record.auth]
    if record.ar:
        z.append("\n;; ADDITIONAL SECTION:")
        [z.extend(format_rr(rr).split("\n")) for rr in record.ar]

    return "\n".join(z)


def trace_resolve(sname):
    """Resolve the given name to ip and print its trace"""
    reply, trace = resolve(sname)

    ips = reply.resolve(sname)
    ip = ips[0] if ips else None
    print('trace recursive DNS query to resolve: {} ({})'.format(sname, ip))
    for i, response in enumerate(trace, 1):
        print('{} {} [{}]'.format(i, response.server_name, response.server_ip))

    print()
    print('final reply')
    print(trace_log_format(reply.response))
    print()


def set_timeout(seconds, function, *args, **kwargs):
    """Run a function with timeout in seconds"""
    process = multiprocessing.Process(target=function, args=args, kwargs=kwargs)
    process.start()

    process.join(seconds)

    if process.is_alive():
        process.terminate()
        process.join()
        raise TimeoutError()


def main():
    # check input argument
    if len(sys.argv) < 2:
        print("usage: {} <name(s) to resolve>".format(sys.argv[0]))
        sys.exit()

    # find ip for each given names
    names = sys.argv[1:]
    for name in names:
        trace_resolve(name)


if __name__ == '__main__':
    # 9 instead 10 to ensure it runs no longer than 10s
    set_timeout(9, main)
