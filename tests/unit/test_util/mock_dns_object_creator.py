import dns
from dns.flags import Flag
from dns.rdtypes.ANY.CAA import CAA
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.TXT import TXT
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rdtypes.ANY.PTR import PTR
from dns.rrset import RRset
from dns.message import QueryMessage

from open_mpic_core import DnsRecordType


class MockDnsObjectCreator:
    @staticmethod
    def create_rrset(rdatatype, *records):
        test_rrset = RRset(name=dns.name.from_text("example.com"), rdclass=dns.rdataclass.IN, rdtype=rdatatype)
        for record in records:
            test_rrset.add(record)
        return test_rrset

    @staticmethod
    def create_caa_record(flags, tag, value):
        return MockDnsObjectCreator.create_record_by_type(
            DnsRecordType.CAA, {"flag": flags, "tag": tag, "value": value}
        )

    @staticmethod
    def create_record_by_type(record_type, record_data):
        value = record_data["value"]
        match record_type:
            case DnsRecordType.CNAME:
                return CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, target=value)
            case DnsRecordType.TXT:
                return TXT(dns.rdataclass.IN, dns.rdatatype.TXT, strings=[value.encode("utf-8")])
            case DnsRecordType.CAA:
                flags = record_data["flag"] if "flag" in record_data else 0
                tag = record_data["tag"] if "tag" in record_data else "issue"
                return CAA(
                    dns.rdataclass.IN,
                    dns.rdatatype.CAA,
                    flags=flags,
                    tag=tag.encode("utf-8"),
                    value=value.encode("utf-8"),
                )
            case DnsRecordType.A:
                return A(dns.rdataclass.IN, dns.rdatatype.A, address=value)
            case DnsRecordType.AAAA:
                return AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, address=value)
            case DnsRecordType.PTR:
                return PTR(dns.rdataclass.IN, dns.rdatatype.PTR, target=value)

    @staticmethod
    def create_caa_query_answer(record_name, flags, tag, value, mocker):
        return MockDnsObjectCreator.create_dns_query_answer(
            record_name, "", DnsRecordType.CAA, {"flag": flags, "tag": tag, "value": value}, mocker
        )

    @staticmethod
    def create_dns_query_answer(record_name, record_name_prefix, record_type, record_data, mocker):
        dns_record = MockDnsObjectCreator.create_record_by_type(record_type, record_data)
        good_response = MockDnsObjectCreator.create_dns_query_message_with_question(
            record_name, record_name_prefix, record_type
        )
        dns_record_name = good_response.question[0].name
        dns_record_type = dns.rdatatype.from_text(record_type)
        response_question_rrset = RRset(name=dns_record_name, rdclass=dns.rdataclass.IN, rdtype=dns_record_type)
        good_response.question = [response_question_rrset]
        response_answer_rrset = RRset(name=dns_record_name, rdclass=dns.rdataclass.IN, rdtype=dns_record_type)
        response_answer_rrset.add(dns_record)
        good_response.answer = [response_answer_rrset]  # caa checker doesn't look here, but dcv checker does
        mocker.patch(
            "dns.message.Message.find_rrset", return_value=response_answer_rrset
        )  # needed for Answer constructor to work
        return dns.resolver.Answer(
            qname=dns_record_name, rdtype=dns_record_type, rdclass=dns.rdataclass.IN, response=good_response
        )

    @staticmethod
    def create_dns_query_answer_with_multiple_records(
        record_name, record_name_prefix, dns_record_type, *records, mocker
    ):
        good_response = MockDnsObjectCreator.create_dns_query_message_with_question(
            record_name, record_name_prefix, dns_record_type
        )
        dns_record_name = good_response.question[0].name
        rdatatype = dns.rdatatype.from_text(dns_record_type)
        response_answer_rrset = MockDnsObjectCreator.create_rrset(rdatatype, *records)
        good_response.answer = [response_answer_rrset]
        mocker.patch("dns.message.Message.find_rrset", return_value=response_answer_rrset)
        return dns.resolver.Answer(
            qname=dns_record_name, rdtype=rdatatype, rdclass=dns.rdataclass.IN, response=good_response
        )

    @staticmethod
    def create_dns_query_message_with_question(
        record_name, record_name_prefix, record_type: DnsRecordType
    ) -> QueryMessage:
        query_message = QueryMessage()
        query_message.flags = Flag.QR | Flag.RD | Flag.RA
        if (record_name_prefix is not None) and (record_name_prefix != ""):
            dns_record_name = dns.name.from_text(f"{record_name_prefix}.{record_name}")
        else:
            dns_record_name = dns.name.from_text(record_name)
        response_question_rrset = RRset(
            name=dns_record_name, rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.from_text(record_type)
        )
        query_message.question = [response_question_rrset]
        return query_message
