#!/usr/bin/env python

class Target:
    def __init__(self):
        self.src_ip     = None
        self.dst_ip     = None
        self.src_port   = None
        self.dst_port   = None
        self.proto      = None
        self.service    = None
        self.regex      = None
        self.sig        = None
        self.cve        = None

    def set_src_ip(self, src_ip):
        self.src_ip = src_ip

    def set_dst_ip(self, dst_ip):
        self.dst_ip = dst_ip

    def set_src_port(self, src_port):
        self.src_port = src_port

    def set_dst_port(self, dst_port):
        self.dst_port

    def set_proto(self, proto):
        self.proto = proto

    def set_service(self, service):
        self.service = service

    def set_regex(self, regex):
        self.regex = regex

    def set_sig(self, sig):
        self.sig = sig

    def set_cve(self, cve_id):
        self.cve = cve_id
