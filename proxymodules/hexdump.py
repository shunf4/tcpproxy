#!/usr/bin/env python3
import os.path as path
import re
import datetime

HOSTNAME_INVALID_PATTERN = re.compile("[^a-zA-Z0-9._-]")
class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Print a hexdump of the received data'
        self.incoming = incoming  # incoming means module is on -im chain
        self.len = 16
        self.wsdirection = False
        self.source = ("NO_SOURCE", "")
        self.destination = ("NO_DEST", "")
        self.logdir = None
        self.contexts = {}
        if options is not None:
            if 'length' in options.keys():
                self.len = int(options['length'])
            if str(options.get("wsdirection", "0")) == "1":
                self.wsdirection = True

            log_dir = str(options.get("logdir", ""))
            if log_dir != "":
                self.logdir = log_dir
        
    def create_context(self, timestamp):
        ctx = {}
        self.contexts[timestamp] = ctx
        ctx["remote_hostname"] = None
        ctx["timestamp"] = None
        ctx["timestamp_str"] = None
        ctx["source"] = None
        ctx["destination"] = None

        return ctx

    def help(self):
        return """
        \tlength: bytes per line (int)\n
        \twsdirection: set to 1 to enable wireshark direction indication\n
        \tlogdir: if not set, output to stdout; else output to log files under logdir\n"""
    
    def get_destination(self, timestamp):
        return self.contexts.get(timestamp, {}).get("destination") or self.destination

    def get_source(self, timestamp):
        return self.contexts.get(timestamp, {}).get("source") or self.source

    def execute_ex(self, data, timestamp):
        result = []
        
        if self.wsdirection:
            result.append("I" if self.incoming else "O")
        ctx = self.contexts[timestamp]

        # this is a pretty hex dumping function directly taken from
        # http://code.activestate.com/recipes/142812-hex-dumper/
        
        digits = 2
        for i in range(0, len(data), self.len):
            s = data[i:i + self.len]
            hexa = ' '.join(['%0*X' % (digits, x) for x in s])
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
            result.append("%08X   %-*s   %s" % (i, self.len * (digits + 1), hexa, text))
        if self.logdir:
            remote = self.get_source(timestamp) if self.incoming else self.get_destination(timestamp)
            remote_addr = ctx["remote_hostname"] or remote[0]
            remote_port = remote[1]
            remote_addr = HOSTNAME_INVALID_PATTERN.sub("_", str(remote_addr))
            if ctx["timestamp_str"] is None:
                ctx["timestamp_str"] = ctx["timestamp"].strftime("%Y-%m-%d_%H-%M-%S-%f")
            filename = "%s$$%s_%d.log" % (ctx["timestamp_str"], remote_addr, remote_port)
            with open(path.join(self.logdir, filename), "a") as f:
                f.write("\n".join(result))
                f.write("\n")
        else:
            print("\n".join(result))
        return data


if __name__ == '__main__':
    print ('This module is not supposed to be executed alone!')
