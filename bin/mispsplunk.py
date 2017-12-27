#!/usr/bin/python
import os
from pymisp import PyMISP

misp_verifycert = True
supported_types = ["url", "md5", "sha1", "filename", "text", "ssdeep", "ip-src", "ip-dst", "domain", "email-src", "email-dst", "email-subject", "user-agent", "AS"]

class Misp2Lookup():
    def __init__(self, misp_object_response, lookup_dir="./"):
        # Given a MISP Object response we drop CSV into the lookup directory
        self.misp_res = misp_object_response
        self.lookupdir = lookup_dir
        
    def _is_type_supported(self, type_name):        
        if type_name in supported_types:
            return True
        return False    

    def _category_to_fileprefix(self, category):
        return category.replace(' ','_').lower()

    def open_files(self):
        self.fp = {}
        for misp_type in supported_types:
            misp_lookup = self.lookupdir + os.sep + misp_type + ".csv"
            if not os.path.isfile(misp_lookup):
                single_fp = open(misp_lookup, "a+")
                # We write our CSV headers
                single_fp.write("category,event_uuid,value\n")
                self.fp[misp_type] = single_fp
            else:
                single_fp = open(misp_lookup, "a+")
                self.fp[misp_type] = single_fp
            
    def close_files(self):
        for key, value in self.fp.iteritems():
            self.fp[key].close()
        
    def write(self):
        self.open_files()
        for item in self.misp_res['response']:
            event_uuid = item['Event']['uuid']
            for attr in item['Event']['Attribute']:
                if self._is_type_supported(attr["type"]):
                    self.fp[attr["type"]].write(attr["category"] + "," + event_uuid + "," + attr["value"] + "\n")
        self.close_files()
