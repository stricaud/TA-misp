import sys
import os
import time
import traceback

import ConfigParser

from pymisp.api import PyMISP

from splunklib.modularinput import *

from mispsplunk import *

MISP_INDEX = "misp"
MISP_FIRST_TIME_SNAPSHOT = "120d"
lookup_dir = os.environ["SPLUNK_HOME"] + os.sep + "etc" + os.sep + "apps" + os.sep + "TA-misp" + os.sep + "lookups"
input_conf_default = os.environ["SPLUNK_HOME"] + os.sep + "etc" + os.sep + "apps" + os.sep + "TA-misp" + os.sep + "default" + os.sep + "inputs.conf"
input_conf_local = os.environ["SPLUNK_HOME"] + os.sep + "etc" + os.sep + "apps" + os.sep + "TA-misp" + os.sep + "local" + os.sep + "inputs.conf"

class MispInputScript(Script):
    def get_scheme(self):
        scheme = Scheme("MISP Input")
        scheme.description = "Connect with MISP to check if your logs try to tell you something you should know"
        scheme.use_external_validation = True
        scheme.use_single_instance = True

        misp_url_arg = Argument("misp_url")
        misp_url_arg.data_type = Argument.data_type_string
        misp_url_arg.description = "Please provide the URL where you access to your MISP instance"
        misp_url_arg.required_on_create = True
        scheme.add_argument(misp_url_arg)
        
        automation_key_arg = Argument("automation_key")
        automation_key_arg.data_type = Argument.data_type_string
        automation_key_arg.description = "Please provide your automation key, which you can get from your MISP instance, such as: https://misp.example.com/events/automation"
        automation_key_arg.required_on_create = True
        scheme.add_argument(automation_key_arg)

        return scheme

    def get_sync_time(self):
        if os.path.isfile(input_conf_local):
            config = ConfigParser.ConfigParser()
            config.read(input_conf_local)
            return int(int(config.get("input_misp", "interval")) / 60)
        if os.path.isfile(input_conf_default):
            config = ConfigParser.ConfigParser()
            config.read(input_conf_default)
            return int(int(config.get("input_misp", "interval")) / 60)

        # We do not want to issue an error here, we just pull every 142 minutes
        return 142
            
    def validate_input(self, validation_definition):
        url = str(validation_definition.parameters["misp_url"])
        if len(url) < 1:
            raise ValueError("The URL must have a length > 1 char")

    def is_first_time(self):
        # We cheat and check only of the AS.csv file exists or not. It must at least have the CSV headers after the first run.
        if os.path.isfile(lookup_dir + os.sep + "AS.csv"):
            return False
        return True
        
    def stream_events(self, inputs, ew):
        ew.log("INFO", "Streaming events for MISP modular input")
        sync_time = self.get_sync_time()
        ew.log("INFO", "Events are streamed every %d minutes\n" % (sync_time))
        
        for input_name, input_item in inputs.inputs.iteritems():
            misp_url = input_item["misp_url"]
            automation_key = input_item["automation_key"]
            misp = PyMISP(str(misp_url), str(automation_key), True, 'json')
            # except:
            #     traceback.print_exc(file=fp)
            # res = misp.get_index()
            if self.is_first_time():
                ew.log("INFO", "Downloading MISP objects for the first time. It will take a while.")
                try:
                    res = misp.download_last(MISP_FIRST_TIME_SNAPSHOT)
                except:
                    tracebk = traceback.format_exc()
                    ew.log("ERROR", tracebk)
            else:
                ew.log("INFO", "Downloading MISP objects every %d minutes." % (sync_time))
                try:                    
                    res = misp.download_last("%dm" % (sync_time))
                except:
                    tracebk = traceback.format_exc()
                    ew.log("ERROR", tracebk)

            ew.log("INFO", "MISP objects collected, creating events")
            try:
                for item in res['response']:
                    event = Event()
                    # event.index = MISP_INDEX
                    event.stanza = input_name
                    event.data = item
                    ew.write_event(event)
            except:
                tracebk = traceback.format_exc()
                ew.log("ERROR", tracebk)

            ew.log("INFO", "MISP Events created, now creating lookups")
                
            lookups = Misp2Lookup(res, lookup_dir)
            lookups.write()

            ew.log("INFO", "Streaming finished")
            
if __name__ == "__main__":
    sys.exit(MispInputScript().run(sys.argv))

