#! /usr/bin/env python
"""
ACI JSON updater
.
Writen by Tony Condran & Chris Welsh

Housley Communications
www.housley.com.au


This is sharemeware - so please pass around
Would like the see Housley name in there if possible

Versions:
0.1 May 2018, TC
0.1 Oct 2018, TC
1.0 July 2019 CW
1.0.1 March 2020 JC
"""
import argparse
import ast
from pprint import pprint
import getpass
import os
import requests
import logging
import json
import sys
ver = "1.0.1"
verDate = 'March 2020'


class Session(object):
    """Session class
       This class contains the connectivity information for talking to the
       APIC.
    """

    def __init__(self, ipOrFqdn, uid, pwd, verify_ssl=False):
        self.ipOrFqdn = ipOrFqdn
        self.uid = uid
        self.pwd = pwd
        self.uriAddress = 'https://%s:443' % self.ipOrFqdn
        self.session = None
        self.verify_ssl = verify_ssl

    def login(self):
        """Login into  APIC"""
        logging.info("\n*** Connecting to the APIC\n")
        login_url = self.uriAddress + '/api/aaaLogin.json'
        name_pwd = {'aaaUser': {'attributes': {'name': self.uid,
                                               'pwd': self.pwd}}}
        vCred = json.dumps(name_pwd)
        self.session = requests.Session()
        ret = self.session.post(login_url, data=vCred, verify=self.verify_ssl)
        return ret

    def push_to_apic(self, data):
        """Push the data to the APIC"""
        # Find the dn of the object we are pushing to determine the base url to
        # which we must post. It should appear on a line that looks something
        # like one of the following:
        # "dn": "uni/tn-common"
        # "dn": "uni/infra/cdpIfP-Disable_CDP"
        # "dn": "uni/fabric/format-default"
        # "dn": "uni/fabric/comm-default"
        #
        # Too hard to add users using API because of the need to create
        # unique UnixID and password when creating user

        vDataStr = str(data)
        vDnFoundAt = vDataStr.find("dn")
        vUniFoundAt = vDataStr.find("uni", vDnFoundAt)
        if vUniFoundAt < 0:
            logging.info("\n*** Can't determine dn path in ",
                         vDataStr + "\n\n")
            print("\n*** Can't determine dn path. Cannot continue")
            exit()
        vCommaFoundAt = vDataStr.find(",", vUniFoundAt)
        vDnSubstr = vDataStr[vUniFoundAt:vCommaFoundAt - 1]
        # vLastSlashFoundAt=vDnSubstr.rfind("/")
        post_url = "/api/mo/" + vDnSubstr + ".json"

        # The following works for tenants, fabric and access policies,
        # but NOT adding users

        post_uri = self.uriAddress + post_url
        logging.debug("\n*** Posting uri:\n %s \n*** data:\n %s",
                      post_uri, data)
        resp = self.session.post(post_uri, data=json.dumps(data))
        logging.info("\n*** Response:\n %s %s\n", resp, resp.text)
        return resp

    def get(self, url=None):
        """Perform a REST GET call to the APIC."""

        if url == None:
            url = self.url
            logging.info("\n*** no url\n\n")

        else:
            #url = "/api/mo/uni/" + url + ".json"
            url = url + ".json"
            logging.info("\n*** url: \n" + url + "\n\n")

        get_url = self.uriAddress + url
        logging.info("\n*** URL to APIC: \n" + get_url + "\n\n")

        logging.debug("\n*** get_utl:\n" + get_url + "\n\n")
        resp = self.session.get(get_url)
        logging.debug("\n*** resp:\n" + str(resp) + "\n\n")
        pprint(ast.literal_eval(resp.text))


class tools():
    def readJSON(self, filename):
        # read from file - as JSON/DICT
        logging.debug("\n******* File Name:\n" + filename + "\n\n")
        try:
            file = open(filename)
        except:  # Should never happen
            print("Could not open JSON file: " + filename)
            exit()

        # read file
        jsondata = file.read()

        try:
            dict = json.loads(jsondata)

        except:
            print("Error importing JSON file data: " + filename)
            print("Format error")
            exit()

        file.close()

        # Lot of output
        #logging.debug("\n**** File Dump: ")
        # logging.debug(dict)
        return(dict)

    def getFileList(self, dir):
        print("Processing files in directory: " + dir)
        logging.info("\n*** Processing files in directory: \n" + dir + "\n\n")

        fileList = os.listdir(dir)
        jsonFiles = [fName for fName in fileList if fName.endswith(".json")]
        noFiles = len(jsonFiles)

        if not len(jsonFiles) > 0:
            print("No .json files found in directory " + dir)
            logging.info(
                "\n*** No .json files found in directory " + dir + "\n\n")
            exit()

        else:
            print("Number of .json files: " + str(noFiles))
            logging.debug("\n***** Files: \n" + str(jsonFiles) + "\n\n")

        return jsonFiles

    def aciPusher(self, vJsonData, aciSession):
        logging.info("\n**** Pushing vJsonData:" + str(vJsonData) + "\n\n")
        vResult = str(aciSession.push_to_apic(vJsonData))
        if "Response [200]" not in vResult:
            print("Pushing failed with: " + vResult)
            logging.info("\n*** Push failed with: ", str(vResult))
            return False
        else:
            return True


""" #############################
        start of program
    ############################# """


def main():

    # Defaults for passed arguments
    vPath = ""
    vUser = "admin"
    vEnteredPassword = None

    vParser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                      description="\nHousley ACI bulk JSON file posting script:\n" +
                                      "Posts all JSON configuration files found in given directory to given ACI APIC\n" +
                                      "or pulls JSON config for a given mo or class\n\n",
                                      epilog="Examples:\n%(prog)s -t apic1.my.domain push dir_where_json_files_are_stored\n" +
                                      "%(prog)s -t apic1.my.domain push tn-common.json\n" +
                                      "%(prog)s -t apic1.my.domain pull /mo/uni/tn-common\n" +
                                      "%(prog)s -t apic1.my.domain pull /class//dhcpClient")

    vParser.add_argument("-t, --target",
                         dest="vApicIpOrFqdn",
                         metavar="Target_APIC_IP_or_FQDN",
                         help="Target APIC IP or FQDN")

    vParser.add_argument("-u", "--user",
                         dest="vUser",
                         metavar="Admin_User",
                         default="admin",
                         help="User name for APIC login - default = admin")

    vParser.add_argument("-p", "--password",
                         dest="vEnteredPassword",
                         metavar="Admin_User_Password",
                         default=None,
                         help="Password for APIC admin user login")

    vParser.add_argument("-v", "--version",
                         action="version",
                         version="%(prog)s version " + str(ver) + " " + verDate)

    vParser.add_argument("-d", "--debug",
                         dest="vDebugLevel",
                         metavar="Debug_Level",
                         help="Set the debug level 0=none, 1=INFO, 2=DEBUG",
                         type=int,
                         default=0)

    # Build sub commands
    vActions = vParser.add_subparsers(title="actions", dest="commandAction")
    vParserPush = vActions.add_parser("push",
                                      help="Push JSON file or directory or JSON files to APIC")
    vParserPush.add_argument(
        dest="vPath",
        metavar="JSON_Path",
        help="relative path to JSON file or directory (Mandatory)")
    vParserPull = vActions.add_parser("pull",
                                      help="Pull JSON config for managed object (mo) or class",
                                      )
    vParserPull.add_argument(
        dest="vObject",
        metavar="mo_or_class",
        help="path to managed object (mo) or class")

    vArgs = vParser.parse_args()

    print("*" * 80)
    # Check for compulsory option combinations

    vCommandAction = vArgs.commandAction.upper()

    # Check if APIC IP or FQDN has been passed
    if vArgs.vApicIpOrFqdn == None:
        vPrompt = str(
            "Input IP addresss or FQDN for APIC. Be accurate, no error checking performed:")
        vApicIpOrFqdn = raw_input(vPrompt)
    else:
        vApicIpOrFqdn = vArgs.vApicIpOrFqdn

    if vArgs.vEnteredPassword == None:
        vPrompt = str("Input Password for " + vUser +
                      " at APIC " + vApicIpOrFqdn + ": ")
        vPassword = getpass.getpass(vPrompt)
    else:
        vPassword = vArgs.vEnteredPassword

    """
        Set logging output level
        use DEBUG if you need to see more details
        use INFO for less details
        NOTE - some logging is commented out in code any way as too much output
        - but you can uncomment if piping to file
    """
    if vArgs.vDebugLevel == 1:
        logging.basicConfig(level=logging.INFO)
    elif vArgs.vDebugLevel > 1:
        logging.basicConfig(level=logging.DEBUG)
    #

    # instance of tools
    tls = tools()

    # Check APIC contactable
    requests.packages.urllib3.disable_warnings()
    vAciSession = Session(ipOrFqdn=vApicIpOrFqdn, uid=vUser,
                          pwd=vPassword, verify_ssl=False)
    logging.info("\n*** Checking APIC connection / login- " +
                 str(vAciSession.login()) + "\n\n")

    # check Action parameter
    if vCommandAction == "PUSH":
        # this PUSH section should be rewritten to be recursive within
        # directories and within files
        print("Pushing " + vArgs.vPath)
        if os.path.isfile(vArgs.vPath):
            print("Processing File:" + vArgs.vPath)
            fList = [os.path.basename(vArgs.vPath)]
            vPath = os.path.dirname(vArgs.vPath)
            logging.debug("\n**** " + str(fList) + "\n\n")
        elif os.path.isdir(vArgs.vPath):
            print("Processing Directory:" + vArgs.vPath)
            # get dir listing
            fList = tls.getFileList(vArgs.vPath)
            vPath = vArgs.vPath
            logging.debug("\n**** " + str(fList) + "\n\n")

        else:
            print("Invalid path: " + vArgs.vPath +
                  " is neither a file or a directory")
            exit()

        # Set flag to see if there are any push failures
        vPushSuccess = True
        # get JSON from each file and send to APIC
        for vF in fList:
            vFile = os.path.join(vPath, vF)
            jsonData = tls.readJSON(vFile)
            print("--- Processing File:" + vF)

            # large output
            logging.debug("\n*** jsonData\n" + str(jsonData) + "\n\n")

            if "imdata" in jsonData:
                for vObj in jsonData["imdata"]:
                    vPushSuccess = vPushSuccess and tls.aciPusher(
                        vObj, vAciSession)
                # Next vObj
            else:
                vPushSuccess = vPushSuccess and tls.aciPusher(
                    jsonData, vAciSession)
        # Next vF

        if vPushSuccess:
            print("Done.. ")
        else:
            print("Errors encountered while pushing. Check output")

    elif vCommandAction == "PULL":
        # Needs logic added here to determine if requested object is a mo or a class
        # eg  pull /api/node/class//dhcpClient fails
        baseUrl = "/api"
        # If user omitted leading /, add one for them
        if vArgs.vObject[1:1] != "/":
            urlstr = baseUrl + "/" + vArgs.vObject

        else:
            urlstr = baseUrl + vArgs.vObject

        logging.debug("\n*** Getting: " + (urlstr) + "\n\n")
        vAciSession.get(urlstr)

    else:  # Never reached because argparse catches error
        print("Action (PUSH or PULL) must be specified")
        exit()


if __name__ == '__main__':
    main()
