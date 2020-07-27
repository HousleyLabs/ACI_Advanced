"""
Comments:
Developed by Housley Communications - Tony Condran
Sept 2019

The Housley ACI Audit Script:
- Queries the APIC based on an audit_list in a specified json config file
- Saves the matching objects for each item in the list into json files in a subdirectory
"""

import os, json, requests, getpass

##### Variables #####
"""
These variables could be passed via the Command line
Using the argparse library - https://docs.python.org/3/library/argparse.html

If the password is set to "PROMPT" the user will be prompted to enter a secure password
"""


addr = "replace_with_apic_hostname/ip"
user = "username"
passwd = "PROMPT"

vFile = "./audit.json"
Output_Dir = "./data"



class Session(object):
    def __init__(self, ipaddr, uid, pwd, verify_ssl=False):
        self.ipaddr = ipaddr
        self.uid = uid
        self.pwd = pwd
        self.api = 'http://' + self.ipaddr
        # self.api = 'https://' + self.ipaddr + ":443"
        self.session = None
        self.verify_ssl = verify_ssl
        self.obj="/api/mo/uni.json"


    def login(self):
        """Login into APIC"""
        print('Connecting to the APIC')
        login_obj = self.api + '/api/aaaLogin.json'
        name_pwd = {'aaaUser': {'attributes': {'name': self.uid, 'pwd': self.pwd}}}
        vCred = json.dumps(name_pwd)
        self.session = requests.Session()
        ret = self.session.post(login_obj, data=vCred, verify=self.verify_ssl)
        return ret


    def get(self,obj=None):
        """Perform a REST GET call to the APIC."""
        if obj == None:
            obj = self.obj

        get_obj = self.api + obj
        print("  Obj: " + get_obj)

        resp = self.session.get(get_obj)
        dict = json.loads(resp.text)
        return(dict)



class tools():
    def readJSON(self, filename):
        """Read the content of a json file and load it into python as a dictionary"""
        print("Reading Audit File: " + filename)
        try:
            with open(filename) as file:                                        # Open File
                jsondata = file.read()                                          # Read JSON Audit File
        except:
            print("Could open JSON file: " + filename)
            exit()

        try:
            dict = json.loads(jsondata)                                         # Try and load file content as json
            return(dict)

        except:
            print("Error importing JSON file data: " + filename)
            print("Format error")
            exit()


    def writeJSON(self, name="empty", content=""):
        """Write python Dictionary as json to a file"""
        filename = Output_Dir + "/" + name + ".json"                            # Filename to save output
        with open(filename, 'w') as outfile:                                    # Open a file
            json.dump(content, outfile)                                         # Save json to file


################################################################################


def main():
    print("\n#######################################")
    print("########## Housley ACI Audit ##########")
    print("#######################################")

    # Instance of tools
    tls = tools()


    ### Secure Password Entry ###
    if passwd == "PROMPT":                                                      # If Password Set to "PROMPT"
        vPrompt = str("Input Password for "+ user + " at APIC " + addr + ": ")
        password = getpass.getpass(vPrompt)                                     # Prompt user to enter secure password
    else:
        password = passwd                                                       # Else Use password supplied in file


    # Connect to APIC
    try:
        aci = Session(ipaddr=addr, uid=user, pwd=password, verify_ssl=False)    # Login to ACI and return the session
        print("Checking APIC connection / login- " + str(aci.login()))

    except:
        print("login failed")
        exit()


    # Read audit file
    jsonData = tls.readJSON(vFile)                                              # Read config file


    ### Create Output Directory ###
    if not os.path.exists(Output_Dir):                                          # If output directory doesnt exist
        os.mkdir(Output_Dir)                                                    # Create it


    ### Write Objects to directory ###
    for line in jsonData["audit_list"]:                                         # For every item in the json config
        if line.get("url") != None :                                            # Check line has a URL (not a comment line)
            print("\n### Getting name: " + line["name"] + " ###")
            resp = aci.get(line["url"])                                         # Get the output of the ACI query
            tls.writeJSON(name=line["name"], content=resp)                      # Save the Output to a file
            print("  Saved to " + Output_Dir + "/" + line["name"] + ".json")




if __name__ == '__main__':
    main()
