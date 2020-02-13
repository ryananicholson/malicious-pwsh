#!/usr/bin/env python3
#
# Description:  Proof of concept using freq.py to find obfuscated PowerShell 
#               commands in the Microsoft-Windows-PowerShell/Operational 
#               event log (in .evtx format).
# Author:       Ryan Nicholson (@ryananicholson | https://www.ryanic.com)
# Inspired by:  DeepBlueCLI by Eric Conrad, Backshore Communications, LLC.
#               https://github.com/sans-blue-team/DeepBlueCLI
# Requirements: pip3 install -r requirements.txt
# Usage:        python3 malicious-pwsh.py <file.evtx>
#

import Evtx.Evtx as evtx
import sys
import subprocess 
import xmltodict

def main():

    if (len(sys.argv) != 2):
        print("\033[31m[-]\033[0m Invalid number of arguments!")
        print("    \033[33mpython3 malicious-pwsh.py <file.evtx>\033[0m")
        exit(1)

    print("\033[32mConverting " + sys.argv[1] + " to XML... \033[0m")
    # Partial code from evtx_dump.py
    with evtx.Evtx(sys.argv[1]) as log:
        xmlevents = "<Events>"
        for record in log.records():
            xmlevents += (record.xml())
        xmlevents += "</Events>"

    print("\033[32mRunning freq.py... \033[0m")
    dictevents = xmltodict.parse(xmlevents)
    for event in dictevents['Events']['Event']:
        if event['System']['EventID']['#text'] == "4103":
            eventdata = (event['EventData']['Data'][0]['#text'])
            score = subprocess.check_output("./freq.py -m \"" + eventdata + "\" english_mixedcase.freq", shell=True)
            if (float(score) < 5.0):
                print("\033[31m[-]\033[0m Likely obfuscated PowerShell!")
                print("    Freq.py score: \033[31m" + score.decode("utf-8") + "\033[0m")
                if len(eventdata) > 300:
                    eventdata = eventdata[0:299] + "..."
                print(eventdata + "\n")

if __name__ == "__main__":
    main()
