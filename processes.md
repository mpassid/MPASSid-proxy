#Processes 

This document describes automation processes used in MPASSid solution

## Register new Wilma instance
When municipality wants to take MPASSid into use and they have Wilma student management system, 
the following process happens: 
- Local Wilma is configured following the instructions of service provider Starsoft Ltd
- Municipality fills in form at https://kyyberi.typeform.com/to/H60CAI and provide following data: logo url, 
wilma instance url, contact email, municipality name
After submit, info is stored to TypeForm. 
- From there Zapier gets new entries and post the data to Digipalvelutehdas Slack 
channel #wilma-integrations. At the same time new instance information is posted to mpassid operator as email too. 
