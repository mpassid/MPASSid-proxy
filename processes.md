# Processes 

This document describes automation processes used in MPASSid solution

# Municipalities
Integration at the municipality is in 99% of the cases about adding attribute source to MPASSid. Attribute source is from where MPASSid gets needed information about students and teachers. Normally attribute source is one of the following: Wilma, Helmi, AD or Azure AD. Collected attributes are: 
- ID
- First name
- Surname
- Municipality name
- School name
- Class (from students)
- Role information (student/teacher)


## Add new municipality (Wilma instance)
When municipality wants to take MPASSid into use and they have Wilma student management system, 
the following process happens: 
- Local Wilma is configured following the instructions of service provider Starsoft Ltd
- Municipality fills in form at https://kyyberi.typeform.com/to/H60CAI and provide following data: logo url, 
wilma instance url, contact email, municipality name. After submit, info is stored to TypeForm. 
- From there Zapier gets new entries and post the data to Digipalvelutehdas Slack 
channel #wilma-integrations (private channel). At the same time new instance information is posted to mpassid operator as email too. 
- MPASSid operator manually adds the provided new wilma instance in the trusted sources, creates login button for the municipality (using the icon provided), tests the connection with robot account if possible, then informs the readiness of integration to municipality given email address. 

## Add new municipality (AD instance)
TBD

## Add new municipality (Azure AD instance)
TBD 

# Services

## Add new service
TBD
