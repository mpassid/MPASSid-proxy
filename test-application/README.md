# MPASS test application

Vagrant box: Shibboleth Service Provider 2.x connected to MPASS-testing environment.

## Prereqs
* Virtualbox (or other vagrant compliant virtualization "engine")
* Vagrant (tested with 1.8.1)
* Ansible (tested with 1.9.4 and 2.0.0.1)

## This Vagrant box includes following packages / applications:
* CentOS 6.4
* Apache httpd 2.2
* Shibboleth Service Provider (SP) 2.5.x

## Usage

* Execute "vagrant up" and wait that the ansible run has completed, expected outcome:

```
PLAY RECAP *********************************************************************
app                        : ok=22   changed=17   unreachable=0    failed=0   
```

Open browser and navigate to the address "http://192.168.0.150/secure/"

This URL is secured with Shibboleth SP, so that will redirect you to MPASS test discovery page where you should select "Simulated LDAP school" as the authentication source.

You can use following users to test this setup:
* Student: u0000001 / u0000001pwd
* Teacher: o0010001 / o0010001pwd

After authentication you will be redirected back to http://192.168.0.150/secure/. During this redirection, your browser probably warns you about moving from https-domain to unsecure http-domain.

In the end, the final page is a simple PHP site which will show your environment variables and http headers. Those will include the MPASS-attributes corresponding to the authenticated user.

## License

The MIT License
Copyright (c) 2015-2016 CSC - IT Center for Science, http://www.csc.fi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
