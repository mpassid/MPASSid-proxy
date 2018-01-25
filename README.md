# MPASS-proxy

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/Digipalvelutehdas/MPASSid-proxy.svg?branch=master)](https://travis-ci.org/Digipalvelutehdas/MPASSid-proxy)
[![Coverage Status](https://coveralls.io/repos/github/Digipalvelutehdas/MPASSid-proxy/badge.svg?branch=master)](https://coveralls.io/github/Digipalvelutehdas/MPASSid-proxy?branch=master)

MPASS-proxy consists of several modules for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home), providing
extensions for authentication, attribute resolution and audit logging. They can be used individually, but together they provide an open source 
implementation for the [ECA Authentication](http://docs.educloudalliance.org/en/latest/auth/index.html) standard's
[Auth proxy](http://docs.educloudalliance.org/en/latest/auth/proxy/index.html) component. The standard is specified by the 
[EduCloud Alliance](https://portal.educloudalliance.org/).

For more information about the MPASS project, see http://www.mpass.id/.

## Module descriptions

- _idp-attribute-impl-authnid_: AuthnID -calculation implementation as specified by the ECA Auth standard.
- _idp-attribute-impl-ecadata_: ECA Auth Data -connection implementation.
- _idp-authn-api-discovery_: Interface module for authentication flow selection.
- _idp-authn-api-shibsp_: Interface module for integrating SAML-based auth sources.
- _idp-authn-api-socialuser_: Interface module for integrating OAuth2/OIDC-based auth sources.
- _idp-authn-api-wilma_: Interface module for integrating Wilma auth sources.
- _idp-authn-impl-discovery_: Implementation module for authentication flow selection.
- _idp-authn-impl-jwt_: Implementation module for integrating (Opinsys/Peda.net) JWT auth sources.
- _idp-authn-impl-shibsp_: Implementation module for integrating SAML-based auth sources.
- _idp-authn-impl-socialuser_: Implementation module for integrating OAuth2/OIDC-based auth sources.
- _idp-authn-impl-wilma_: Implementation module for integrating Wilma auth sources.
- _idp-mpass-monitor-api_: Interface module for integrated SSO sequence monitoring.
- _idp-mpass-monitor-impl_: Implementation module for integrated SSO sequence monitoring.
- _idp-mpass-parent_: Parent module containing for instance version management for the libraries.
- _idp-mpass-rest-api_: Interface module for metadata API.
- _idp-mpass-rest-impl_: Implementation module for metadata API.
- _idp-profile-impl-audit_: Some extensions for audit logging.
- _idp-profile-impl-metadata_: Some extensions for metadata resolution.

## Prerequisities and build instructions

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
cd idp-mpass-parent
mvn package
```

The command compiles all the source code and builds a JAR-package for each module (see _target/_ directories).

## License

The MIT License
Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi

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
