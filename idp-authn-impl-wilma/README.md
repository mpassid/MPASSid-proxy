# Shibboleth IdP v3: Wilma Authentication

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home) that interacts with a Wilma instance. The
module can be used for outsourcing the authentication to a Wilma instance instead of for instance 
prompting and validating the user credentials locally.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-wilma
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-wilma-\<version\>.jar_.

## Deployment

TODO
