# Shibboleth IdP Authn Flow Discovery

## Overview

This module constains interface classes for [idp-authn-impl-discovery](../idp-authn-impl-discovery). These two
modules can be used for implementing a simple authentication method selection flow for
[Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](..) -module in the Maven repository or in the relative path _../_.

```
cd idp-authn-impl-discovery
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-api-discovery-\<version\>.jar_.

## Deployment

After compilation, the _target/idp-authn-api-discovery-\<version\>.jar_ must be deployed to the IdP Web
application. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-authn-api-discovery-VERSION.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.