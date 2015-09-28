# Shibboleth IdP Social User authentication extensions

## Overview

This module contains implementations of Facebook, Google, LinkedIn and Twitter user authentications for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Prequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-socialuser
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-socialuser-\<version\>.jar_ and some assemblies.

## Deployment

After compilation, the _target/idp-authn-api-socialuser-\<version\>.jar_ must be deployed to the IdP Web application and it must be configured. Depending on the IdP installation, the module deployment may be achieved for instance with the following sequence:

```
cp target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib/.
cd /opt/shibboleth-idp
sh bin/build.sh
cp -r target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/conf /opt/shibboleth-idp/conf
cp -r target/idp-authn-impl-socialuser-\<version\>-bin/idp-authn-impl-socialuser-\<version\>/flows /opt/shibboleth-idp/flows
```

The second final command will rebuild the _war_-package for the IdP application.

- You will need to define the OAUTH1/OAUTH2 parameters for the applied authentication methods to beans defined in /opt/shibboleth-idp/flows/authn/SocialUser/socialuser-authn-beans.xml 
- You will need to add the applied authentication methods to /opt/shibboleth-idp/conf/authn/general-authn.xml
- /opt/shibboleth-idp/conf/attribute-resolver-social.xml has example attribute definitions