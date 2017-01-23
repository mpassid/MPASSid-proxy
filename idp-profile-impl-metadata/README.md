# Shibboleth IdP v3: Metadata resolver extensions

## Overview

This module implements some metadata resolution extensions for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home).

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-profile-impl-metadata
mvn package
```

After successful compilation, the _target_ directory contains _idp-profile-impl-metadata-\<version\>-bin_
subdirectory.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-profile-impl-metadata-<version>-bin/idp-profile-impl-metadata-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

TODO: configuration documentation.
