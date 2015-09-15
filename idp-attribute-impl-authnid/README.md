# ECA AuthnID calculator

## Overview

This module is a [Data Connector](https://wiki.shibboleth.net/confluence/display/IDP30/Attribute+Resolver)
plugin for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home). It
implements AuthnID-calculation part for the ECA Auth Proxy -module, as defined in [EduCloud Alliance's]
(https://portal.educloudalliance.org/) [ECA Authentication]
(https://github.com/educloudalliance/eca-docs/blob/master/auth/index.rst) standard. In short, this module can
be used for calculating a unique privacy-preserving identifier for the authenticated principals.

## Prequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-attribute-impl-authnid
mvn package
```

After successful compilation, the _target_ directory contains _idp-attribute-impl-authnid-\<version\>.jar_ and
_idp-attribute-impl-authnid-\<version\>-tests.jar_.

## Deployment

After compilation, the _target/idp-attribute-impl-authnid-\<version\>.jar_ must be deployed to the IdP Web
application. Depending on the IdP installation, the module deployment may be achieved for instance with the
following sequence:

```
cp target/idp-attribute-impl-authnid-1.0-SNAPSHOT.jar /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.


## Configuration

### XML-namespace settings

In addition to the existing ones, the _attribute-resolver.xml_ must contain the following XML-namespace
declarations to activate the module:

```
xmlns:ecaid="fi.okm.mpass.shibboleth.attribute.dc.authnid"
xsi:schemaLocation="fi.okm.mpass.shibboleth.attribute.dc.authnid classpath:/eca-authnid-connector.xsd
```

The following configuration attributes are available for the _DataConnector_ itself:

- _srcAttributeNames_: Comma-separated list of attribute names to be used for calculating the authnID.
- _destAttributeName_: The destination attribute name where to set the calculated authnID.
- _prefixSalt_ (optional): The prefix salt to be used before calculating the authnID.
- _postfixSalt_ (optional): The postfix salt to be appended before calculating the authnID.
- _minInputLength_ (optional): The minimum length for the unsalted input before calculating the authnID. Default 10.
- _skipCalculation_ (optional): Comma-separated list of 'attribute_name'='attribute_value' pairs for skipping the authnID calculation.
- _skipCalculationSrc_ (optional): The source attribute used as a destination attribute if the authnID calculation has been skipped (see _skipCalculation_).

An example snippet of minimal configuration in _attribute-resolver.xml_, which uses _uid_ attribute as source
and calculates the result to SAML attribute with friendly name _authnId_:

```
<resolver:AttributeDefinition id="authnid" xsi:type="ad:Simple">
    <resolver:Dependency ref="calculateAuthnId" />
    <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:TODO:namespace:authnID" friendlyName="authnid" encodeType="false" />
</resolver:AttributeDefinition>

<resolver:DataConnector id="calculateAuthnId" xsi:type="ecaid:AuthnIdDataConnector" srcAttributeNames="uid" destAttributeName="authnid">
    <resolver:Dependency ref="uid" />
</resolver:DataConnector>
```


