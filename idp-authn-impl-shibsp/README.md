# Shibboleth IdP v3: Shibboleth SP authentication

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3]
(https://wiki.shibboleth.net/confluence/display/IDP30/Home) exploiting attributes provided by 
[Shibboleth Service Provider](https://shibboleth.net/products/service-provider.html). The module can be used
for outsourcing the authentication to another SAML IdP instead of prompting and validating the user
credentials itself.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- Currently [idp-mpass-parent](https://github.com/Digipalvelutehdas/MPASS-proxy/tree/master/idp-mpass-parent) -module in the Maven repository or in the relative path _../idp-mpass-parent_.

```
cd idp-authn-impl-shibsp
mvn package
```

After successful compilation, the _target_ directory contains _idp-authn-impl-shibsp-\<version\>-bin_
subdirectory.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
cp target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/flows/* /opt/shibboleth-idp/flows
cp target/idp-authn-impl-shibsp-<version>-bin/idp-authn-impl-shibsp-<version>/conf/* /opt/shibboleth-idp/conf/authn
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

## Configuration

The distribution package contains three different authentication flows: _authn/Shib_, _authn/ShibExample_ and _authn/ShibExternal_. The first
one is an abstract flow that contains general steps exploited by the other two flows. Typically, the deployer doesn't need to customize the
abstract flow or its beans.

### authn/ShibExample

This flow assumes that the URL location where the end-user is accessing the IDP is protected by Shibboleth SP. In other words, the
Shibboleth SP must be configured to provide the Apache environment and/or HTTP headers to the location. Typically the URL location
corresponds to the endpoint where Shibboleth IdP receives the incoming authentication request, for instance 
*https://idp.example.org/idp/profile/SAML2/Redirect/SSO*.

```
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      parent="authn/Shib">

    <view-state id="ExternalTransfer" view="externalRedirect:#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExample.externalAuthnPath')}&amp;forceAuthn=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isForceAuthn()}&amp;isPassive=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isPassive()}&amp;target=#{flowExecutionUrl}%26_eventId_proceed%3D1">
        <transition to="ValidateShibFlowAuthentication" />
    </view-state>
    
</flow>
```

The example above assumes that you have a bean called _shibboleth.authn.ShibExample.externalAuthnPath_ configured in the file 
_/opt/shibboleth-idp/conf/authn/shib-authn-config.xml_. The bean must contain the desired
[Shibboleth SP Handler](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPHandler) location and its parameters.

### authn/ShibExternal

In comparison to the previous flow, this flow is more flexible regarding the Shibboleth SP configuration. On the other hand, the
configuration requires some extra steps, explained below.

```
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      parent="authn/Shib">

    <view-state id="ExternalTransfer" view="externalRedirect:#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExternal.externalHandler')}&amp;forceAuthn=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isForceAuthn()}&amp;isPassive=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isPassive()}&amp;target=#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExternal.externalAuthServlet')}%3Fconversation=#{flowExecutionContext.getKey().toString()}">
        <on-render>
            <evaluate expression="opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).getSubcontext(T(net.shibboleth.idp.authn.context.ExternalAuthenticationContext), true).setFlowExecutionUrl(flowExecutionUrl + '&amp;_eventId_proceed=1')" />
            <evaluate expression="externalContext.getNativeRequest().getSession().setAttribute('conversation' + flowExecutionContext.getKey().toString(), new net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl(opensamlProfileRequestContext))" />
        </on-render>
        <transition to="ValidateShibExternalAuthentication" />
    </view-state>
    
</flow>
```

The example above assumes that you have a bean called _shibboleth.authn.ShibExternal.externalAuthnPath_ configured in the file 
_/opt/shibboleth-idp/conf/authn/shib-authn-config.xml_. The bean must contain the desired
[Shibboleth SP Handler](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPHandler) location and its parameters. Also, a bean
called _shibboleth.authn.ShibExternal.externalAuthServlet_ must be configured in the same file, and it must correspond to the location
of the _fi.okm.mpass.shibboleth.authn.impl.ShibbolethSpAuthnServlet_ servlet.

```
...
    <bean id="shibboleth.authn.ShibExternal.externalHandler" class="java.lang.String"
        c:_0="https://idp.example.org/override/Shibboleth.sso/Login?entityID=https://idp2.example.org/idp/shibboleth" />

    <bean id="shibboleth.authn.ShibExternal.externalAuthServlet" class="java.lang.String"
        c:_0="https://idp.example.org/idp/Authn/ShibExternal" />
...
```


The servlet is configured in the *web.xml* (usually _/opt/shibboleth-idp/edit-webapp/WEB-INF/web.xml_).

```
...
    <servlet>
        <servlet-name>ShibbolethSpAuthnServlet</servlet-name>
        <servlet-class>fi.okm.mpass.shibboleth.authn.impl.ShibbolethSpAuthnServlet</servlet-class>
        <load-on-startup>2</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>ShibbolethSpAuthnServlet</servlet-name>
        <url-pattern>/Authn/ShibExternal</url-pattern>
    </servlet-mapping>
...
```


It should be noted that with the _authn/ShibExternal_ flow, it is possible to configure multiple flows with different SP Handler 
configurations, by using [ApplicationOverride](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApplicationOverride).

Finally, you will need to add the new authentication flow definition(s) to _/opt/shibboleth-idp/conf/authn/general-authn.xml_:

```
<bean id="authn/ShibExample" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```

The flow definition must also be enabled via _idp.authn.flows_ variable in _/opt/shibboleth-idp/conf/idp.properties_.