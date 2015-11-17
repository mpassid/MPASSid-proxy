# MPASS -kirjautumisjärjestelmän toteutus: Proxy

## Yleiskuvaus

Tämä toteutus koostuu useista [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home)
arkkitehtuurin päälle toteutetuista moduuleista, jotka muodostavat toteutuksen [EduCloud Alliancen](https://portal.educloudalliance.org/)
määrittelemän [ECA Authentication](https://github.com/educloudalliance/eca-docs/blob/master/auth/index.rst) -standardin Proxy-komponentille.


## Moduulien kuvaus

- _idp-attribute-impl-authnid_: ECA Auth standardin mukainen AuthID-laskentatoteutus
- _idp-attribute-impl-ecadata_: ECA Auth standardin mukainen yhteys Data-moduuliin
- _idp-authn-api-shibsp_: SAML-pohjaisten tunnistusvälineiden integraation rajapintamääritykset
- _idp-authn-api-socialuser_: Sosiaalisen median tunnistusvälineiden adaptereiden rajapintamääritykset
- _idp-authn-impl-shibsp_: SAML-pohjaisten tunnistusvälineiden integraation toteutus
- _idp-authn-impl-socialuser_: Sosiaalisen median tunnistusvälineiden adaptereiden toteutus
- _idp-mpass-parent_: Moduulien käyttämien kirjastojen versiomäärittelyt jne
- _idp-profile-impl-audit_: Laajennoksia audit-lokitukseen

## Esivaatimukset ja kääntöohjeet

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
cd idp-mpass-parent
mvn package
```

Komento kääntää jokaisen moduulin lähdekoodin ja paketoi modulien _target/_ -hakemistoihin _jar-paketin_.

## Lisenssi / License

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