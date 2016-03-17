package fi.okm.mpass.shibboleth.authn.principal.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Unit testing for {@link ShibHeaderPrincipal}.
 */
public class ShibHeaderPrincipalTest extends KeyValuePrincipalTest {
    
    @Override @BeforeTest @Test
    public void initTests() {
        super.initTests();
        principalClass = ShibHeaderPrincipal.class;
    }
    
    @Test
    public void testClone() throws Exception {
        super.assertKeyAndValue(new ShibHeaderPrincipal(key, value).clone());
    }
    
    @Test
    public void testEquals() throws Exception {
        ShibHeaderPrincipal principal1 = new ShibHeaderPrincipal(key, value);
        Object principal2 = new ShibHeaderPrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        Object principal3 = new ShibHeaderPrincipal(key + "mock", value);
        Object principal4 = new ShibHeaderPrincipal(key, "mock" + value);
        ShibAttributePrincipal principal5 = new ShibAttributePrincipal(key, value);
        Assert.assertTrue(principal1.equals(principal1));
        Assert.assertTrue(principal1.equals(principal2));
        Assert.assertFalse(principal1.equals(null));
        Assert.assertFalse(principal1.equals(principal3));
        Assert.assertFalse(principal1.equals(principal4));
        Assert.assertFalse(principal1.equals(principal5));
    }
    
    @Test
    public void testHash() throws Exception {
        ShibHeaderPrincipal principal1 = new ShibHeaderPrincipal(key, value);
        ShibHeaderPrincipal principal2 = new ShibHeaderPrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        ShibHeaderPrincipal principal3 = new ShibHeaderPrincipal(key, "mock" + value);
        Assert.assertEquals(principal1.hashCode(), principal2.hashCode());
        Assert.assertFalse(principal1.hashCode() == principal3.hashCode());
    }

    @Override
    public void initPrincipalClass() {
        principalClass = ShibHeaderPrincipal.class;
    }
}
