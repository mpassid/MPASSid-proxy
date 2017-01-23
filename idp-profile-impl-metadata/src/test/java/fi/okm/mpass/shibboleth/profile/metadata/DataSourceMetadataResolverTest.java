/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fi.okm.mpass.shibboleth.profile.metadata;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Iterator;

import org.opensaml.core.OpenSAMLInitBaseTestCase;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.context.support.GenericApplicationContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.ext.spring.config.IdentifiableBeanPostProcessor;
import net.shibboleth.ext.spring.util.SchemaTypeAwareXMLBeanDefinitionReader;
import net.shibboleth.idp.saml.metadata.RelyingPartyMetadataProvider;
import net.shibboleth.idp.testing.DatabaseTestingSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

/**
 * Unit tests for {@link DataSourceMetadataResolver}.
 */
public class DataSourceMetadataResolverTest extends OpenSAMLInitBaseTestCase {
    
    public static final String BASE_PATH_BEANS = "/fi/okm/mpass/shibboleth/profile/metadata";
    public static final String BASE_PATH_STORAGE = "/fi/okm/mpass/shibboleth/storage";
    
    DataSourceMetadataResolver resolver;
    
    String entityId;
    String acsUrl;
    
    @BeforeMethod
    public void initTests() throws Exception {
        entityId = "https://www.example.org/entity";
        acsUrl = "https://www.example.org/acs";
        resolver = initialize();
        Assert.assertEquals(resolver.getId(), "dataSourceEntity");
        DatabaseTestingSupport.InitializeDataSource(BASE_PATH_STORAGE + "/ServiceStore.sql", resolver.getDataSource());
    }

    @AfterMethod
    public void tearDown() throws Exception {
        Assert.assertTrue(resolver.isFailFastInitialization());
        Assert.assertTrue(resolver.isRequireValidMetadata());
        DatabaseTestingSupport.InitializeDataSource(BASE_PATH_STORAGE + "/DeleteStore.sql", resolver.getDataSource());        
    }
    
    public static DataSourceMetadataResolver initialize() throws Exception {
        DataSourceMetadataResolverTest test = new DataSourceMetadataResolverTest();
        return test.getResolver();
    }
    
    public DataSourceMetadataResolver getResolver() throws Exception {
        GenericApplicationContext context = new GenericApplicationContext();
        context.getBeanFactory().addBeanPostProcessor(new IdentifiableBeanPostProcessor());
        return getBean(BASE_PATH_BEANS + "/dataSourceEntity.xml", DataSourceMetadataResolver.class, context, false);
    }

    @Test
    public void testNoServices() throws Exception {
        final Iterator<EntityDescriptor> entities = resolver.resolve(criteriaFor(entityId)).iterator();
        Assert.assertFalse(entities.hasNext());
    }

    @Test
    public void testOneService() throws Exception {
        insertService(resolver, entityId, acsUrl);
        assertExpected(resolver.resolve(criteriaFor(entityId)).iterator(), 1, new String[] { entityId }, new String[] { acsUrl });
        assertExpected(resolver.resolve(new CriteriaSet()).iterator(), 1, new String[] { entityId }, new String[] { acsUrl });
    }

    @Test
    public void testTwoServices() throws Exception {
        final String entityId2 = entityId + "2";
        final String acsUrl2 = acsUrl + "2";
        insertService(resolver, entityId, acsUrl);
        insertService(resolver, entityId2, acsUrl2);
        assertExpected(resolver.resolve(criteriaFor(entityId)).iterator(), 1, new String[] { entityId }, new String[] { acsUrl });
        assertExpected(resolver.resolve(new CriteriaSet()).iterator(), 2, new String[] { entityId, entityId2 }, new String[] { acsUrl, acsUrl2 });
    }
    
    @SuppressWarnings("unchecked")
    protected <Type> Type getBean(String fileName, Class<Type> claz, GenericApplicationContext context,
            boolean supressValid) {
        context.setDisplayName("ApplicationContext: " + claz);
        loadFile(fileName, context, supressValid);
        context.refresh();
        return (Type)((RelyingPartyMetadataProvider) context.getBean("dataSourceEntity")).getEmbeddedResolver();
    }
    
    private void loadFile(String fileName, GenericApplicationContext context, boolean supressValid) {
        SchemaTypeAwareXMLBeanDefinitionReader beanDefinitionReader =
                new SchemaTypeAwareXMLBeanDefinitionReader(context);

        if (supressValid) {
           beanDefinitionReader.setValidating(false);
        }
        beanDefinitionReader.loadBeanDefinitions(fileName, BASE_PATH_BEANS + "/beans.xml");
    }

    protected void insertService(final DataSourceMetadataResolver resolver, final String entityId, final String acsUrl) throws Exception {
        final String insertResult = "INSERT INTO mpass_services" +
                " (samlEntityId, samlAcsUrl, startTime) VALUES (?,?,?)";
        try (final Connection conn = resolver.getDataSource().getConnection()) {
            final PreparedStatement statement = conn.prepareStatement(insertResult, Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, entityId);
            statement.setString(2,  acsUrl);
            statement.setTimestamp(3, new Timestamp(System.currentTimeMillis()));
            statement.executeUpdate();
        } catch (Exception e) {
            throw e;
        }
        resolver.refresh();
    }
    
    protected void assertEquals(final EntityDescriptor descriptor, final String entityId, final String acsUrl) {
        Assert.assertEquals(descriptor.getEntityID(), entityId);
        final AssertionConsumerService acs = descriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAssertionConsumerServices().get(0);
        Assert.assertEquals(acs.getLocation(), acsUrl);
        Assert.assertEquals(acs.getBinding(), SAMLConstants.SAML2_POST_BINDING_URI);
    }
    
    protected void assertExpected(final Iterator<EntityDescriptor> entities, int size, String[] entityIds, String[] acsUrls) {
        for (int i = 0; i < size; i++) {
            Assert.assertTrue(entities.hasNext());
            final EntityDescriptor entity = entities.next();
            assertEquals(entity, entityIds[i], acsUrls[i]);
        }
        Assert.assertFalse(entities.hasNext());
    }
    
    static public CriteriaSet criteriaFor(String entityId) {
        EntityIdCriterion criterion = new EntityIdCriterion(entityId);
        return new CriteriaSet(criterion);
    }
}
