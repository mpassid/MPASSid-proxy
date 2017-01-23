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

import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.sql.DataSource;

import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.RefreshableMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import com.google.common.base.Strings;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A {@link MetadataResolver} implementation that reads the minimal SAML entity configurations from a data source.
 */
public class DataSourceMetadataResolver extends AbstractReloadingMetadataResolver
    implements MetadataResolver, RefreshableMetadataResolver {
    
    /** The database table name for the service providers. */
    public static final String TABLE_NAME_SERVICES = "mpass_services";
    
    /** The column name for the SAML entity ID. */
    public static final String COLUMN_ID_ENTITY_ID = "samlEntityId";
    
    /** The column name for the SAML (POST-binding) assertion consumer service URL. */
    public static final String COLUMN_ID_ACS_URL = "samlAcsUrl";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(DataSourceMetadataResolver.class);
    
    /** The data source for the trusted SAML entity configuration. */
    @Nonnull private DataSource dataSource;
    
    /**
     * Constructor.
     * @param source The data source for the trusted SAML entity configuration.
     */
    public DataSourceMetadataResolver(final DataSource source) {
        super();
        setDataSource(source);
    }
    
    /**
     * Constructor.
     * @param backgroundTaskTimer The timer used to schedule background refresh tasks.
     * @param source The data source for the trusted SAML entity configuration.
     */
    public DataSourceMetadataResolver(@Nullable final Timer backgroundTaskTimer, final DataSource source) {
        super(backgroundTaskTimer);
        setDataSource(source);
    }
    
    /**
     * Set the data source for the trusted SAML entity configuration.
     * @param source What to set.
     */
    public void setDataSource(final DataSource source) {
        dataSource = Constraint.isNotNull(source, "The data source cannot be null!");
    }
    
    /**
     * Get the data source for the trusted SAML entity configuration.
     * @return The data source for the trusted SAML entity configuration.
     */
    public DataSource getDataSource() {
        return dataSource;
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<EntityDescriptor> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        
        //TODO add filtering for entity role, protocol? maybe
        //TODO add filtering for binding? probably not, belongs better in RoleDescriptorResolver
        
        EntityIdCriterion entityIdCriterion = criteria.get(EntityIdCriterion.class);
        if (entityIdCriterion == null || Strings.isNullOrEmpty(entityIdCriterion.getEntityId())) {
            List<EntityDescriptor> descriptors = getBackingStore().getOrderedDescriptors();
            if (descriptors != null) {
                return new ArrayList<>(descriptors);
            } else {
                return Collections.emptyList();
            }
        }        
        return lookupEntityID(entityIdCriterion.getEntityId());
    }
    
    /** {@inheritDoc} */
    @Override
    public EntityDescriptor resolveSingle(CriteriaSet criteria) throws ResolverException {
        return super.resolveSingle(criteria);
    }

    /** {@inheritDoc} */
    @Override
    protected String getMetadataIdentifier() {
        return getId();
    }

    /** {@inheritDoc} */
    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        log.trace("Start fetching metadata");
        final EntitiesDescriptor entities = new EntitiesDescriptorBuilder().buildObject();
        try (final Connection connection = getDataSource().getConnection()) {
            ResultSet results = connection.prepareStatement("SELECT * from " + TABLE_NAME_SERVICES).executeQuery();
            //TODO filter out the ones with a value in end-timestamp
            //TODO support multiple ACS endpoints
            while (results.next()) {
                final EntityDescriptor entity = new EntityDescriptorBuilder().buildObject();
                final String entityId = results.getString(COLUMN_ID_ENTITY_ID);
                entity.setEntityID(entityId);
                final SPSSODescriptor descriptor = new SPSSODescriptorBuilder().buildObject();
                descriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
                final AssertionConsumerService acs = new AssertionConsumerServiceBuilder().buildObject();
                acs.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
                acs.setLocation(results.getString(COLUMN_ID_ACS_URL));
                acs.setIndex(1);
                acs.setIsDefault(true);
                descriptor.getAssertionConsumerServices().add(acs);
                entity.getRoleDescriptors().add(descriptor);
                entities.getEntityDescriptors().add(entity);
                log.debug("Added one entity descriptor for {}", entityId);
            }
        } catch (SQLException e) {
            log.error("Could not fetch the services from the database", e);
            return null;
        }
        final Marshaller marshaller = XMLObjectSupport.getMarshaller(entities);
        try {
            final Element element = marshaller.marshall(entities);
            return getContents(element);
        } catch (MarshallingException | UnsupportedEncodingException e) {
            log.error("Could not marshall EntitiesDescriptor", e);
        }
        return null;
    }

    /**
     * Get the contents for the given element as UTF-16 encoded byte array.
     * @param element The element.
     * @return The contents of the element as byte array.
     * @throws UnsupportedEncodingException If UTF-16 encoding is not supported by the platform.
     */
    protected byte[] getContents(final Element element) throws UnsupportedEncodingException {
        final Document document = element.getOwnerDocument();
        final DOMImplementationLS domImplLs = (DOMImplementationLS) document.getImplementation();
        final LSSerializer serializer = domImplLs.createLSSerializer();
        final String str = serializer.writeToString(element);
        log.trace("Built the following element from the contents of the database: {}", str);
        return str.getBytes("UTF-16");
    }
}