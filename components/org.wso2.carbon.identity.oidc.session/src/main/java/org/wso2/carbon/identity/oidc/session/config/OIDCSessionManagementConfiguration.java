package org.wso2.carbon.identity.oidc.session.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.utils.CarbonUtils;

import javax.xml.namespace.QName;

/**
 * This class loads configurations with regard the OIDC session management from repository/conf/identity/identity.xml
 */
public class OIDCSessionManagementConfiguration {

    private static final Log log = LogFactory.getLog(OIDCSessionManagementConfiguration.class);

    private static OIDCSessionManagementConfiguration instance;

    private String oidcLogoutConsentPageUrl = null;
    private String oidcLogoutPageUrl = null;

    private static final String CONFIG_ELEM_OAUTH = "OAuth";

    private OIDCSessionManagementConfiguration() {
        buildConfiguration();
    }

    /**
     * Returns the singleton instance of OIDCSessionManagementConfiguration
     *
     * @return OIDCSessionManagementConfiguration instance
     */
    public static OIDCSessionManagementConfiguration getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (OIDCSessionManagementConfiguration.class) {
                if (instance == null) {
                    instance = new OIDCSessionManagementConfiguration();
                }
            }
        }
        return instance;
    }

    /**
     * Returns configured OIDC Logout Consent page URL
     *
     * @return OIDC Logout Consent page URL
     */
    public String getOIDCLogoutConsentPageUrl() {
        return oidcLogoutConsentPageUrl;
    }

    /**
     * Returns configured OIDC Logout page URL
     *
     * @return OIDC Logout page URL
     */
    public String getOIDCLogoutPageUrl() {
        return oidcLogoutPageUrl;
    }

    private void buildConfiguration() {
        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthConfigElement = configParser.getConfigElement(CONFIG_ELEM_OAUTH);

        if (oauthConfigElement == null) {
            log.warn("Error in OAuth Configuration. OAuth element is not available");
            return;
        }

        OMElement element = oauthConfigElement.getFirstChildWithName(getQNameWithIdentityNS(
                OIDCSessionConstants.OIDCConfigElements.OIDC_LOGOUT_CONSENT_PAGE_URL));
        if (element != null) {
            if (StringUtils.isNotBlank(element.getText())) {
                oidcLogoutConsentPageUrl = IdentityUtil.fillURLPlaceholders(element.getText());
            }
        }

        element = oauthConfigElement.getFirstChildWithName(getQNameWithIdentityNS(
                OIDCSessionConstants.OIDCConfigElements.OIDC_LOGOUT_PAGE_URL));
        if (element != null) {
            if (StringUtils.isNotBlank(element.getText())) {
                oidcLogoutPageUrl = IdentityUtil.fillURLPlaceholders(element.getText());
            }
        }
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }
}
