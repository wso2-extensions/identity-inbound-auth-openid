package org.wso2.carbon.identity.oidc.session.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class OIDCSessionIFrameServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(OIDCSessionIFrameServlet.class);

    private static final String CLIENT_ORIGIN_PLACE_HOLDER = "CLIENT_ORIGIN";
    private static final String ERROR_RESPONSE = "<html><body>Invalid OP IFrame Request</body></html>";

    private static final String OP_IFRAME_RESOURCE = "op_iframe.html";

    private static StringBuilder opIFrame = null;

    @Override
    public void init() throws ServletException {
        loadOPIFrame();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.setContentType("text/html");

        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);
        if (StringUtils.isBlank(clientId)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid request.\'client_id\' not found in request as parameter");
            }
            response.getWriter().print(ERROR_RESPONSE);
        } else {
            try {
                OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
                OAuthAppDO oAuthAppDO = oAuthAppDAO.getAppInformation(clientId);

                String clientOrigin = OIDCSessionManagementUtil.getOrigin(oAuthAppDO.getCallbackUrl());
                response.getWriter().print(getOPIFrame(clientOrigin));
            } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving OAuth application information for the provided client id", e);
                }
                response.getWriter().print(ERROR_RESPONSE);
            }
        }

    }

    private String getOPIFrame(String clientOrigin) {
        Map<String, Object> valuesMap = new HashMap<>();
        valuesMap.put(CLIENT_ORIGIN_PLACE_HOLDER, clientOrigin);

        StrSubstitutor substitutor = new StrSubstitutor(valuesMap);
        return substitutor.replace(opIFrame.toString());
    }

    private void loadOPIFrame() {
        opIFrame = new StringBuilder();

        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(OP_IFRAME_RESOURCE)) {
            int i;
            while ((i = inputStream.read()) > 0) {
                opIFrame.append((char) i);
            }

        } catch (IOException e) {
            log.error("Failed to load OP IFrame", e);
        }
    }
}
