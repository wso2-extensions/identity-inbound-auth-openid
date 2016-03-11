/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

public class OIDCSessionConstants {

    public static final String OPBS_COOKIE_ID = "opbs";

    // Request Parameters
    public static final String OIDC_CLIENT_ID_PARAM = "client_id";
    public static final String OIDC_SESSION_STATE_PARAM = "session_state";
    public static final String OIDC_LOGOUT_CONSENT_PARAM = "consent";

    public static class OIDCConfigElements {
        public static final String OIDC_LOGOUT_CONSENT_PAGE_URL = "OIDCLogoutConsentPage";
        public static final String OIDC_LOGOUT_PAGE_URL = "OIDCLogoutPage";
    }

    public static class OIDCEndpoints {
        public static final String OIDC_SESSION_IFRAME_ENDPOINT = "/oidc/check_session_iframe";
        public static final String OIDC_LOGOUT_ENDPOINT = "/oidc/end_session_endpoint";
    }

    private OIDCSessionConstants() {
    }
}
