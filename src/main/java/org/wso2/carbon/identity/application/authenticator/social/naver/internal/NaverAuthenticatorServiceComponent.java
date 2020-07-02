package org.wso2.carbon.identity.application.authenticator.social.naver.internal;

import java.util.Hashtable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.social.naver.NaverCustomAuthenticator;

@Component(name = "NaverAuthenticatorServiceComponent",
immediate = true)
public class NaverAuthenticatorServiceComponent{

	private static final Log LOGGER = LogFactory.getLog(NaverAuthenticatorServiceComponent.class);

	@Activate
 protected void activate(ComponentContext ctxt) {
        try {
        	NaverCustomAuthenticator naverAuthenticator = new NaverCustomAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),naverAuthenticator, props);
            LOGGER.info("----Naver Authenticator bundle is activated----");
  
        } catch (Throwable e) {
            LOGGER.fatal("----Error while activating Naver authenticator----", e);
        }
    }
  
	@Deactivate
	protected void deactivate(ComponentContext ctxt) {
        LOGGER.info("----Naver Authenticator bundle is deactivated----");
    }

}
