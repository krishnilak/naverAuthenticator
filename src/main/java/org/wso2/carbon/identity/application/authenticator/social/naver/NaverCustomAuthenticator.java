package org.wso2.carbon.identity.application.authenticator.social.naver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

public class NaverCustomAuthenticator extends AbstractApplicationAuthenticator implements
FederatedApplicationAuthenticator {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8654763286341993633L;
	private static final Log LOGGER = LogFactory.getLog(NaverCustomAuthenticator.class);
	

	public boolean canHandle(HttpServletRequest arg0) {
		LOGGER.debug("inside canHandle");
		// TODO Auto-generated method stub
		return false;
	}

	public String getContextIdentifier(HttpServletRequest arg0) {
		LOGGER.debug("inside getContextIdentifier");
		// TODO Auto-generated method stub
		return null;
	}

	public String getFriendlyName() {
		LOGGER.debug("inside getFriendlyName");
		// TODO Auto-generated method stub
		return "NAVER";
	}

	public String getName() {
		LOGGER.debug("inside getName");
		// TODO Auto-generated method stub
		return "NAVER";
	}

	@Override
	protected void processAuthenticationResponse(HttpServletRequest arg0, HttpServletResponse arg1,
			AuthenticationContext arg2) throws AuthenticationFailedException {
		LOGGER.debug("inside processAuthenticationResponse");
		// TODO Auto-generated method stub
		
	}

}
