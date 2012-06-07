/*
 * Sonar OpenID Plugin
 * Copyright (C) 2012 SonarSource
 * dev@sonar.codehaus.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.plugins.openid;

import org.apache.commons.lang.StringUtils;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.sonar.api.web.ServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Validate tokens forwarded by the OpenID provider after the request initiated by {@link OpenIdAuthenticationFilter}.
 * If authenfication is successful, then object of type UserDetails is added to request attributes.
 */
public final class OpenIdValidationFilter extends ServletFilter {

  static final String USER_ATTRIBUTE = "openid_user";
  private OpenIdClient openIdClient;

  public OpenIdValidationFilter(OpenIdClient openIdClient) {
    this.openIdClient = openIdClient;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/openid/validate");
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    try {
      ParameterList responseParameters = new ParameterList(request.getParameterMap());
      HttpServletRequest httpRequest = (HttpServletRequest) request;

      StringBuffer receivingURL = httpRequest.getRequestURL();
      String queryString = httpRequest.getQueryString();
      if (StringUtils.isNotEmpty(queryString)) {
        receivingURL.append("?").append(httpRequest.getQueryString());
      }

      VerificationResult verification = openIdClient.verify(receivingURL.toString(), responseParameters);

      Identifier verified = verification.getVerifiedId();
      if (verified != null) {
        AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();
        if (authSuccess != null) {
          request.setAttribute(USER_ATTRIBUTE, OpenIdClient.toUser(authSuccess));
        }
      }

      filterChain.doFilter(request, response);

    } catch (Exception e) {
      throw new IllegalStateException("Fail to validate openId token", e);
    }
  }

  public void destroy() {
  }
}