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

import org.openid4java.message.AuthRequest;
import org.sonar.api.web.ServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Requests to login form (/sessions/new) are redirected to the OpenID form
 * hosted on the identity provider, for example Google.
 */
public final class OpenIdAuthenticationFilter extends ServletFilter {

  private OpenIdClient openIdClient;

  public OpenIdAuthenticationFilter(OpenIdClient openIdClient) {
    this.openIdClient = openIdClient;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/sessions/new");
  }

  public void init(FilterConfig filterConfig) throws ServletException {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    AuthRequest authRequest = openIdClient.createAuthenticationRequest();
    ((HttpServletResponse) servletResponse).sendRedirect(authRequest.getDestinationUrl(true));
  }

  public void destroy() {
  }
}