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
package org.sonar.plugins.openid.api;

import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.sonar.api.ServerExtension;

/**
 * <p>Adds verifications to authentication request.</p>
 * <p>The plugin providing this extension must use the same classloader than the openid plugin, by setting the parameter <basePlugin> of sonar-packaging-maven-plugin
 * to <code>openid</code>. See more details in the
 * <a href="https://github.com/SonarCommunity/sonar-openid/tree/master/samples/sonar-openid-sample-extension-plugin">sample plugin</a>.
 * </p>
 *
 * @since 1.1
 */
public abstract class OpenIdExtension implements ServerExtension {

  /**
   * Override this method to complete the request attributes (AX/SREG)
   */
  public void doOnRequest(AuthRequest request) {

  }

  /**
   * Override this method to complete the verification of OpenId response.
   *
   * @return is the response verified and user allowed to connect ?
   * @throws RuntimeException if the response can't be verified
   */
  public boolean doVerifyResponse(AuthSuccess response) {
    return true;
  }
}
