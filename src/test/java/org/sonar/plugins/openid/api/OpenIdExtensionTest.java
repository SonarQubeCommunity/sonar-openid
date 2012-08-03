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

import org.junit.Test;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyZeroInteractions;

public class OpenIdExtensionTest {
  @Test
  public void do_nothing_on_doOnRequest_by_default() {
    AuthRequest request = mock(AuthRequest.class);
    new OpenIdExtension() {}.doOnRequest(request);

    verifyZeroInteractions(request);
  }

  @Test
  public void do_not_add_response_verification_by_default() {
    AuthSuccess response = mock(AuthSuccess.class);
    boolean ok = new OpenIdExtension(){}.doVerifyResponse(response);

    verifyZeroInteractions(response);
    assertThat(ok).isTrue();
  }
}
