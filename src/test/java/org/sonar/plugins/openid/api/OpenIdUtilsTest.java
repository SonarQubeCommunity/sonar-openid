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

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenIdUtilsTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private AuthSuccess response;

  @Before
  public void init() {
    response = mock(AuthSuccess.class);
  }

  @Test
  public void getMessageAs_no_sreg_response() {
    assertThat(OpenIdUtils.getMessageAs(SRegResponse.class, response, SRegMessage.OPENID_NS_SREG)).isNull();
  }

  @Test
  public void getMessageAs_get_sreg_response() throws MessageException {
    SRegResponse sregResponse = new SRegResponse() {
    };
    when(response.hasExtension("http://openid.net/sreg/1.0")).thenReturn(true);
    when(response.getExtension("http://openid.net/sreg/1.0")).thenReturn(sregResponse);

    assertThat(OpenIdUtils.getMessageAs(SRegResponse.class, response, "http://openid.net/sreg/1.0")).isSameAs(sregResponse);
    assertThat(OpenIdUtils.getMessageAs(SRegResponse.class, response, "http://other")).isNull();
  }

  @Test
  public void getMessageAs_unchecked_exceptions_only() throws MessageException {
    thrown.expect(RuntimeException.class);
    thrown.expectMessage("fake");

    when(response.hasExtension("http://openid.net/sreg/1.0")).thenReturn(true);
    when(response.getExtension("http://openid.net/sreg/1.0")).thenThrow(new MessageException("fake"));

    OpenIdUtils.getMessageAs(SRegResponse.class, response, "http://openid.net/sreg/1.0");
  }
}
