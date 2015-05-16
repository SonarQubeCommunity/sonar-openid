Sonar OpenID Plugin
===================

Download and Version information: http://update.sonarsource.org/plugins/openid-confluence.html

## Description / Features

This plugin enables user authentication and Single Sign-On via an OpenID provider:
* Support OpenID Authentication 2.0
* Support Google accounts
* On the fly creation of users in SonarQube

## Installation

1. Install the plugin through the Update Center or download it into the _SONARQUBE_HOME/extensions/plugins_ directory
2. Restart the SonarQube server

## Usage

The following properties must be added to _SONARQUBE_HOME/conf/sonar.properties_:

```
# This property must be set to true
sonar.authenticator.createUsers=true
 
# Enable OpenID plugin
sonar.security.realm=openid
 
# URL of OpenID provider
sonar.openid.providerUrl=https://www.google.com/accounts/o8/id
 
# URL of logout page
sonar.openid.providerLogoutUrl=https://www.google.com/accounts/Logout
 
# URL of SonarQube server
sonar.openid.sonarServerUrl=http://localhost:9000
 
# Optional properties:
sonar.authenticator.updateUserAttributes=true
# If set to 'true', at each login, user's attributes (name, email, etc.)
# are re-synchronized. If set to 'false', user's attributes are not
# re-synchronized except when creating the user for the first time
```

### Technical Users

Since SonarQube 4.2, technical users can be set. Technical users are authenticated against SonarQube's own database of users, rather than against any external tool (LDAP, Active Directory, Crowd, etc.).

Similarly, all accounts not flagged as local will be authenticated only against the external tool. By default admin is a technical account. Technical accounts are configured in _SONARQUBE_HOME/conf/sonar.properties_ in the `sonar.security.localUsers` (default value = admin) property as a comma-separated list.

### Logs

Note that the library openid4java generates many INFO logs. For versions prior to SonarQube 4.1, edit the file conf/logback.xml and add the following loggers to log only warnings and errors:

```xml
<logger name="org.openid4java">
  <level value="WARN"/>
</logger>
```