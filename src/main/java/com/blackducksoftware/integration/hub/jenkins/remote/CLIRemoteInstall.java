/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package com.blackducksoftware.integration.hub.jenkins.remote;

import java.io.File;

import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;

import com.blackducksoftware.integration.hub.CIEnvironmentVariables;
import com.blackducksoftware.integration.hub.HubIntRestService;
import com.blackducksoftware.integration.hub.cli.CLIInstaller;
import com.blackducksoftware.integration.hub.cli.CLILocation;
import com.blackducksoftware.integration.hub.jenkins.HubJenkinsLogger;

import hudson.EnvVars;
import hudson.remoting.Callable;

public class CLIRemoteInstall implements Callable<Void, Exception> {
	private static final long serialVersionUID = 3459269768733083577L;

	private final HubJenkinsLogger logger;

	private final String directoryToInstallTo;

	private final String localHost;

	private final String hubUrl;

	private final String hubUser;

	private final String hubPassword;

	private String proxyHost;

	private int proxyPort;

	private String proxyUserName;

	private String proxyPassword;

	private final EnvVars variables;

	public CLIRemoteInstall(final HubJenkinsLogger logger, final String directoryToInstallTo, final String localHost,
			final String hubUrl, final String hubUser, final String hubPassword, final EnvVars variables) {
		this.directoryToInstallTo = directoryToInstallTo;
		this.localHost = localHost;
		this.hubUrl = hubUrl;
		this.hubUser = hubUser;
		this.hubPassword = hubPassword;
		this.logger = logger;
		this.variables = variables;
	}

	public void setProxyHost(final String proxyHost) {
		this.proxyHost = proxyHost;
	}

	public void setProxyPort(final int proxyPort) {
		this.proxyPort = proxyPort;
	}

	public void setProxyUserName(final String proxyUserName) {
		this.proxyUserName = proxyUserName;
	}

	public void setProxyPassword(final String proxyPassword) {
		this.proxyPassword = proxyPassword;
	}

	@Override
	public Void call() throws Exception {
		final File hubToolDir = new File(directoryToInstallTo);
		final CLILocation cliLocation = new CLILocation(hubToolDir);
		final CIEnvironmentVariables ciEnvironmentVariables = new CIEnvironmentVariables();
		ciEnvironmentVariables.putAll(variables);
		final CLIInstaller installer = new CLIInstaller(cliLocation, ciEnvironmentVariables);

		final HubIntRestService service = new HubIntRestService(hubUrl);
		service.setLogger(logger);
		if (StringUtils.isNotBlank(proxyHost) && proxyPort != 0) {
			service.setProxyProperties(proxyHost, proxyPort, null, proxyUserName, proxyPassword);
		}
		service.setCookies(hubUser, hubPassword);

		installer.performInstallation(logger, service, localHost);

		return null;
	}

	@Override
	public void checkRoles(final RoleChecker checker) throws SecurityException {
		checker.check(this, new Role(CLIRemoteInstall.class));
	}

}
