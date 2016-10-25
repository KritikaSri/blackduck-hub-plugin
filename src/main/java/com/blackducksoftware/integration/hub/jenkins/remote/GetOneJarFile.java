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

import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;

import com.blackducksoftware.integration.hub.cli.CLILocation;

import hudson.remoting.Callable;

public class GetOneJarFile implements Callable<String, Exception> {
    private static final long serialVersionUID = 3459269768733083577L;

    private final String directoryToInstallTo;

    public GetOneJarFile(final String directoryToInstallTo) {
        this.directoryToInstallTo = directoryToInstallTo;
    }

    @Override
    public String call() throws Exception {
        final File hubToolDir = new File(directoryToInstallTo);
        final CLILocation cliLocation = new CLILocation(hubToolDir);
        final File file = cliLocation.getOneJarFile();
        if (file != null) {
            return file.getCanonicalPath();
        }
        return null;
    }

    @Override
    public void checkRoles(final RoleChecker checker) throws SecurityException {
        checker.check(this, new Role(GetOneJarFile.class));
    }

}
