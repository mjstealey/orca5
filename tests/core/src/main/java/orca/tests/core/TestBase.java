/*
 * Copyright (C) 2004-2007 Duke University. This software is distributed under
 * the terms of the Eclipse Public License Version 1.0 found in
 * the file named LICENSE.Eclipse, which was shipped with this distribution.
 * Any use, reproduction or distribution of this software constitutes
 * the recipient's acceptance of the Eclipse license terms.
 * This notice and the full text of the license must be included with any
 * distribution of this software.
 */

package orca.tests.core;

import orca.util.ChangeClasspath;
import orca.util.PathGuesser;

import java.io.File;

import java.net.URL;

public class TestBase {
    public static void fixClassPath() {
        try {
            File f = new File(PathGuesser.getRealBase());
            URL url = f.toURL();
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            ChangeClasspath.addURL(loader, url);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}