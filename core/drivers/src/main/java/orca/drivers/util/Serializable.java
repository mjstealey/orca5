/*
 * Copyright (C) 2004-2007 Duke University. This software is distributed under
 * the terms of the Eclipse Public License Version 1.0 found in
 * the file named LICENSE.Eclipse, which was shipped with this distribution.
 * Any use, reproduction or distribution of this software constitutes
 * the recipient's acceptance of the Eclipse license terms.
 * This notice and the full text of the license must be included with any
 * distribution of this software.
 */

package orca.drivers.util;

import java.util.Properties;


public interface Serializable
{
    public Properties save() throws Exception;

    public void save(Properties properties) throws Exception;

    public void reset(Properties properties) throws Exception;
}