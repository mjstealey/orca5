/*
 * Copyright (C) 2004-2007 Duke University. This software is distributed under
 * the terms of the Eclipse Public License Version 1.0 found in the file named
 * LICENSE.Eclipse, which was shipped with this distribution. Any use,
 * reproduction or distribution of this software constitutes the recipient's
 * acceptance of the Eclipse license terms. This notice and the full text of the
 * license must be included with any distribution of this software.
 */

package orca.controllers.openflow;

import orca.controllers.openflow.OpenFlowControllerManagerObject.ResultOpenFlowRequestMng;
import orca.manage.extensions.api.ManagerObject;
import orca.manage.extensions.api.beans.ResultMng;
import orca.manage.extensions.api.beans.ResultStringMng;
import orca.manage.extensions.standard.beans.ResultProxyMng;
import orca.manage.extensions.standard.controllers.proxies.local.LocalControllerManagementProxy;
import orca.security.AuthToken;

public class LocalOpenFlowControllerManagementProxy extends LocalControllerManagementProxy
        implements IOpenFlowControllerManagementProxy {
    /**
     * The controller manager object.
     */
    private OpenFlowControllerManagerObject manager;

    public LocalOpenFlowControllerManagementProxy() {
        super();
    }

    public LocalOpenFlowControllerManagementProxy(OpenFlowControllerManagerObject manager) {
        super(manager);
        this.manager = manager;
    }

    public void setManagerObject(ManagerObject manager) {
        super.setManagerObject(manager);
        this.manager = (OpenFlowControllerManagerObject) manager;
    }

    public ResultStringMng addRequest(String start, String end, int vmsDuke, int vmsRenci, AuthToken caller)
            throws Exception {
        return manager.addRequest(start, end, vmsDuke, vmsRenci, caller);
    }

    public ResultOpenFlowRequestMng getRequests(AuthToken caller) throws Exception {
        return manager.getRequests(caller);
    }

    public ResultOpenFlowRequestMng getRequests(String id, AuthToken caller) throws Exception {
        return manager.getRequests(id, caller);
    }

    public ResultProxyMng getVMBroker(AuthToken caller) throws Exception {
        return manager.getVMBroker(caller);
    }

    public ResultProxyMng getOpenFlowBroker(AuthToken caller) throws Exception {
        return manager.getOpenFlowBroker(caller);
    }

    public ResultMng closeRequest(String id, AuthToken caller) throws Exception {
        return manager.closeRequest(id, caller);
    }

}
