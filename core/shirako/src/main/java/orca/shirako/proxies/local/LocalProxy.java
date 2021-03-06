/*
 * Copyright (C) 2004-2007 Duke University. This software is distributed under
 * the terms of the Eclipse Public License Version 1.0 found in the file named
 * LICENSE.Eclipse, which was shipped with this distribution. Any use,
 * reproduction or distribution of this software constitutes the recipient's
 * acceptance of the Eclipse license terms. This notice and the full text of the
 * license must be included with any distribution of this software.
 */

package orca.shirako.proxies.local;

import java.util.Properties;

import orca.security.AuthToken;
import orca.shirako.api.IActor;
import orca.shirako.api.ICallbackProxy;
import orca.shirako.api.IClientCallbackProxy;
import orca.shirako.api.IProxy;
import orca.shirako.api.IRPCRequestState;
import orca.shirako.api.IReservation;
import orca.shirako.api.IServiceManagerCallbackProxy;
import orca.shirako.common.ReservationID;
import orca.shirako.container.Globals;
import orca.shirako.core.RPCRequestState;
import orca.shirako.kernel.IncomingFailedRPC;
import orca.shirako.kernel.IncomingQueryRPC;
import orca.shirako.kernel.IncomingRPC;
import orca.shirako.kernel.IncomingReservationRPC;
import orca.shirako.kernel.RPCManager;
import orca.shirako.kernel.RPCRequestType;
import orca.shirako.proxies.Proxy;
import orca.shirako.registry.ActorRegistry;
import orca.shirako.util.RPCError;
import orca.shirako.util.RPCException;
import orca.shirako.util.RemoteActorException;
import orca.shirako.util.UpdateData;
import orca.util.PropList;
import orca.util.persistence.CustomRestorable;
import orca.util.persistence.PersistenceException;

/**
 * Acts as a proxy or skeleton for a local actor, e.g., instances of LocalProxy
 * carry all cross-actor calls when the client and server are co-located
 * (running in the same JVM). Most of the heavy lifting is in subclasses:
 * LocalAuthority, LocalAgent, and LocalReturn.
 * <p>
 * The subclasses perform some destination-specific translations, e.g., to the
 * reservation type. They also must pass arguments by copy rather by reference.
 * We are fast and loose in a few cases where we know that the caller doesn't
 * modify an argument or that the destination won't keep it.
 * <p>
 * LocalProxy and its descendants have no caller-specific state and therefore
 * may be passed by reference.
 */
public class LocalProxy extends Proxy implements ICallbackProxy {
    protected class LocalProxyRequestState extends RPCRequestState {
        IReservation reservation;
        UpdateData udd;
        ICallbackProxy callback;
        Properties query;
        String requestID;
        ReservationID failedReservationID;
        RPCRequestType failedRequestType;
        String errorDetail;
    }

    public LocalProxy() {
    }

    /**
     * Creates a new proxy representing the specified actor
     * @param actor The actor object to be represented by this proxy
     */
    public LocalProxy(IActor actor) {
    	super(actor.getIdentity());
        this.logger = actor.getLogger();
        this.proxyType = IProxy.ProxyTypeLocal;
    }

    /*
     * ========================================================================
     * Public interface
     * ========================================================================
     */

    public void execute(IRPCRequestState state) throws RPCException {
        try {
            LocalProxyRequestState local = (LocalProxyRequestState) state;
            IncomingRPC incoming = null;
            switch (state.getType()) {
                case Query:
                    incoming = new IncomingQueryRPC(local.getMessageID(), local.query, local.callback, local.getCaller());
                    break;
                case QueryResult:
                    incoming = new IncomingQueryRPC(local.getMessageID(), local.requestID, local.query, local.getCaller());
                    break;
                case Claim:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, (IClientCallbackProxy) local.callback, local.getCaller());
                    break;
                case Ticket:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, (IClientCallbackProxy) local.callback, local.getCaller());
                    break;
                case Redeem:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, (IServiceManagerCallbackProxy) local.callback, local.getCaller());
                    break;
                case ExtendTicket:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.getCaller());
                    break;
                case ExtendLease:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.getCaller());
                    break;
                case Close:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.getCaller());
                    break;
                case Relinquish:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.getCaller());
                    break;
                case UpdateTicket:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.udd, local.getCaller());
                    break;
                case UpdateLease:
                    incoming = new IncomingReservationRPC(local.getMessageID(), local.getType(), local.reservation, local.udd, local.getCaller());
                    break;
                case FailedRPC:
                    if (local.failedReservationID != null) {
                        incoming = new IncomingFailedRPC(local.getMessageID(), local.failedRequestType, local.requestID, local.failedReservationID, local.errorDetail, local.getCaller());
                    } else {
                        incoming = new IncomingFailedRPC(local.getMessageID(), local.failedRequestType, local.requestID, local.errorDetail, local.getCaller());
                    }
                    break;                        
                default:
                    throw new RemoteActorException("Unsupported RPC type: " + state.getType());
            }
            RPCManager.dispatchIncoming(getActor(), incoming);
        } catch (RemoteActorException e) {
            throw new RPCException("Error while processing RPC request", RPCError.InvalidRequest, e);
        }
    }

    public IRPCRequestState prepareQuery(ICallbackProxy callback, Properties query, AuthToken caller) {
        LocalProxyRequestState state = new LocalProxyRequestState();
        state.query = new Properties();
        PropList.mergeProperties(query, state.query);
        state.callback = callback;
        return state;
    }

    public IRPCRequestState prepareQueryResult(String requestID, Properties response, AuthToken caller) {
        LocalProxyRequestState state = new LocalProxyRequestState();
        state.query = new Properties();
        PropList.mergeProperties(response, state.query);
        state.requestID = requestID;
        return state;
    }

    public IRPCRequestState prepareFailedRPC(String requestID, RPCRequestType failedRequestType, ReservationID failedReservationID, String errorDetail, AuthToken caller) {
        LocalProxyRequestState state = new LocalProxyRequestState();
        state.requestID = requestID;
        state.failedRequestType = failedRequestType;
        state.failedReservationID = failedReservationID;
        state.errorDetail = errorDetail;
        return state;
    }

    /*
     * ========================================================================
     * Get/set
     * ========================================================================
     */

    /**
     * Returns the actor represented by this proxy
     * @return
     */
    public IActor getActor() {
        IActor result = ActorRegistry.getActor(getName());

        if (result == null) {
            throw new RuntimeException("Actor does not exist.");
        }

        return result;
    }
}
