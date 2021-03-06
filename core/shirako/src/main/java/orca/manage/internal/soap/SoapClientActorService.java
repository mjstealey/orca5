package orca.manage.internal.soap;

import java.util.Date;
import java.util.Properties;

import orca.manage.OrcaConstants;
import orca.manage.OrcaConverter;
import orca.manage.beans.ResultMng;
import orca.manage.beans.ResultPoolInfoMng;
import orca.manage.beans.ResultProxyMng;
import orca.manage.beans.ResultReservationMng;
import orca.manage.beans.ResultStringMng;
import orca.manage.beans.ResultStringsMng;
import orca.manage.internal.Converter;
import orca.manage.internal.IClientActorManagementObject;
import orca.manage.proxies.soap.beans.clientactor.AddBrokerRequest;
import orca.manage.proxies.soap.beans.clientactor.AddBrokerResponse;
import orca.manage.proxies.soap.beans.clientactor.AddReservationRequest;
import orca.manage.proxies.soap.beans.clientactor.AddReservationResponse;
import orca.manage.proxies.soap.beans.clientactor.AddReservationsRequest;
import orca.manage.proxies.soap.beans.clientactor.AddReservationsResponse;
import orca.manage.proxies.soap.beans.clientactor.ClaimResourcesRequest;
import orca.manage.proxies.soap.beans.clientactor.ClaimResourcesResponse;
import orca.manage.proxies.soap.beans.clientactor.DemandReservationRequest;
import orca.manage.proxies.soap.beans.clientactor.DemandReservationResponse;
import orca.manage.proxies.soap.beans.clientactor.ExtendReservationRequest;
import orca.manage.proxies.soap.beans.clientactor.ExtendReservationResponse;
import orca.manage.proxies.soap.beans.clientactor.GetBrokerRequest;
import orca.manage.proxies.soap.beans.clientactor.GetBrokerResponse;
import orca.manage.proxies.soap.beans.clientactor.GetBrokersRequest;
import orca.manage.proxies.soap.beans.clientactor.GetBrokersResponse;
import orca.manage.proxies.soap.beans.clientactor.GetPoolInfoRequest;
import orca.manage.proxies.soap.beans.clientactor.GetPoolInfoResponse;
import orca.security.AuthToken;
import orca.shirako.common.ReservationID;
import orca.shirako.common.SliceID;
import orca.shirako.container.Globals;
import orca.util.ExceptionUtils;
import orca.util.ID;
import orca.util.ResourceType;

import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;

public class SoapClientActorService extends SoapService {
	public static final String CLIENT_ACTOR_NS = "http://www.nicl.duke.edu/orca/manage/services/clientactor";

	public SoapClientActorService() {
	}

	protected IClientActorManagementObject getActorMO(ID guid) {
		try {
			return (IClientActorManagementObject) Globals.getContainer()
					.getManagementObjectManager().getManagementObject(guid);
		} catch (Exception e) {
			throw new RuntimeException("Invalid actor guid: " + guid);
		}
	}

	@PayloadRoot(localPart = "AddReservationRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	AddReservationResponse addReservation(@RequestPayload AddReservationRequest request) {
		ResultMng status = new ResultMng();
		AddReservationResponse response = new AddReservationResponse();
		response.setStatus(status);
		
		try {
			if (request.getGuid() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultStringMng tmp = mo.addReservation(request.getReservation(), auth);
			updateStatus(tmp.getStatus(), status);
			if (tmp.getResult() != null){
				response.setReservationId(tmp.getResult());
			}
		}catch (Exception e){
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}
		
		return response;
	}

	@PayloadRoot(localPart = "AddReservationsRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	AddReservationsResponse addReservations(@RequestPayload AddReservationsRequest request) {
		ResultMng status = new ResultMng();
		AddReservationsResponse response = new AddReservationsResponse();
		response.setStatus(status);
		
		try {
			if (request.getGuid() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultStringsMng tmp = mo.addReservations(request.getReservations(), auth);
			updateStatus(tmp.getStatus(), status);
			if (tmp.getResult() != null){
				response.getReservationIds().addAll(tmp.getResult());
			}
		}catch (Exception e){
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}
		
		return response;
	}

	@PayloadRoot(localPart = "DemandReservationRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	DemandReservationResponse demandReservation(@RequestPayload DemandReservationRequest request) {
		ResultMng status = new ResultMng();
		DemandReservationResponse response = new DemandReservationResponse();
		response.setStatus(status);
		
		try {
			if (request.getGuid() == null || (request.getReservation() == null && request.getReservationId() == null)) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			if (request.getReservation() != null && request.getReservationId() != null){
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultMng tmp;
			if (request.getReservationId() != null){
				tmp = mo.demandReservation(new ReservationID(request.getReservationId()), auth);
			}else {
				tmp = mo.demandReservation(request.getReservation(), auth);
			}			
			updateStatus(tmp, status);
		}catch (Exception e){
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}
		
		return response;
	}

	
	@PayloadRoot(localPart = "GetBrokersRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	GetBrokersResponse getBrokers(@RequestPayload GetBrokersRequest request) {
		ResultMng status = new ResultMng();
		GetBrokersResponse response = new GetBrokersResponse();
		response.setStatus(status);

		try {
			if (request.getGuid() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultProxyMng tmp = mo.getBrokers(auth);
			updateStatus(tmp.getStatus(), status);
			if (status.getCode() == 0) {
				response.getBrokers().addAll(tmp.getResult());
			}
		} catch (Exception e) {
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}

		return response;
	}

	@PayloadRoot(localPart = "GetBrokerRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	GetBrokerResponse getBroker(@RequestPayload GetBrokerRequest request) {
		ResultMng status = new ResultMng();
		GetBrokerResponse response = new GetBrokerResponse();
		response.setStatus(status);

		try {
			if (request.getGuid() == null || request.getBrokerId() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultProxyMng tmp = mo.getBroker(new ID(request.getBrokerId()), auth);
			updateStatus(tmp.getStatus(), status);
			if (status.getCode() == 0) {
				response.setBroker(getFirst(tmp.getResult()));
			}
		} catch (Exception e) {
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}

		return response;
	}

	@PayloadRoot(localPart = "AddBrokerRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	AddBrokerResponse addBroker(@RequestPayload AddBrokerRequest request) {
		ResultMng status = new ResultMng();
		AddBrokerResponse response = new AddBrokerResponse();
		response.setStatus(status);

		try {
			if (request.getGuid() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultMng tmp = mo.addBroker(request.getBroker(), auth);
			updateStatus(tmp, status);
		} catch (Exception e) {
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}

		return response;
	}

	@PayloadRoot(localPart = "ClaimResourcesRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	ClaimResourcesResponse claimResources(@RequestPayload ClaimResourcesRequest request) {
		ResultMng status = new ResultMng();
		ClaimResourcesResponse response = new ClaimResourcesResponse();
		response.setStatus(status);

		try {
			if (request.getGuid() == null || request.getBrokerId() == null
					|| request.getReservationId() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultReservationMng tmp;
			if (request.getSliceId() != null) {		
				tmp = mo.claimResources(new ID(request.getBrokerId()),
					new SliceID(request.getSliceId()),
					new ReservationID(request.getReservationId()), auth);
			}else {
				tmp = mo.claimResources(new ID(request.getBrokerId()),
						new ReservationID(request.getReservationId()), auth);			
			}
			updateStatus(tmp.getStatus(), status);
			if (status.getCode() == 0) {
				response.setReservation(getFirst(tmp.getResult()));
			}
		} catch (Exception e) {
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}

		return response;
	}

	@PayloadRoot(localPart = "GetPoolInfoRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	GetPoolInfoResponse getPoolInfo(@RequestPayload GetPoolInfoRequest request) {
		ResultMng status = new ResultMng();
		GetPoolInfoResponse response = new GetPoolInfoResponse();
		response.setStatus(status);

		try {
			if (request.getGuid() == null || request.getBrokerId() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			ResultPoolInfoMng tmp = mo.getPoolInfo(new ID(request.getBrokerId()), auth);
			updateStatus(tmp.getStatus(), status);
			if (status.getCode() == 0) {
				response.getPoolInfo().addAll(tmp.getResult());
			}
		} catch (Exception e) {
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}

		return response;
	}

	
	@PayloadRoot(localPart = "ExtendReservationRequest", namespace = CLIENT_ACTOR_NS)
	public @ResponsePayload
	ExtendReservationResponse extendReservation(@RequestPayload ExtendReservationRequest request) {
		ResultMng status = new ResultMng();
		ExtendReservationResponse response = new ExtendReservationResponse();
		response.setStatus(status);
		
		try {
			if (request.getGuid() == null || request.getReservationID() == null) {
				status.setCode(OrcaConstants.ErrorInvalidArguments);
				return response;
			}
			AuthToken auth = Converter.fill(request.getAuth());
			IClientActorManagementObject mo = getActorMO(new ID(request.getGuid()));
			Date newEndTime = new Date(request.getEndTime());
			ResourceType rtype = null;
			if (request.getNewResourceType() != null){
				rtype = new ResourceType(request.getNewResourceType());
			}
			Properties requestProperties = OrcaConverter.fill(request.getRequestProperties());
			Properties configProperties = OrcaConverter.fill(request.getConfigProperties());
			ResultMng tmp = mo.extendReservation(new ReservationID(request.getReservationID()), newEndTime, request.getNewUnits(), rtype, requestProperties, configProperties, auth);
			updateStatus(tmp, status);
		}catch (Exception e){
			status.setCode(OrcaConstants.ErrorInternalError);
			status.setMessage(e.getMessage());
			status.setDetails(ExceptionUtils.getStackTraceString(e.getStackTrace()));
		}
		
		return response;
	}
}