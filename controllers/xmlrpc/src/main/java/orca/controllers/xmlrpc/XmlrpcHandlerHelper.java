package orca.controllers.xmlrpc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.login.CredentialException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import orca.controllers.OrcaControllerException;
import orca.controllers.OrcaXmlrpcServlet;
import orca.controllers.xmlrpc.SliceStateMachine.SliceCommand;
import orca.controllers.xmlrpc.geni.GeniAmV2Handler;
import orca.controllers.xmlrpc.geni.IGeniAmV2Interface.ApiOptionFields;
import orca.controllers.xmlrpc.geni.IGeniAmV2Interface.GeniStates;
import orca.controllers.xmlrpc.x509util.CertificateUtil;
import orca.controllers.xmlrpc.x509util.Credential;
import orca.controllers.xmlrpc.x509util.CredentialValidator;
import orca.controllers.xmlrpc.x509util.Gid;
import orca.manage.IOrcaServiceManager;
import orca.manage.OrcaConverter;
import orca.manage.beans.PropertiesMng;
import orca.manage.beans.PropertyMng;
import orca.manage.beans.ReservationMng;
import orca.security.AbacUtil;
import orca.security.AuthToken;
import orca.shirako.common.ReservationID;
import orca.shirako.common.meta.UnitProperties;
import orca.util.PropList;

import org.apache.log4j.Logger;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

import com.hp.hpl.jena.ontology.OntResource;

/**
 * This is a helper class for all XMLRPC handlers. WARNING: Any method you declare public (non-static) becomes a remote
 * method!
 * 
 * @author ibaldin
 *
 */
public class XmlrpcHandlerHelper {
    public static final String RFC3399_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    public static final String PropertyNdlConverterUrlList = "ndl.converter.url";
    private static final String SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
    public static final String RSPEC2_TO_NDL = "ndlConverter.requestFromRSpec2";
    public static final String RSPEC3_TO_NDL = "ndlConverter.requestFromRSpec3";
    public static final String MANIFEST_TO_RSPEC = "ndlConverter.manifestToRSpec3";
    public static final String AD_TO_RSPEC = "ndlConverter.adToRSpec3";
    public static final String ADS_TO_RSPEC = "ndlConverter.adsToRSpec3";
    protected static final String DEFAULT_OUTPUT_FORMAT = "RDF-XML";
    protected static final String DEFAULT_NDL_CONVERTER_URL_LIST = "http://geni.renci.org:12080/ndl-conversion/,http://localhost:11080/ndl-conversion/";
    public static final String PropertyGeniCredentialVerification = "geni.credential.verification.required";

    protected Logger logger;
    protected String NdlConverterUrlList;

    /**
     * 
     * @param filePath
     * @return
     * @throws java.io.IOException
     */
    public static String readFileAsString(String filePath) throws java.io.IOException {
        byte[] buffer = new byte[(int) new File(filePath).length()];
        FileInputStream f = new FileInputStream(filePath);
        f.read(buffer);
        f.close();
        return new String(buffer);
    }

    /**
     * To deal with RFC3339 Date
     * 
     * @param datestring
     * @return
     * @throws java.text.ParseException
     */
    public static Date parseRFC3339Date(String datestring) throws java.text.ParseException {
        Date d = new Date();
        // if there is no time zone, we don't need to do any special parsing.
        if (datestring.endsWith("Z")) {
            SimpleDateFormat s = new SimpleDateFormat(RFC3399_DATE_FORMAT);// spec for RFC3339
            s.setTimeZone(TimeZone.getTimeZone("UTC"));
            try {
                d = s.parse(datestring);
            } catch (java.text.ParseException pe) {// try again with optional decimals
                s = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'");
                s.setTimeZone(TimeZone.getTimeZone("UTC"));
                s.setLenient(true);
                d = s.parse(datestring);
            }
            return d;
        }

        // step one, split off the timezone.
        char timezoneSeparator;
        if (datestring.contains("+")) {
            timezoneSeparator = '+';
        } else {
            timezoneSeparator = '-';
        }

        String firstpart = datestring.substring(0, datestring.lastIndexOf(timezoneSeparator));
        String secondpart = datestring.substring(datestring.lastIndexOf(timezoneSeparator));

        // step two, remove the colon from the timezone offset
        secondpart = secondpart.substring(0, secondpart.indexOf(':'))
                + secondpart.substring(secondpart.indexOf(':') + 1);
        datestring = firstpart + secondpart;
        SimpleDateFormat s = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");// spec for RFC3339
        s.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            d = s.parse(datestring);
        } catch (java.text.ParseException pe) {// try again with optional decimals
            s = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ");// spec for RFC3339 (with fractional seconds)
            s.setTimeZone(TimeZone.getTimeZone("UTC"));
            s.setLenient(true);
            d = s.parse(datestring);
        }
        return d;
    }

    /**
     * Takes a timestamp as a Calendar and returns it as a String in RFC 3339 format.
     *
     * @param timestamp
     *            a timestamp as a Calendar
     * @return the provided timestamp as a RFC 3339 string
     */
    public static String getRFC3339String(Calendar timestamp) {
    	// As of Java 7 this is possible /ib 03/13/2018
    	SimpleDateFormat rfc3339Formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    	return rfc3339Formatter.format(timestamp.getTime());
    }

    private static void appendTwoDigitInteger(StringBuilder builder, int integer) {
        if (integer < 10)
            builder.append('0');
        builder.append(integer);
    }

    protected void setAbacAttributes(ReservationMng reservation, Logger logger) throws Exception {

        // insecure comms are not allowed
        if (OrcaXmlrpcServlet.getSslSessionId() == null || OrcaXmlrpcServlet.getClientCertificateChain() == null) {
            logger.error("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
            throw new CredentialException("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
        }

        X509Certificate[] clientCertificateChain = OrcaXmlrpcServlet.getClientCertificateChain();

        if (clientCertificateChain[0] == null) {
            throw new CertificateException("Caller's certificate is missing.");
        }

        AuthToken caller = new AuthToken();
        caller.setCertificate(clientCertificateChain[0]);
        String value = AbacUtil.getRequesterAuthTokenValue(caller);

        OrcaConverter.setRequestProperty(reservation, AbacUtil.getRequesterAuthTokenKey(), value);
        OrcaConverter.setConfigurationProperty(reservation, AbacUtil.getRequesterAuthTokenKey(), value);
    }

    /**
     * Use slice URN/name to determine slice reservations
     * 
     * @param slice_urn
     * @return
     * @throws Exception
     * @throws CredentialException
     */
    public static List<ReservationMng> getAllSliceReservations(IOrcaServiceManager sm, XmlrpcControllerSlice sl)
            throws Exception {
        if (sl == null)
            return null;

        XmlRpcController controller = XmlrpcOrcaState.getInstance().getController();

        if (controller == null)
            throw new Exception("ERROR: XMLrpcController not initiated: " + sl.getSliceUrn());

        if (sl.getWorkflow() == null)
            throw new Exception("ERROR: InterDomainHandler not initiated: " + sl.getSliceUrn());

        return sl.getAllReservations(sm);
    }

    /**
     * Use guid to determine all slice reservations
     * 
     * @param sid
     * @return
     * @throws Exception
     * @throws CredentialException
     */
    public static List<ReservationMng> getAllSliceReservationsByGuid(IOrcaServiceManager sm, String sid)
            throws Exception {
        if (sid == null)
            return null;

        XmlrpcControllerSlice sl = XmlrpcOrcaState.getInstance().getSlice(sid);

        return getAllSliceReservations(sm, sl);
    }

    public static List<ReservationMng> getAllSliceReservationsByName(IOrcaServiceManager sm, String urn)
            throws Exception {
        if (urn == null)
            return null;

        String sid = XmlrpcControllerSlice.getSliceIDForUrn(urn);
        return getAllSliceReservationsByGuid(sm, sid);
    }

    /**
     * Function to do the GENI (non ABAC) authorization check, if required.
     * 
     * @param sliceUrn
     * @param credentials
     * @param requiredPrivilege
     * @return expiration date
     * @throws CredentialException
     */
    public static Date validateGeniCredential(String sliceUrn, Object[] credentials, String[] requiredPrivilege,
            Map<String, Object> options, boolean verifyCredentials, Logger logger) throws CredentialException,
            CertificateException, CertPathValidatorException, XMLSignatureException, MarshalException {

        if (!verifyCredentials) {
            return null;
        }

        // insecure comms are not allowed
        if (OrcaXmlrpcServlet.getSslSessionId() == null || OrcaXmlrpcServlet.getClientCertificateChain() == null) {
            logger.error("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
            throw new CredentialException("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
        }

        X509Certificate[] clientCertificateChain = OrcaXmlrpcServlet.getClientCertificateChain();

        if (clientCertificateChain.length > 0)
            logger.info("validateGeniCredential(): Client presented a certificate with subject: "
                    + clientCertificateChain[0].getSubjectX500Principal());

        X509Certificate callerCert = clientCertificateChain[0];

        X509Certificate userCert = callerCert; // by default userCert used for credential verification is the caller
                                               // cert from SSL connection

        Set<String> privilegeList = null;

        if (requiredPrivilege != null && requiredPrivilege.length > 0) {
            privilegeList = new HashSet<String>();
            for (int count = 0; count < requiredPrivilege.length; count++) {
                privilegeList.add(requiredPrivilege[count]);
            }
        }

        // Find out if there is a "geni_speaking_for" as a key in the options Map; grab the urn and set
        // look_for_speaksfor_cred = true

        boolean look_for_speaksfor_cred = false;
        String spoken_for_user_urn = null;
        if (options != null) {
            spoken_for_user_urn = (String) options.get(ApiOptionFields.GENI_SPEAKING_FOR.name);
            if (spoken_for_user_urn != null) {
                logger.info("geni_speaking_for option found");
                look_for_speaksfor_cred = true;
            }
        }

        if (look_for_speaksfor_cred) { // Find speaks-for credential only if the spoken_for_user_urn != null
            // speaks_for_context = true
            logger.info("Tool attempting to speak for user: " + spoken_for_user_urn);
            for (int itr = 0; itr < credentials.length; itr++) { // for each cred in credentials

                String type = CredentialValidator.checkCredentialType((String) credentials[itr]);
                // if credential type is "abac" [*** if there are multiple speaksfor credentials, all of them need to be
                // valid ***]
                if (type != null && type.equalsIgnoreCase("abac")) { // this is a speaks for credential
                    logger.info("Found speaks for credential");
                    logger.info("Starting speaks-for credential validation...");
                    X509Certificate spokenfor_user_cert = CredentialValidator
                            .validateSpeaksForCredential((String) credentials[itr], spoken_for_user_urn, callerCert);

                    // if user_cert != null
                    // Send user cert as parameter for actual credential verification
                    // userCert = user_cert; // update userCert to the user certificate in the speaks for credential
                    if (spokenfor_user_cert != null) {
                        userCert = spokenfor_user_cert;
                    } else {
                        throw new CredentialException(
                                "spokenfor_user_cert was returned as null from validateSpeaksForCredential()");
                    }

                }

            }
            logger.info("Done with speaks-for validation...");
            logger.info("Tool speaking for user: " + spoken_for_user_urn);

        }

        // At this point all speaks for credentials, if they exist, have to be valid;
        // And we grab the userCert from the last valid speaks-for credential
        // If there is no speaks-for credential, the userCert is the callerCert

        logger.info("Validating non speaks-for credentials using user certificate with subject: "
                + userCert.getSubjectX500Principal());

        Date expDate = null;
        for (int itr = 0; itr < credentials.length; itr++) {
            try {
                // if credential type != "abac" do a normal credential check
                String type = CredentialValidator.checkCredentialType((String) credentials[itr]);
                if (type != null && !(type.equalsIgnoreCase("abac"))) {
                    expDate = CredentialValidator.validateCredential(sliceUrn, (String) credentials[itr], privilegeList,
                            userCert);
                    return expDate;
                }
            } catch (Exception exception) {
                logger.debug(exception.getMessage());
                // check next credential
            }
        }

        throw new CredentialException("No credential was found with appropriate privileges or valid dates.");
    }

    /**
     * Orca light credential validation - simply check that the presented cert is still valid and traceable to a known
     * trust root. Ignores all input parameters and gets the client cert chain from the servlet. (11/29/2011) /ib
     * 
     * @param sliceUrn
     * @param credentials
     * @param requiredPrivilege
     * @param logger
     * @param verifyCredentials
     * @throws CredentialException
     */
    @SuppressWarnings("unchecked")
    public static String validateOrcaCredential(String sliceUrn, Object[] credentials, String[] requiredPrivilege,
            boolean verifyCredentials, Logger logger) throws CredentialException {

        if (!verifyCredentials) {
            return null;
        }

        // insecure comms are not allowed
        if (OrcaXmlrpcServlet.getSslSessionId() == null || OrcaXmlrpcServlet.getClientCertificateChain() == null) {
            logger.error("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
            throw new CredentialException("Client " + OrcaXmlrpcServlet.getClientIpAddress()
                    + " is not using secure communications, operations are not allowed");
        }

        X509Certificate[] clientCertificateChain = OrcaXmlrpcServlet.getClientCertificateChain();
        List<String> altNameStrings = null;

        if (clientCertificateChain.length > 0) {
            logger.info("validateOrcaCredential(): Client presented a certificate with subject: "
                    + clientCertificateChain[0].getSubjectX500Principal());

            try {
                altNameStrings = getExtensionValue(clientCertificateChain[0], SUBJECT_ALTERNATIVE_NAME);
                /*
                 * for (String altName: altNameStrings) { logger.debug("Certificate contains subject alternative name: "
                 * + altName); }
                 */
            } catch (Exception e) {
                ;
            }
        }

        // check the expiration date on the presented cert chain
        try {
            for (int i = 0; i < clientCertificateChain.length; i++)
                clientCertificateChain[i].checkValidity();
        } catch (Exception e) {
            throw new CredentialException("Certificate invalid: " + e);
        }

        // and that it can be traced to a trust root
        String CH_TRUSTSTORE_PATH = XmlRpcController.HomeDirectory
                + XmlRpcController.getProperty(CredentialValidator.PropertyChTruststorePath);
        String CH_TRUSTSTORE_PASS = XmlRpcController.getProperty(CredentialValidator.PropertyChTruststorePassword);

        try {
            CertificateUtil.verifyCertChain((List<X509Certificate>) Arrays.asList(clientCertificateChain),
                    CH_TRUSTSTORE_PATH, CH_TRUSTSTORE_PASS);
        } catch (CertPathValidatorException e) {
            throw new CredentialException("Unable to validate trust root: " + e);
        }

        // Changes below for speaks_for

        // In the normal case, return the clientcertUserDN as below
        /*
         * return (((altNameStrings != null) && (altNameStrings.size() > 0)) ? altNameStrings.toString() :
         * clientCertificateChain[0].getSubjectDN().getName());
         */

        // supply URN if emulab cert or DN if other cert
        String clientcertUserDN = ((altNameStrings != null) && (altNameStrings.size() > 0)) ? altNameStrings.toString()
                : clientCertificateChain[0].getSubjectDN().getName();

        logger.info("clientcertUserDN = " + clientcertUserDN);

        String speaksforUserDN = null;
        boolean speaks_for_context = false;

        // Check if a speaks for credential exists in the list of credentials
        // If so, get the userDN from the userCert in the speaks-for credential and set speaks_for_context to true
        for (int itr = 0; itr < credentials.length; itr++) { // for each cred in credentials
            String type = CredentialValidator.checkCredentialType((String) credentials[itr]);
            // if credential type is "abac"
            if (type != null && type.equalsIgnoreCase("abac")) { // this is a speaks for credential
                logger.info("Found speaks for credential while setting userDN");
                // get userDN from (String)credentials[itr]
                Credential credential;
                try {
                    credential = new Credential((String) credentials[itr]);
                } catch (Exception exception) {
                    logger.error(exception.getMessage());
                    throw new CredentialException("Exception parsing speaks_for credential xml while setting userDN");
                }

                Gid userGid = credential.getSignature().getIssuerGid(); // user gid
                X509Certificate userCert = userGid.getCertificate(); // this is the cert of the user on behalf of whool
                                                                     // the tool is speaking for

                List<String> altNameStringsInUserCert = null;

                try {
                    altNameStringsInUserCert = getExtensionValue(userCert, SUBJECT_ALTERNATIVE_NAME);
                    for (String altNameInUserCert : altNameStringsInUserCert) {
                        logger.info("User certificate (speaks-for) contains subject alternative name: "
                                + altNameInUserCert);
                    }
                } catch (Exception e) {
                    ;
                }

                speaksforUserDN = ((altNameStringsInUserCert != null) && (altNameStringsInUserCert.size() > 0))
                        ? altNameStringsInUserCert.toString() : userCert.getSubjectDN().getName();
                logger.info("speaksforUserDN = " + speaksforUserDN);

                speaks_for_context = true;

            }
        }

        // If it is not speaks for context, then return userDN from client cert in SSL connection
        if (!speaks_for_context) {
            logger.debug("returning clientcertUserDN as userDN");
            return clientcertUserDN;
        } else {
            logger.debug("returning speaksforUserDN as userDN");
            return speaksforUserDN;
        }

    }

    public static class NoOwnerDNOnReservation extends Exception {
        String reservation;

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public NoOwnerDNOnReservation(String resId) {
            reservation = resId;
        }

        @Override
        public String toString() {
            return "Owner not specified on reservation " + reservation;
        }
    }

    public static class NotSliceOwnerException extends Exception {
        /**
         * 
         */
        private static final long serialVersionUID = 1L;
        String sliceName, userDN;

        public NotSliceOwnerException(String s, String dn) {
            sliceName = s;
            userDN = dn;
        }

        @Override
        public String toString() {
            return "Slice " + sliceName + " is not owned by " + userDN;
        }
    }

    /**
     * Validate ownership of a sliver by a given DN
     * 
     * @param sm
     * @param sliver_guid
     * @param userDN
     * @return
     */
    public static boolean validateSliverOwner(IOrcaServiceManager sm, String sliver_guid, String userDN)
            throws NoOwnerDNOnReservation {
        try {
            if (userDN == null)
                throw new RuntimeException("validateSliverOwner(): supplied userDN is null");

            ReservationID res = new ReservationID(sliver_guid);
            ReservationMng rm = sm.getReservation(res);
            if (rm == null)
                throw new RuntimeException("validateSliverOwner(): Unable to find reservation " + res);

            String reservationDN = OrcaConverter.getLocalProperty(rm, XmlrpcOrcaState.XMLRPC_USER_DN);
            if (reservationDN != null)
                return userDN.equals(reservationDN);
            else
                throw new NoOwnerDNOnReservation(sliver_guid);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("Unable to validate sliver ownership due to " + e);
        }
    }

    /**
     * alternative version of reservation ownership validation, if we already have ReservationMng object on hand
     * 
     * @param rm
     * @param userDN
     * @return
     */
    public static boolean validateSliverOwner(ReservationMng rm, String userDN) throws NoOwnerDNOnReservation {
        try {
            if (userDN == null)
                throw new RuntimeException("validateSliverOwner(): supplied userDN is null");

            if (rm == null)
                throw new RuntimeException("validateSliverOwner(): reservation is null ");

            String reservationDN = OrcaConverter.getLocalProperty(rm, XmlrpcOrcaState.XMLRPC_USER_DN);
            if (reservationDN != null)
                return userDN.equals(OrcaConverter.getLocalProperty(rm, XmlrpcOrcaState.XMLRPC_USER_DN));
            else
                throw new NoOwnerDNOnReservation(rm.getReservationID());
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("Unable to validate sliver ownership due to " + e);
        }
    }

    /**
     * helper function looks at list of reservations, makes sure at least one reservation has a DN property matching the
     * supplied string
     * 
     * @param l
     * @param userDN
     * @return
     */
    public static boolean validateSliverListOwner(List<ReservationMng> l, String userDN) throws NoOwnerDNOnReservation {
        if (l == null)
            return false;
        for (ReservationMng r : l) {
            try {
                return validateSliverOwner(r, userDN);
            } catch (NoOwnerDNOnReservation ndn) {
                // skip if DN is not on reservation
                ;
            }
        }
        // however DN has to be on at least one reservation
        throw new NoOwnerDNOnReservation("none");
    }

    /**
     * Validate that offered list of reservations is part of the list of slice reservations
     * 
     * @param sliceRes
     * @param resList
     * @return
     */
    public static boolean validateSliverListSlice(List<ReservationMng> sliceRes, List<String> resList) {
        if ((resList == null) || (sliceRes == null))
            return false;

        Set<String> resSet = new HashSet<>(resList);
        int validCount = 0;
        for (ReservationMng rmng : sliceRes) {
            if (resSet.contains(rmng.getReservationID())) {
                validCount++;
            }
        }
        if (validCount == resSet.size())
            return true;
        return false;
    }

    /**
     * Return DN or subjectAlternativeName URN in the certificate used for this SSL session
     * 
     * @param logger
     * @return
     * @throws CredentialException
     */
    public static String getCredentialDN(Logger logger) throws CredentialException {

        // insecure comms are not allowed
        if (OrcaXmlrpcServlet.getSslSessionId() == null || OrcaXmlrpcServlet.getClientCertificateChain() == null) {
            return null;
        }

        X509Certificate[] clientCertificateChain = OrcaXmlrpcServlet.getClientCertificateChain();
        List<String> altNameStrings = null;

        if (clientCertificateChain.length > 0) {
            logger.info("validateOrcaCredential(): Client presented a certificate with subject: "
                    + clientCertificateChain[0].getSubjectX500Principal());

            try {
                altNameStrings = getExtensionValue(clientCertificateChain[0], SUBJECT_ALTERNATIVE_NAME);
                for (String altName : altNameStrings) {
                    logger.info("Certificate contains subject alternative name: " + altName);
                }
            } catch (Exception e) {
                ;
            }

            // supply URN if emulab cert or DN if other cert
            return (((altNameStrings != null) && (altNameStrings.size() > 0)) ? altNameStrings.toString()
                    : clientCertificateChain[0].getSubjectDN().getName());
        }
        return null;
    }

    /**
     * Get extension value as string from a cert
     * 
     * @param X509Certificate
     * @param oid
     * @return
     * @throws IOException
     */
    public static List<String> getExtensionValue(X509Certificate X509Certificate, String oid) throws IOException {
        byte[] extensionValue = X509Certificate.getExtensionValue(oid);
        List<String> ret = null;

        if (extensionValue != null) {
            DERObject derObject = toDERObject(extensionValue);

            ret = getDERStrings(derObject);
        }
        return ret;
    }

    /**
     * Try to recursively extract strings from DER object
     * 
     * @param derObject
     * @return
     */
    private static List<String> getDERStrings(DERObject derObject) {

        if (derObject == null)
            return null;

        List<String> ret = new ArrayList<String>();

        if (derObject instanceof DEROctetString) {
            DEROctetString derOctetString = (DEROctetString) derObject;

            derObject = toDERObject(derOctetString.getOctets());
            List<String> res = getDERStrings(derObject);
            if (res != null)
                ret.addAll(res);
            else
                ret.add(new String(derOctetString.getOctets()));
            return ret;
        }
        if (derObject instanceof DERSequence) {
            DERSequence derSeq = (DERSequence) DERSequence.getInstance(derObject);

            for (int i = 0; i < derSeq.size(); i++) {
                DEREncodable derEnc = derSeq.getObjectAt(i);
                List<String> res = getDERStrings(derEnc.getDERObject());
                if (res != null)
                    ret.addAll(res);
            }
            return ret;
        }
        if (derObject instanceof DERUTF8String) {
            DERUTF8String s = DERUTF8String.getInstance(derObject);
            ret.add(s.getString());
            return ret;
        }

        if (derObject instanceof DERTaggedObject) {
            DERTaggedObject derTO = (DERTaggedObject) derObject.getDERObject();
            List<String> res = getDERStrings(derTO.getObject());
            if (res != null)
                ret.addAll(res);
            return ret;
        }

        return ret;
    }

    /**
     * Convert byte string to DER Object
     * 
     * @param data
     * @return
     * @throws IOException
     */
    private static DERObject toDERObject(byte[] data) {
        ASN1InputStream asnInputStream = null;
        try {
            ByteArrayInputStream inStream = new ByteArrayInputStream(data);
            asnInputStream = new ASN1InputStream(inStream);

            return asnInputStream.readObject();
        } catch (Exception e) {
            return null;
        } finally {
            if (asnInputStream != null)
                try {
                    asnInputStream.close();
                } catch (Exception e) {
                    ;
                }
        }
    }

    /**
     * Make RR calls to converters until success or list exhausted
     * 
     * @param call
     * @param params
     * @return
     */
    @SuppressWarnings("unchecked")
    protected Map<String, Object> callConverter(String call, Object[] params) {
        Map<String, Object> ret = null;

        // make a round robin call to all converters (list is shuffled to do load balancing)
        logger.debug("Choosing NDL converter from list: " + NdlConverterUrlList);
        ArrayList<String> urlList = new ArrayList<String>(Arrays.asList(NdlConverterUrlList.split(",")));
        Collections.shuffle(urlList);
        for (String cUrl : urlList) {
            try {
                XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
                config.setServerURL(new URL(cUrl));
                XmlRpcClient client = new XmlRpcClient();
                client.setConfig(config);

                logger.debug("GENI AM API: Invoking NDL converter " + call + " at " + cUrl);
                ret = (Map<String, Object>) client.execute(call, params);
                break;
            } catch (XmlRpcException e) {
                logger.error("GENI AM API: Unable to contact NDL converter at " + cUrl + " due to " + e);
                continue;
            } catch (MalformedURLException ue) {
                ret = new HashMap<String, Object>();
                ret.put("err", true);
                ret.put("msg", "ORCA actor misconfiguration: invalid converter URL " + cUrl);
            } catch (ClassCastException ce) {
                // old converter, skip it
                logger.error("GENI AM API: Unable to use NDL converter at " + cUrl
                        + " because converter return does not match expected type");
                continue;
            }
        }

        if (ret == null) {
            ret = new HashMap<String, Object>();
            ret.put("err", true);
            ret.put("msg", "Unable to contact/use any of specified NDL-RSPEC converters at " + NdlConverterUrlList);
        }

        return ret;
    }

    /**
     * Get the manifest in a standard way based on ORCA state
     * 
     * @param instance
     * @param slice_urn
     * @param logger
     * @return
     */
    public static String getSliceManifest(XmlrpcOrcaState instance, String slice_urn, Logger logger)
            throws OrcaControllerException {
        IOrcaServiceManager sm = null;
        XmlrpcControllerSlice ndlSlice = null;
        try {
            List<ReservationMng> allRes = null;
            String result;

            // find this slice and lock it
            ndlSlice = instance.getSlice(slice_urn);
            if (ndlSlice == null) {
                logger.error("getSliceManifest(): unable to find slice " + slice_urn + " among active slices");
                throw new OrcaControllerException("ERROR: unable to find slice " + slice_urn + " among active slices");
            }
            // lock the slice
            ndlSlice.lock();
            ndlSlice.getStateMachine().transitionSlice(SliceCommand.REEVALUATE);
            logger.debug("Slice " + slice_urn + " transitioned to state " + ndlSlice.getStateMachine().getState());

            sm = instance.getSM();

            try {
                allRes = ndlSlice.getAllReservations(sm);
            } catch (Exception e) {
                logger.error("getSliceManifest(): Exception encountered for " + slice_urn + ": " + e);
                throw new OrcaControllerException("ERROR: unable to get reservations in slice status for " + slice_urn);
            }

            if (allRes == null) {
                result = "ERROR: Invalid slice " + slice_urn + ", slice status can't be determined";
                logger.error("getSliceManifest(): Invalid slice " + slice_urn + ", slice status can't be determined");
                throw new OrcaControllerException(result);
            } else {
                // don't forget the GENI state
                GeniStates geniStates = GeniAmV2Handler.getSliceGeniState(instance, slice_urn);
                // DEBUG
                logger.debug("getSliceManifest(): listing reservations and states for slice " + slice_urn);
                for (ReservationMng rmm : allRes) {
                    logger.debug("GSM: reservation " + rmm.getReservationID() + " is in state " + rmm.getState());
                }

                logger.debug("getSliceManifest(): listing domains for slice " + slice_urn);
                for (OntResource orr : ndlSlice.getWorkflow().getDomainInConnectionList()) {
                    logger.debug("---- " + orr.getLocalName() + " " + orr);
                }
                try {
                    ReservationConverter orc = ndlSlice.getOrc();
                    orc.updateGeniStates(ndlSlice.getWorkflow().getManifestModel(), geniStates);
                    result = orc.getManifest(ndlSlice.getWorkflow().getManifestModel(),
                            ndlSlice.getWorkflow().getDomainInConnectionList(),
                            ndlSlice.getWorkflow().getBoundElements(), allRes);
                } catch (Exception e) {
                    logger.error("getSliceManifest(): converter unable to get manifest: " + e);
                    e.printStackTrace();
                    throw new OrcaControllerException("ERROR: Failed due to exception: " + e);
                }
            }

            // HORRIBLE HACK!
            if (!result.contains("rdf:RDF") && (result.contains("ERROR")))
                throw new OrcaControllerException(result);

            return result;
        } catch (CredentialException ce) {
            logger.error("getSliceManifest(): Credential Exception: " + ce.getMessage());
            throw new OrcaControllerException("ERROR: CredentialException encountered: " + ce.getMessage());
        } catch (Exception oe) {
            logger.error("getSliceManifest(): Exception encountered: " + oe.getMessage());
            oe.printStackTrace();
            throw new OrcaControllerException("ERROR: Exception encountered: " + oe);
        } finally {
            if (sm != null) {
                instance.returnSM(sm);
            }
            if (ndlSlice != null) {
                ndlSlice.getWorkflow().syncManifestModel();
                ndlSlice.getWorkflow().syncRequestModel();
                ndlSlice.unlock();
            }
        }
    }

    /**
     * Get all slice reservations in a standard way
     * 
     * @param instance
     * @param slice_urn
     * @param userDN
     * @param logger
     * @throws OrcaControllerException
     */
    public static List<ReservationMng> getSliceReservations(XmlrpcOrcaState instance, String slice_urn, String userDN,
            Logger logger) throws OrcaControllerException {

        IOrcaServiceManager sm = null;
        XmlrpcControllerSlice ndlSlice = null;
        try {
            List<ReservationMng> allRes = null;

            // find this slice and lock it
            ndlSlice = instance.getSlice(slice_urn);
            if (ndlSlice == null) {
                logger.error("getSliceReservations(): unable to find slice " + slice_urn + " among active slices");
                throw new OrcaControllerException("unable to find slice " + slice_urn + " among active slices");
            }
            // lock the slice
            ndlSlice.lock();
            ndlSlice.getStateMachine().transitionSlice(SliceCommand.REEVALUATE);
            logger.debug("Slice " + slice_urn + " transitioned to state " + ndlSlice.getStateMachine().getState());

            sm = instance.getSM();

            if (!ndlSlice.matchUserDN(userDN))
                throw new NotSliceOwnerException(slice_urn, userDN);

            try {
                allRes = ndlSlice.getAllReservations(sm);
            } catch (Exception e) {
                logger.error("getSliceReservations(): Exception encountered for " + slice_urn + ": " + e);
                throw new OrcaControllerException("nable to get reservations in slice status for " + slice_urn);
            }
            return allRes;
        } catch (CredentialException ce) {
            logger.error("getSliceReservations(): Credential Exception: " + ce.getMessage());
            throw new OrcaControllerException("CredentialException encountered: " + ce.getMessage());
        } catch (Exception oe) {
            logger.error("getSliceReservations(): Exception encountered: " + oe.getMessage());
            oe.printStackTrace();
            throw new OrcaControllerException(oe.toString());
        } finally {
            if (sm != null) {
                instance.returnSM(sm);
            }
            if (ndlSlice != null)
                ndlSlice.unlock();
        }
    }

    /**
     * Add new local properties to reservation of the form prefix.index.suffix. First find the highest index and
     * increment (if indicated, otherwise use current highest index). It also calls updateReservation on SM to save the
     * new properties. ReservationMng object is modified and not safe to use afterwards
     * 
     * @param sm
     * @param rm
     * @param propPrefix
     * @param increment
     *            - increment index or not
     * @param p
     *            - new properties
     * @return
     */
    public static Integer addIndexedLocalProperties(IOrcaServiceManager sm, ReservationMng rm, String propPrefix,
            boolean increment, Properties p) {
        try {
            PropertiesMng psmng = rm.getLocalProperties();
            if (psmng == null)
                throw new RuntimeException(
                        "addIndexedLocalProperties(): unable to get local properties for reservation "
                                + rm.getReservationID());

            Properties cp = OrcaConverter.fill(psmng);
            int index = PropList.highestPropIndex(cp, propPrefix) + (increment ? 1 : 0);

            Enumeration<?> names = p.propertyNames();

            PropertiesMng npsmng = new PropertiesMng();

            while (names.hasMoreElements()) {
                String nm = (String) names.nextElement();

                PropertyMng pmng = new PropertyMng();
                pmng.setName(propPrefix + "." + index + "." + nm);
                pmng.setValue(p.getProperty(nm));

                npsmng.getProperty().add(pmng);
            }

            rm.setLocalProperties(npsmng);
            // alternative implementation
            //
            // cp.setProperty(propPrefix + "." + index + "." + propSuffix, value);
            // psmng = OrcaConverter.fill(cp);
            // rm.setConfigurationProperties(psmng);

            sm.updateReservation(rm);

            return index;
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("Unable to add local properties " + rm.getReservationID() + " due to " + e);
        }
    }

    /**
     * Add new local properties to reservation of the form prefix.suffix. It also calls updateReservation on SM to save
     * the new properties. ReservationMng object is modified and not safe to use afterwards
     * 
     * @param sm
     * @param rm
     * @param propPrefix
     * @param increment
     *            - increment index or not
     * @param p
     *            - new properties
     * @return
     */
    public static void addLocalProperties(IOrcaServiceManager sm, ReservationMng rm, String propPrefix, Properties p) {
        try {
            PropertiesMng psmng = rm.getLocalProperties();
            if (psmng == null)
                throw new RuntimeException("addLocalProperties(): unable to get local properties for reservation "
                        + rm.getReservationID());

            Enumeration<?> names = p.propertyNames();

            PropertiesMng npsmng = new PropertiesMng();

            while (names.hasMoreElements()) {
                String nm = (String) names.nextElement();

                PropertyMng pmng = new PropertyMng();
                pmng.setName(propPrefix + "." + nm);
                pmng.setValue(p.getProperty(nm));

                npsmng.getProperty().add(pmng);
            }

            rm.setLocalProperties(npsmng);

            sm.updateReservation(rm);
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("Unable to add local properties " + rm.getReservationID() + " due to " + e);
        }
    }

    /**
     * Find an active stitch to the given reservation and return its GUID (stitch which has a performed property, but no
     * undone property)
     * 
     * @param local
     * @return
     */
    public static String findActiveStitch(Properties local, String to) {
        String retGuid = null;
        if (to == null)
            return retGuid;

        for (String key : local.stringPropertyNames()) {
            if (key.startsWith(UnitProperties.SliceStitchPrefix)) {
                String[] keyNameParts = key.split("\\.");
                if (keyNameParts.length < 3)
                    continue;
                retGuid = keyNameParts[1];
                String datePerformed = local.getProperty(UnitProperties.SliceStitchPrefix + UnitProperties.DOT + retGuid
                        + UnitProperties.DOT + UnitProperties.SliceStitchPerformed);
                String dateUndone = local.getProperty(UnitProperties.SliceStitchPrefix + UnitProperties.DOT + retGuid
                        + UnitProperties.DOT + UnitProperties.SliceStitchUndone);
                String toRes = local.getProperty(UnitProperties.SliceStitchPrefix + UnitProperties.DOT + retGuid
                        + UnitProperties.DOT + UnitProperties.SliceStitchToReservation);

                if ((to.equals(toRes)) && (datePerformed != null) && (dateUndone == null))
                    return retGuid;
            }
        }
        return null;
    }

    /**
     * Return a list of guids (possibly empty) of all stitches
     * 
     * @param local
     * @return
     */
    public static Set<String> findAllStitches(Properties local) {
        Set<String> ret = new HashSet<>();

        for (String key : local.stringPropertyNames()) {
            if (key.startsWith(UnitProperties.SliceStitchPrefix)) {
                String[] keyNameParts = key.split("\\.");
                if (keyNameParts.length < 3)
                    continue;

                if (keyNameParts != null)
                    ret.add(keyNameParts[1]);
            }
        }

        return ret;
    }

    /**
     * Return as map properties of a given stitch
     * 
     * @param local
     * @param stitchGuid
     * @return
     */
    public static Properties getStitchProperties(Properties local, String stitchGuid) {
        Properties ret = new Properties();

        if (stitchGuid == null)
            return null;

        for (String key : local.stringPropertyNames()) {
            if (key.startsWith(UnitProperties.SliceStitchPrefix + UnitProperties.DOT + stitchGuid)) {
                ret.setProperty(key, local.getProperty(key));
            }
        }
        return ret;
    }

    /**
     * Find index of modify operation matching this stitch operation guid
     * 
     * @param config
     * @param guid
     * @return
     */
    public static int findModifyIndexForStitch(Properties config, String guid) {
        int retIndex = -1;

        if (guid == null)
            return retIndex;

        for (String key : config.stringPropertyNames()) {
            if (key.startsWith(UnitProperties.ModifyPrefix)) {
                String[] keyNameParts = key.split("\\.");
                if (keyNameParts.length < 3)
                    continue;
                try {
                    retIndex = Integer.parseInt(keyNameParts[1]);
                } catch (NumberFormatException nfe) {
                    continue;
                }
                String modifyStitchGuid = config.getProperty(
                        UnitProperties.ModifyPrefix + retIndex + UnitProperties.DOT + UnitProperties.SliceStitchUUID);
                if (guid.equals(modifyStitchGuid))
                    return retIndex;
            }
        }
        return retIndex;
    }

    private static final String RESOURCE_DOMAIN_VALUE = "resource.domain.value";
    private static final String DomainPattern = "(\\w+)(vmsite|Net)/(vm|vlan)";
    private static final Pattern pattern = Pattern.compile(DomainPattern);

    /**
     * Obtain a short domain name from RESOURCE resource.domain.value property (XXXvmsite/vm or XXXvmsite/vlan or
     * XXXNet/vlan)
     * 
     * @param mng
     * @return
     */
    public static String getShortDomain(ReservationMng mng) {
        // Look at 'resource.domain.value' RESOURCE property which will XXXvmsite/vm or XXXvmsite/vlan or XXXNet/vlan,
        // match on XXX
        Properties resProps = OrcaConverter.fill(mng.getResourceProperties());

        String domain = resProps.getProperty(RESOURCE_DOMAIN_VALUE);

        if (domain == null)
            return null;

        Matcher matcher = pattern.matcher(domain);

        if (matcher.find())
            return matcher.group(1);
        else
            return null;
    }

    public static void main(String[] args) {

        try {
            Date d = parseRFC3339Date("2013-03-06T15:00:00-05:00");
            System.out.println("Date " + d.toString());
        } catch (Exception e) {
            System.out.println(e);
        }

        // System.exit(0);

        // try {
        // InputStream inStream = new FileInputStream("/Users/ibaldin/.ssl/IliaBaldine-Emulab/emulab-tmp.pem");
        // CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
        // List<String> altNames = getExtensionValue(cert, SUBJECT_ALTERNATIVE_NAME);
        // System.out.println("Alt name is: " + altNames);
        // for (String altName: altNames) {
        // try {
        // URI altNameUri = new URI(altName);
        // String r = PublicId.decodeURN(altName);
        // System.out.println("Authority: " + altNameUri.getAuthority());
        // System.out.println("Scheme-specific part: " + altNameUri.getSchemeSpecificPart());
        // System.out.println("Decoded: " + r);
        // if (r.matches("IDN .+ user .+"))
        // System.out.println("Matches!");
        // } catch(Exception e) {
        // ;
        // }
        // }
        //
        // } catch (Exception e) {
        // System.err.println("Error encountered: " + e);
        // e.printStackTrace();
        // }

        System.out.println("Testing regex: " + getShortDomain(null));

    }

}
