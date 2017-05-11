package orca.controllers.xmlrpc;

import com.hp.hpl.jena.ontology.OntModel;
import com.hp.hpl.jena.ontology.OntResource;
import orca.embed.workflow.ManifestParserListener;
import orca.embed.workflow.RequestWorkflow;
import orca.manage.OrcaConverter;
import orca.manage.beans.ReservationMng;
import orca.manage.beans.TicketReservationMng;
import orca.ndl.NdlException;
import orca.ndl.NdlManifestParser;
import orca.ndl.elements.NetworkElement;
import orca.shirako.container.Globals;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.*;

import static orca.controllers.xmlrpc.OrcaXmlrpcHandler.*;
import static orca.controllers.xmlrpc.OrcaXmlrpcHandlerTest.CHAR_TO_MATCH_RESERVATION_COUNT;
import static orca.controllers.xmlrpc.OrcaXmlrpcHandlerTest.VALID_RESERVATION_SUMMARY_REGEX;
import static orca.controllers.xmlrpc.ReservationConverter.PropertyUnitEC2InstanceType;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class OrcaRegressionTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                // run the regression test suite
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-1.rdf", true, 1},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-1.rdf", true, 1},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-2.rdf", true, 1},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-3.rdf", true, 1},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-4.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-5.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-6.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-7.rdf", true, 8},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-8.rdf", true, 8},
                { "../../embed/src/test/resources/orca/embed/TS1/TS1-9.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-1.rdf", true, 13},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-2.rdf", true, 13},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-3.rdf", true, 5},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-4.rdf", true, 13},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-6.rdf", true, 11},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-7.rdf", true, 12},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-8.rdf", true, 4-1}, // Shared VLAN does not count as reservation.
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-9.rdf", true, 3-1+1}, // StitchPort does not count as reservation
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-10.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-11.rdf", true, 3},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-12.rdf", true, 45},
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-13.rdf", true, 5-2}, //two stitchingports on different vlans to a node on two seperate two-end broadcast links
                { "../../embed/src/test/resources/orca/embed/TS2/TS2-14.rdf", true, 10-1},//more than 2 mixed stitchingport and nodes connecting to a inter-rack MP (Flukes manifest drawing)
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-1.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-2.rdf", true, 4},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-3.rdf", true, 13+12}, // 13 in request + 12 extra for connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-4.rdf", true, 13},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-5.rdf", true, 9},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-6.rdf", true, 13},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-7.rdf", true, 8+2}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-8.rdf", true, 5+2}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-9.rdf", true, 20},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-10.rdf", true, 56},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-11.rdf", true, 42},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-12.rdf", true, 10+4}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-13.rdf", true, 10+2},
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-14.rdf", true, 99+5}, // Works here, maybe not correctly in ExoSM.
                { "../../embed/src/test/resources/orca/embed/TS3/TS3-15.rdf", true, 4+2},
                { "../../embed/src/test/resources/orca/embed/TS4/TS4-1.rdf", true, 5+4}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS4/TS4-2.rdf", true, 5+2}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS4/TS4-3.rdf", true, 10+4}, // extra connecting VLANs
                { "../../embed/src/test/resources/orca/embed/TS5/TS5-1.rdf", true, 6+4},
                { "../../embed/src/test/resources/orca/embed/mp.rdf", true, 4+6},
                { "../../embed/src/test/resources/orca/embed/106_mp.rdf", true, 4+2},
                { "../../embed/src/test/resources/orca/embed/80_mp.rdf", true, 3+6},
                //{ "../../embed/src/test/resources/orca/embed/TS7/TS7-1.rdf", true, 14-1+11}, // Deprecated. OSG site no longer exists
                { "../../embed/src/test/resources/orca/embed/request-stitchport-URLcham-TAG3291-3292.rdf", true, 3-2+4},
                { "../../embed/src/test/resources/orca/embed/request-stitchport-URLcham-URLncbi.rdf", true, 3-2+4},
                // TS8 really only tests Post-boot Scripts. Not useful in Unit tests
                /*
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-1.rdf", true, 12},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-2.rdf", true, 1},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-3.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-4.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-5.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-6.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-7.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-8.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-9.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-10.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-11.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-12.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-13.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-14.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-15.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-16.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-17.rdf", true, 6},
                { "../../embed/src/test/resources/orca/embed/TS8/TS8-18.rdf", true, 6}
                */
        });
    }

    // First Parameter -- file name with Request
    private String requestFilename;

    // Second Parameter -- whether test should pass
    private boolean expected;

    // Third Parameter -- number of Devices / Network Elements requested
    private int numDevicesInRequest;

    // JUnit automatically passes in Parameters to constructor
    public OrcaRegressionTest(String requestFilename, boolean expected, int numDevicesInRequest){
        this.requestFilename = requestFilename;
        this.expected = expected;
        this.numDevicesInRequest = numDevicesInRequest;
    }

    @Test
    public void testOrcaRegressionTests() throws Exception {
        String testName = requestFilename.substring(requestFilename.lastIndexOf('/') + 1);
        System.out.println("Starting Orca Regression Test " + testName);

        XmlRpcController controller = new MockXmlRpcController();
        controller.init();
        controller.start();

        XmlrpcControllerSlice slice = OrcaXmlrpcHandlerTest.doTestCreateSlice(controller,
                requestFilename,
                "createSlice_testRegressionTest_" + testName,
                numDevicesInRequest);

        List<TicketReservationMng> computedReservations = slice.getComputedReservations();

        if (requestFilename.contains("106_mp")){
            assertEc2InstanceTypePresent(computedReservations);
        }

        assertManifestWillProcess(slice);
    }

    /**
     * Verify that the EC2 Instance type was present
     * From Issue #106
     *
     * @param computedReservations
     */
    private void assertEc2InstanceTypePresent(List<TicketReservationMng> computedReservations) {
        for (TicketReservationMng reservation : computedReservations){
            // only check VMs for EC2 Instance Type
            System.out.println(reservation.getResourceType());
            if (!reservation.getResourceType().endsWith("vm")){
                continue;
            }

            String ec2InstanceType = OrcaConverter.getConfigurationProperty(reservation, PropertyUnitEC2InstanceType);
            assertNotNull("Could not find EC2 Instance Type in reservation " + reservation.getReservationID(), ec2InstanceType);
        }
    }

    /**
     * Verify that the resulting manifest will process.
     * Catches errors such as "orca.ndl.NdlException: Path has 1 (odd number) of endpoints"
     *
     * @param slice
     */
    private void assertManifestWillProcess(XmlrpcControllerSlice slice) {
        Logger logger = Globals.getLogger(OrcaRegressionTest.class.getSimpleName());

        RequestWorkflow workflow = slice.getWorkflow();
        List<? extends ReservationMng> computedReservations = slice.getComputedReservations();
        OntModel manifestModel = workflow.getManifestModel();
        LinkedList<OntResource> domainInConnectionList = workflow.getDomainInConnectionList();
        Collection<NetworkElement> boundElements = workflow.getBoundElements();

        // get the manifest from the created slice
        String manifest = slice.getOrc().getManifest(manifestModel, domainInConnectionList, boundElements, (List<ReservationMng>) computedReservations);

        ManifestParserListener parserListener = new ManifestParserListener(logger);
        try {
            NdlManifestParser ndlManifestParser = new NdlManifestParser(manifest, parserListener);

            // verify that the manifest can process
            ndlManifestParser.processManifest();
        } catch (NdlException e) {
            fail(e.toString());
        }
    }
}
