package orca.handlers.ec2.tasks;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Properties;
import java.util.UUID;

import orca.shirako.common.meta.UnitProperties;
import orca.shirako.common.meta.ConfigurationProperties;
import orca.shirako.plugins.config.OrcaAntTask;

import org.apache.tools.ant.BuildException;

import orca.comet.accumulo.client.COMETClientUtils;
import orca.comet.accumulo.client.COMETClientImpl;

public class CometWriteTask extends OrcaAntTask{
    protected String sliceid;
    protected String reservationid;
    protected String key;
    protected String value;
    protected String outputProperty;

    public void execute() throws BuildException {
		
	try {
            super.execute();

	    System.out.println("CometWriteTask: sliceid       = " + sliceid);
	    System.out.println("CometWriteTask: reservationid = " + reservationid);
	    System.out.println("CometWriteTask: key           = " + key );
	    System.out.println("CometWriteTask: value         = " + value);
	    
	    //    /etc/orca/am+broker-12080/config/comet.site.properties

	    
	    Properties props = null;
	    try {
		props = COMETClientUtils.getClientConfigProps("/etc/orca/am+broker-12080/config/comet.site.properties");
	    } catch (IOException e) {
		e.printStackTrace();
	    }
	    
	    System.out.println("comet 100");
	    COMETClientImpl cometClient = new COMETClientImpl(props);
	    
	    System.out.println("comet 101");

	    cometClient.createNewEntry("a", "b", "vm");
	    

	    System.out.println("comet 102");

	    
	    cometClient.setInterface("a", "b", "mac1", "ipv6","123.123.123.123/24", "up");
	    
	    /*
	    cometClient.setInterface("a", "b", "mac1", "ipv4","121.121.2.2", "down");
	    cometClient.setHostname("a", "b", "myvmhostname");
	    

	    System.out.println("comet 110");


	    System.out.println("Hostname: "+ cometClient.getHostname("a", "b"));
	    cometClient.setManagementIP("a", "b", "1.1.1.1");
	    System.out.println("MgmpIP: " + cometClient.getManagementIpAddress("a", "b"));
	    cometClient.setNovaID("a", "b", UUID.randomUUID().toString());
	    System.out.println("Novaid "+ cometClient.getNovaID("a", "b"));
	    cometClient.setPhysicalHost("a", "b", "myphysicalhost");
	    System.out.println("PM: "+ cometClient.getPhysicalHost("a", "b"));
	     
	    cometClient.setType("a", "b", "baremetal");
	    System.out.println("Type "+ cometClient.getType("a","b"));
	    
	    System.out.println("comet 1000");
	    */
	    
	    //if(outputProperty != null)
	    //getProject().setProperty(outputProperty,generator.getOutputProperty());
	    
  
	} catch (BuildException e) {
            throw e;
        } catch (Exception e) {
            throw new BuildException("An error occurred: " + e.getMessage(), e);
        }
    }

    public void setSliceid(String sliceid) {
        this.sliceid = sliceid;
    }
    public void setReservationid(String reservationid) {
        this.reservationid = reservationid;
    }
    public void setKey(String key) {
        this.key = key;
    }

    public void setValue(String value) {
        this.value = value;
    }

    

    public void setOutputproperty(String outputproperty) {
        this.outputProperty = outputproperty;
    }

    
}
