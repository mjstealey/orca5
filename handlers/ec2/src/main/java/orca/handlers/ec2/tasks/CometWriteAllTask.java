package orca.handlers.ec2.tasks;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;
import java.io.IOException;
import java.util.Properties;
import java.util.UUID;



import orca.shirako.common.meta.UnitProperties;
import orca.shirako.common.meta.ConfigurationProperties;
import orca.shirako.plugins.config.OrcaAntTask;

import org.apache.tools.ant.BuildException;

import orca.comet.accumulo.client.COMETClientUtils;
import orca.comet.accumulo.client.COMETClientImpl;


abstract class  CometWriteAllGenerator { 
    org.apache.tools.ant.Project project;

    protected org.apache.tools.ant.Project getProject(){
        return project;
    }

    //abstract public void doIt(PrintWriter out) throws Exception;

    abstract public String getOutputProperty();

}


class CometWriteAllGenerator_v1 extends CometWriteAllGenerator{
    String outputProperty;
    COMETClientImpl cometClient;
    String cometSliceID;
    String cometReservationID;

    

    public CometWriteAllGenerator_v1(org.apache.tools.ant.Project project){
	    
	this.project = project;
	this.outputProperty = "";

	Properties cometProperties = null;
	try {
	    cometProperties = COMETClientUtils.getClientConfigProps("/etc/orca/am+broker-12080/config/comet.site.properties");
	} catch (IOException e) {
	    e.printStackTrace();
	}

	cometClient = new COMETClientImpl(cometProperties);
	
	//set cometSliceID
	String temp = getProject().getProperty(UnitProperties.UnitSliceID);
        if (temp != null) {
            cometSliceID=temp;
        } else {
	    System.out.println("Error setting cometSliceID");
	}

	//set cometReservationID
        temp = getProject().getProperty(UnitProperties.UnitReservationID);
        if (temp != null) {
            cometReservationID=temp;
        } else {
	    System.out.println("Error setting cometReservationID");
	}

	//Create the new vm entry in Comet..  should be done in the controller eventually
	cometClient.createNewEntry(cometSliceID,  cometReservationID, "vm");

	
    }
    /*
    public void doIt(PrintWriter out) throws Exception {
	
	generateGlobal(out);
	generateUsers(out);
	generateInterfaces(out);
	generateStorage(out);
	generateRoutes(out);
	generateScripts(out);

    }
    */

    public String getOutputProperty(){
	return outputProperty;
    }

    

    public void writeNovaID() throws Exception {
        String novaID = getProject().getProperty("shirako.save.unit.ec2.instance");
        if (novaID != null) {
            //System.out.println("Comet writing SliceID");                                                                                                                                             
            cometClient.setNovaID(cometSliceID,  cometReservationID, novaID);
        } else {
            System.out.println("Comet Error writing novaID " + novaID + ", slice " + cometSliceID + ", reservation: " + cometReservationID);
        }
    }

    
    public void writeHostName() throws Exception {
	String hostname = getProject().getProperty(UnitProperties.UnitHostName);
        if (hostname != null) {
	    System.out.println("Comet writing HostName: " + hostname + ", slice " + cometSliceID + ", reservation: " + cometReservationID);
            cometClient.setHostname(cometSliceID,  cometReservationID, hostname);
        } else {
            System.out.println("Comet Error writing HostName " + hostname + ", slice " + cometSliceID + ", reservation: " + cometReservationID);
        }
    }

    
    public void writeScript() throws Exception {

	Integer[] scripts = getScripts();
        for (int i = 0; i < scripts.length; i++) {
            Integer scriptNum = scripts[i];
            String scriptName = UnitProperties.UnitScriptPrefix + scriptNum.toString();
            String scriptBody = getProject().getProperty(scriptName);

	    if (scriptBody == null)
                continue;

	    System.out.println("Comet writing script: " + scriptBody + ", slice " + cometSliceID + ", reservation: " + cometReservationID);
	    //should only find one for now.  Comet need to be able to handle multiple scripts
            cometClient.setScript(cometSliceID,  cometReservationID, scriptBody);
	    break; 
        }
    }

    
    public void writePhysicalHost() throws Exception {
        String physicalHost = getProject().getProperty(UnitProperties.UnitEC2Host);
        if (physicalHost != null) {
            cometClient.setPhysicalHost(cometSliceID,  cometReservationID, physicalHost);
        } else {
            System.out.println("Comet Error writing physicalHost "+ physicalHost +", slice " + cometSliceID + ", reservation: " + cometReservationID );
        }
    }

    public void writeManagmentIP() throws Exception {
        String managmentIP = getProject().getProperty(UnitProperties.UnitEC2Host);
	if (managmentIP != null) {
            cometClient.setManagementIP(cometSliceID,  cometReservationID, managmentIP);
        } else {
            System.out.println("Comet Error writing management ip: " + managmentIP  + ", slice " + cometSliceID + ", reservation: " + cometReservationID);
        }
    }

    public void writeInterfaces() throws Exception {

	Integer[] eths = getEths();

        for (int i = 0; i < eths.length; i++) {
            Integer eth = eths[i];

            // see what physical interface on the host we need to attach to                                                                                                                            
            String hosteth = getProject().getProperty(UnitProperties.UnitEthPrefix + eth.toString() + UnitProperties.UnitHostEthSuffix);
            if (hosteth == null) {
                System.out.println("Eth" + eth.toString() + " is missing hosteth. Ignoring");
                continue;
            }

            String ip = getProject().getProperty(UnitProperties.UnitEthPrefix + eth.toString() + UnitProperties.UnitEthIPSuffix);
            if (ip == null) {
                System.out.println("Eth" + eth.toString() + " does not specify an IP.");
            }


            String mac = getProject().getProperty(UnitProperties.UnitEthPrefix + eth.toString() + UnitProperties.UnitEthMacSuffix);
            if (mac == null) {
                System.out.println("Eth" + eth.toString() + " does not specify a MAC.");
                continue;
            }
            String ipVersion = getProject().getProperty(UnitProperties.UnitEthPrefix + eth.toString() + UnitProperties.UnitEthIPVersionSuffix);
            if (ipVersion == null) {
                System.out.println("Eth" + eth.toString() + " does not specify an ip version.");
                ipVersion = "ipv4";
            }

            String vlanTag = getProject().getProperty(UnitProperties.UnitEthPrefix + eth.toString() + UnitProperties.UnitEthVlanSuffix);
            if (vlanTag == null) {
                System.out.println("Eth" + eth.toString() + " does not specify a vlan tag.");
                continue;
            }

	    
            //out.print(mac.replace(":","") + "=" + state + ":" + ipVersion);

	    // attaching to vlan tag                                                                                                                                                                   
            //if (ip != null) {
	    //out.print(":" + ip);
            //}
            //out.println();

            //append iface to output property                                                                                                                                                          
            //outputProperty += hosteth + "." + vlanTag + "." + mac + " ";
	    System.out.println("Comet writing interface: mac " + mac.replace(":","") + ", ipVersion " +  ipVersion + ", ip " + ip + "state up, slice"  + cometSliceID + ", reservation: " + cometReservationID);
	    
	    cometClient.setInterface(cometSliceID,  cometReservationID, mac.replace(":",""), ipVersion, ip, "up");
	    //cometClient.setManagementIP(cometSliceID,  cometReservationID,  mac.replace(":",""));
        }



    }

    
    
    //Helper functions

    protected Integer[] getEths(){
        HashSet<Integer> set = new HashSet<Integer>();
        Hashtable<?, ?> h = project.getProperties();

        Iterator<?> i = h.entrySet().iterator();

        while (i.hasNext()) {
            Map.Entry<?, ?> entry = (Map.Entry<?, ?>) i.next();
            String key = (String) entry.getKey();
            if (key.startsWith(UnitProperties.UnitEthPrefix)) {
                key = key.substring(UnitProperties.UnitEthPrefix.length());
                int index = key.indexOf('.');
		if (index > 0){
		    key = key.substring(0, index);
                    Integer eth = new Integer(Integer.parseInt(key));
                    set.add(eth);
                }
            }
        }

        Integer[] list = new Integer[set.size()];

        int index = 0;
	for (Integer eth : set) {
            list[index++] = eth;
        }

        Arrays.sort(list);
	return list;
    }

    
    protected Integer[] getScripts(){
        HashSet<Integer> set = new HashSet<Integer>();
        Hashtable<?, ?> h = project.getProperties();

        Iterator<?> i = h.entrySet().iterator();

        while (i.hasNext()) {
            Map.Entry<?, ?> entry = (Map.Entry<?, ?>) i.next();
            String key = (String) entry.getKey();
            if (key.startsWith(UnitProperties.UnitScriptPrefix)) {
                key = key.substring(UnitProperties.UnitScriptPrefix.length());
                int index = key.indexOf('.');
                if (index > 0){
                    key = key.substring(0, index);
                }
                Integer script = new Integer(Integer.parseInt(key));
                set.add(script);
            }
        }

        Integer[] list = new Integer[set.size()];

        int index = 0;
        for (Integer script : set) {
            list[index++] = script;
        }

        Arrays.sort(list);
        return list;
    }



}


public class CometWriteAllTask extends OrcaAntTask{
    //protected String file;
    // protected String cloudType;
    //protected String outputProperty;


    public void execute() throws BuildException {
		
	try {
            super.execute();
            //if (file == null) {
            //    throw new Exception("Missing file parameter");
            //}
	    //if (cloudType == null) {
	    //throw new Exception("Missing cloudType parameter");
	    //}


            CometWriteAllGenerator_v1 generator = new CometWriteAllGenerator_v1(getProject());
	    
	    generator.writeScript();
	    generator.writePhysicalHost();
	    generator.writeManagmentIP();
	    generator.writeInterfaces();
	    generator.writeHostName();

	    //if(outputProperty != null)
	    //getProject().setProperty(outputProperty,generator.getOutputProperty());
	    
	} catch (BuildException e) {
            throw e;
        } catch (Exception e) {
            throw new BuildException("An error occurred: " + e.getMessage(), e);
        }
    }
    /*
    public void setFile(String file) {
        this.file = file;
    }

    public void setCloudtype(String cloudtype) {
        this.cloudType = cloudtype;
    }
    */
    
    /*
    public void setOutputproperty(String outputproperty) {
        this.outputProperty = outputproperty;
    }
    */
    
}
