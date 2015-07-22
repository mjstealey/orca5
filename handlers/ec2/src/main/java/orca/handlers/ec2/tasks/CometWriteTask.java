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

import orca.shirako.common.meta.UnitProperties;
import orca.shirako.common.meta.ConfigurationProperties;
import orca.shirako.plugins.config.OrcaAntTask;

import org.apache.tools.ant.BuildException;

import orca.comet.accuClient;

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
