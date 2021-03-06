//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.0.2-b01-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.04.08 at 05:33:55 PM AST 
//


package orca.boot.beans;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for global complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="global">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;all>
 *         &lt;element name="startTime" type="{http://www.w3.org/2001/XMLSchema}long"/>
 *         &lt;element name="cycleMillis" type="{http://www.w3.org/2001/XMLSchema}long"/>
 *         &lt;element name="firstTick" type="{http://www.w3.org/2001/XMLSchema}long"/>
 *         &lt;element name="manualTicks" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="containerGuid" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="locations" type="{http://issg.cs.duke.edu/sharp/boot}locations" minOccurs="0"/>
 *         &lt;element name="database" type="{http://issg.cs.duke.edu/sharp/boot}instance" minOccurs="0"/>
 *       &lt;/all>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "global", propOrder = {

})
public class Global {

    protected long startTime;
    protected long cycleMillis;
    protected long firstTick;
    protected boolean manualTicks;
    protected String containerGuid;
    protected Locations locations;
    protected Instance database;

    /**
     * Gets the value of the startTime property.
     * 
     */
    public long getStartTime() {
        return startTime;
    }

    /**
     * Sets the value of the startTime property.
     * 
     */
    public void setStartTime(long value) {
        this.startTime = value;
    }

    /**
     * Gets the value of the cycleMillis property.
     * 
     */
    public long getCycleMillis() {
        return cycleMillis;
    }

    /**
     * Sets the value of the cycleMillis property.
     * 
     */
    public void setCycleMillis(long value) {
        this.cycleMillis = value;
    }

    /**
     * Gets the value of the firstTick property.
     * 
     */
    public long getFirstTick() {
        return firstTick;
    }

    /**
     * Sets the value of the firstTick property.
     * 
     */
    public void setFirstTick(long value) {
        this.firstTick = value;
    }

    /**
     * Gets the value of the manualTicks property.
     * 
     */
    public boolean isManualTicks() {
        return manualTicks;
    }

    /**
     * Sets the value of the manualTicks property.
     * 
     */
    public void setManualTicks(boolean value) {
        this.manualTicks = value;
    }

    /**
     * Gets the value of the containerGuid property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getContainerGuid() {
        return containerGuid;
    }

    /**
     * Sets the value of the containerGuid property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setContainerGuid(String value) {
        this.containerGuid = value;
    }

    /**
     * Gets the value of the locations property.
     * 
     * @return
     *     possible object is
     *     {@link Locations }
     *     
     */
    public Locations getLocations() {
        return locations;
    }

    /**
     * Sets the value of the locations property.
     * 
     * @param value
     *     allowed object is
     *     {@link Locations }
     *     
     */
    public void setLocations(Locations value) {
        this.locations = value;
    }

    /**
     * Gets the value of the database property.
     * 
     * @return
     *     possible object is
     *     {@link Instance }
     *     
     */
    public Instance getDatabase() {
        return database;
    }

    /**
     * Sets the value of the database property.
     * 
     * @param value
     *     allowed object is
     *     {@link Instance }
     *     
     */
    public void setDatabase(Instance value) {
        this.database = value;
    }

}
