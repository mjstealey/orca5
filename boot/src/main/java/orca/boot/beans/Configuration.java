//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.0.2-b01-fcs 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.04.08 at 05:33:55 PM AST 
//


package orca.boot.beans;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;all>
 *         &lt;element name="global" type="{http://issg.cs.duke.edu/sharp/boot}global" minOccurs="0"/>
 *         &lt;element name="actors" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="actor" type="{http://issg.cs.duke.edu/sharp/boot}actor" maxOccurs="unbounded"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="topology" type="{http://issg.cs.duke.edu/sharp/boot}topology" minOccurs="0"/>
 *       &lt;/all>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {

})
@XmlRootElement(name = "configuration")
public class Configuration {

    protected Global global;
    protected Configuration.Actors actors;
    protected Topology topology;

    /**
     * Gets the value of the global property.
     * 
     * @return
     *     possible object is
     *     {@link Global }
     *     
     */
    public Global getGlobal() {
        return global;
    }

    /**
     * Sets the value of the global property.
     * 
     * @param value
     *     allowed object is
     *     {@link Global }
     *     
     */
    public void setGlobal(Global value) {
        this.global = value;
    }

    /**
     * Gets the value of the actors property.
     * 
     * @return
     *     possible object is
     *     {@link Configuration.Actors }
     *     
     */
    public Configuration.Actors getActors() {
        return actors;
    }

    /**
     * Sets the value of the actors property.
     * 
     * @param value
     *     allowed object is
     *     {@link Configuration.Actors }
     *     
     */
    public void setActors(Configuration.Actors value) {
        this.actors = value;
    }

    /**
     * Gets the value of the topology property.
     * 
     * @return
     *     possible object is
     *     {@link Topology }
     *     
     */
    public Topology getTopology() {
        return topology;
    }

    /**
     * Sets the value of the topology property.
     * 
     * @param value
     *     allowed object is
     *     {@link Topology }
     *     
     */
    public void setTopology(Topology value) {
        this.topology = value;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="actor" type="{http://issg.cs.duke.edu/sharp/boot}actor" maxOccurs="unbounded"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "actor"
    })
    public static class Actors {

        @XmlElement(required = true)
        protected List<Actor> actor;

        /**
         * Gets the value of the actor property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the actor property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getActor().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link Actor }
         * 
         * 
         */
        public List<Actor> getActor() {
            if (actor == null) {
                actor = new ArrayList<Actor>();
            }
            return this.actor;
        }

    }

}
