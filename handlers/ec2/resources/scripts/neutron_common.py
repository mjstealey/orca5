#!/usr/bin/env python                                                                                                                                                   

import os
import sys
import logging as LOG
import logging.handlers
import signal
import string
import time
import traceback

from subprocess import *
from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL
from subprocess import PIPE, Popen

#from novaclient import client
from neutronclient.neutron import client

class Commands:
    @classmethod
    def run_cmd(self, args):
        cmd = args
        LOG.debug("running command: " + " ".join(cmd))
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        retval = p.communicate()[0]
                
        return retval


    @classmethod
    def run(self, args, cwd = None, shell = False, kill_tree = True, timeout = -1, env = None):
        '''
        Run a command with a timeout after which it will be forcibly
        killed.

        Mostly from Alex Martelli solution (probably from one of his 
        python books) posted on stackoverflow.com
        '''
        class Alarm(Exception):
            pass
        def alarm_handler(signum, frame):
            raise Alarm

        LOG.debug("run: args= " + str(args))
        #p = Popen(args, shell = shell, cwd = cwd, stdout = PIPE, stderr = PIPE, env = env)
        p = Popen(args, stdout=PIPE, stderr=STDOUT)
        if timeout != -1:
            signal(SIGALRM, alarm_handler)
            alarm(timeout)
        try:
            stdout, stderr = p.communicate()
            if timeout != -1:
                alarm(0)
        except Alarm:
            pids = [p.pid]
            if kill_tree:
                pids.extend(self._get_process_children(p.pid))
            for pid in pids:
                # process might have died before getting to this line
                # so wrap to avoid OSError: no such process
                try: 
                    kill(pid, SIGKILL)
                except OSError:
                    pass
            return -9, '', ''
        return p.returncode, stdout, stderr

    @classmethod
    def _get_process_children(self, pid):
        p = Popen('ps --no-headers -o pid --ppid %d' % pid, shell = True,
                  stdout = PIPE, stderr = PIPE)
        stdout, stderr = p.communicate()
        return [int(p) for p in stdout.split()]


class NEuca_Quantum_Exception(Exception):
    pass

class NEuca_Quantum_Port_Plugged_In_Exception(Exception):
    pass

class Neutron_Network:
    

    @classmethod
    def create(self, tenant_id, network, net_name):
        LOG.debug("Neutron_Network.create is not defined")
        LOG.debug("Neutron_Network.create: tenant_id " + str(tenant_id) + ", network " + str(network) + ", net_name " + str(net_name))
        LOG.debug("Neutron_Network.create: username " + os.environ['NEUTRON_USERNAME'] + ", password " + os.environ['NEUTRON_PASSWORD'] + ", tenant_name " + os.environ['NEUTRON_AUTH_URL'] + ", auth_url " + os.environ['NEUTRON_TENANT_ID'])
        #neutron_client = client.Client('2.0', username=os.environ['NEUTRON_USERNAME'], password=os.environ['NEUTRON_PASSWORD'], tenant_name=os.environ['NEUTRON_AUTH_URL'], auth_url=os.environ['NEUTRON_TENANT_ID'],connection_pool=True);
        new_net = Neutron_Network()
        new_net.create_network(tenant_id, network, net_name)
        return new_net



    def getUUID(self):
        LOG.debug("Neutron_Network.getUUID is not defined")
        return '123456'


    def create_network(self, tenant_id, network, net_name ):
        #name ='vlan:data:101:11111:1111'
        name = str(tenant_id) + ":" + str(network) + ":" + str(net_name)

        neutron_client = client.Client('2.0', username=os.environ['NEUTRON_USERNAME'], password=os.environ['NEUTRON_PASSWORD'], auth_url=os.environ['NEUTRON_AUTH_URL'], tenant_name=os.environ['NEUTRON_TENANT_ID'],connection_pool=True);

        #neutron net-create data-net2
        network = {'name': 'net-'+str(net_name), 'admin_state_up': True}
        network = neutron_client.create_network({'network':  network})
        
        LOG.debug("Network = " + str(network))
        
        #neutron subnet-create data-net2  --name data-subnet2 172.16.0.0/24
        subnet = {'name': 'subnet-'+str(net_name), 'network_id': network['network']['id'],'cidr': '0.0.0.0/1', 'ip_version': 4}
        subnet = neutron_client.create_subnet({'subnet':subnet})

        LOG.debug("Subnet = " + str(subnet))
        
        
        return network['network']['id']


    @classmethod
    def delete_network(self, tenant_id, network_uuid):
        #name ='vlan:data:101:11111:1111'                                                                                                                                                                   
        name = str(tenant_id) + ":" + str(network) + ":" + str(net_name)

        neutron_client = client.Client('2.0', username=os.environ['NEUTRON_USERNAME'], password=os.environ['NEUTRON_PASSWORD'], auth_url=os.environ['NEUTRON_AUTH_URL'], tenant_name=os.environ['NEUTRON_TENANT_ID'],connection_pool=True);

        #network = {'name': 'net-'+str(net_name), 'admin_state_up': True}
        network = neutron_client.delete_network(network_uuid)

        LOG.debug("Network = " + str(network_uuid))

        
        return 'done deleting network'


    @classmethod
    def add_iface_to_network(self, tenant_id, network_uuid, instance_name, mac_addr):

        #iface_name instance-00000004.fe:16:3e:00:00:02
        iface_name = str(instance_name) + "." + str(mac_addr) 

        #quantum create_port $tenant_id $net_id
        cmd = ["quantum", "create_port", str(tenant_id), str(network_uuid) ]
        rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60) #TODO: needs real timeout

        LOG.debug("rtncode: " + str(rtncode))
        LOG.debug("data_stdout: " + str(data_stdout))
        LOG.debug("data_stderr: " + str(data_stderr))

        if rtncode != 0:
            raise NEuca_Quantum_Exception, "Add iface Failed (create_port), bad error code (" + str(rtncode) + ") : " + str(cmd)

        data_split = data_stdout.split()
        LOG.debug(str(data_split))
        if len(data_split) >= 7:
            port_uuid = data_split[6].strip()
        else:
            raise NEuca_Quantum_Exception, "Add iface Failed (create_port), bad stdout: cmd = " + str(cmd) + "\nstdout = " + str(data_stdout)


        #quantum quantum plug_iface $tenant_id $net_id $port_id instance-00000004.fe:16:3e:00:00:02
        cmd = ["quantum", "plug_iface", str(tenant_id), str(network_uuid), str(port_uuid), str(iface_name) ]
        rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60) #TODO: needs real timeout 

        LOG.debug("rtncode: " + str(rtncode))
        LOG.debug("data_stdout: " + str(data_stdout))
        LOG.debug("data_stderr: " + str(data_stderr))

        if rtncode != 0:
            self._clean_iface(tenant_id, network_uuid, port_uuid)
            raise NEuca_Quantum_Exception, "Add iface Failed (plug_iface), bad error code (" + str(rtncode) + ") : " + str(cmd)

        data_split = data_stdout.split()
        LOG.debug(str(data_split))
        if len(data_split) >= 14:
            reported_iface_name = data_split[2].strip()
            reported_port_uuid = data_split[6].strip()
            reported_network_uuid = data_split[10].strip()
            reported_tenant_id = data_split[13].strip()
        else:
            self._clean_iface(tenant_id, network_uuid, port_uuid)
            raise NEuca_Quantum_Exception, "Add iface Failed (plug_iface), bad stdout: cmd = " + str(cmd) + "\nstdout = " + str(data_stdout)


        if reported_iface_name != iface_name or reported_port_uuid != port_uuid or reported_network_uuid != network_uuid or reported_tenant_id != tenant_id:
            self._clean_iface(tenant_id, network_uuid, port_uuid)
            raise NEuca_Quantum_Exception, "Delete Network Failed, bad stdout reported info does not match supplied info: cmd = " + str(cmd) + "\nstdout = " + str(data_stdout)

        return port_uuid

    @classmethod
    def remove_iface_from_network(self, tenant_id, network_uuid, port_uuid):
        
        self._clean_iface(tenant_id, network_uuid, port_uuid)
        
        return 'OK'

    @classmethod
    def get_network_uuid_for_port(self, tenant_id, iface_uuid):
        #quantum  $tenant_id $net_id 

        cmd = ["quantum", "list_nets_detail", str(tenant_id) ]
        rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60) #TODO: needs real timeout

        LOG.debug("rtncode: " + str(rtncode))
        LOG.debug("data_stdout: " + str(data_stdout))
        LOG.debug("data_stderr: " + str(data_stderr))

        if rtncode != 0:
            raise NEuca_Quantum_Exception, "list_nets_detail failed, bad error code (" + str(rtncode) + ") : " + str(cmd)

        foundIt=False
        lines = data_stdout.split('\n')
        for line in lines:
            line = line.split()
            if len(line) >= 5:
                network_uuid = line[4].strip()

                ports_cmd = ["quantum", "list_ports", str(tenant_id), str(network_uuid) ]
                ports_rtncode,ports_data_stdout,ports_data_stderr = Commands.run(ports_cmd, timeout=60) #TODO: needs real timeout                                                                                 

                LOG.debug("ports_rtncode: " + str(ports_rtncode))
                LOG.debug("ports_data_stdout: " + str(ports_data_stdout))
                LOG.debug("ports_data_stderr: " + str(ports_data_stderr))

                if ports_rtncode != 0:
                    raise NEuca_Quantum_Exception, "list_ports failed, bad error code (" + str(ports_rtncode) + ") : " + str(ports_cmd)

                if iface_uuid in ports_data_stdout: 
                    foundIt = True
                    break
                
                

        if foundIt:
           return network_uuid;
        else:
           return None

    @classmethod
    def remove_all_vm_ifaces(self, tenant_id, iface_uuids):

        for iface_uuid in iface_uuids:
            network_uuid = NEuca_Quantum_Network.get_network_uuid_for_port(tenant_id, iface_uuid)
            if not network_uuid == None:
                NEuca_Quantum_Network.remove_iface_from_network(tenant_id, network_uuid, iface_uuid)
            else:
                LOG.debug("could not find network_uuid for iface " + iface_uuid)
                return 'OK'


    @classmethod
    def get_network_uuid(self, tenant_id, vlan_tag, switch_name):

        #quantum  $tenant_id $net_id
        cmd = ["quantum", "list_nets_detail", str(tenant_id) ]
        rtncode,data_stdout,data_stderr = Commands.run(cmd, timeout=60) #TODO: needs real timeout

        LOG.debug("rtncode: " + str(rtncode))
        LOG.debug("data_stdout: " + str(data_stdout))
        LOG.debug("data_stderr: " + str(data_stderr))
	
        if rtncode != 0:
            raise NEuca_Quantum_Exception, "list_nets_detail failed, bad error code (" + str(rtncode) + ") : " + str(cmd)

	foundIt=False
        lines = data_stdout.split('\n')
	for line in lines:
            line = line.split()
            if len(line) >= 5:
                network_name = line[1].strip()
                network_uuid = line[4].strip()	            
	
  	        network_info = network_name.split(":")
	        if len(network_info) >= 3:
                   if network_info[1] == switch_name and network_info[2] == str(vlan_tag):
                      foundIt=True
                      break

        if foundIt:
	   return network_uuid;
        else: 
	   return None
   



    




