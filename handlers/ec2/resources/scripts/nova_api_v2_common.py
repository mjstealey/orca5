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

from novaclient import client as novaclient
from neutronclient.neutron import client as neutronclient

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

    @classmethod
    def source(self, script, update=1):
        pipe = Popen(". %s; env" % script, stdout=PIPE, shell=True, env={'PATH': os.environ['PATH']})
        data = pipe.communicate()[0]
        env = dict((line.split("=", 1) for line in data.splitlines()))
        if update:
           os.environ.update(env)
        return env

class VM_Exception(Exception):
    pass

class VM_Does_Not_Exist(VM_Exception):
    pass

class Nova_Command_Fail(VM_Exception):
    pass

class Nova_Fatal_Command_Fail(Nova_Command_Fail):
    pass
    
class VM_Broken(VM_Exception):
    def __init__(self, message, vm_id, console_log):
        Exception.__init__(self,message)
        self.vm_id = str(vm_id)
        self.console_log = str(console_log)

    def get_console_log(self):
        return str(self.console_log)
   
    def get_vm_id(self):
        return str(self.vm_id)

class VM_Broken_Unpingable(VM_Broken):
    def __init__(self, message, vm_id, console_log):
        VM_Broken.__init__(self,message, vm_id, console_log)

class VM_Broken_Unsshable(VM_Broken):
    def __init__(self, message, vm_id, console_log):
        VM_Broken.__init__(self,message, vm_id, console_log)

class VM:

    def get_info_str(self):
        info=""
        try:
            info += "id                             : " + str(self.nova_server.id)+ " \n"
            info += "name                           : " + str(self.nova_server.name)+ " \n"
            info += "addresses                      : " + str(self.nova_server.addresses)+ " \n"
            info += "image                          : " + str(self.nova_server.image)+ " \n"
            info += "flavor                         : " + str(self.nova_server.flavor)+ " \n"
            info += "user_id                        : " + str(self.nova_server.user_id)+ " \n"
            info += "status                         : " + str(self.nova_server.status)+ " \n"
            info += "hostId                         : " + str(self.nova_server.hostId)+ " \n"
            info += "key_name                       : " + str(self.nova_server.key_name)+ " \n"
            info += "created                        : " + str(self.nova_server.created)+ " \n"
            info += "metadata                       : " + str(self.nova_server.metadata) + " \n"
            info += "OS-EXT-SRV-ATTR:host           : " + str(getattr(self.nova_server, 'OS-EXT-SRV-ATTR:host')) + " \n"
            info += "OS-EXT-SRV-ATTR:instance_name  : " + str(getattr(self.nova_server, 'OS-EXT-SRV-ATTR:instance_name')) + " \n"
            info += "OS-EXT-STS:vm_state            : " + str(getattr(self.nova_server, 'OS-EXT-STS:vm_state')) + " \n"
            info += "OS-SRV-USG:terminated_at       : " + str(getattr(self.nova_server, 'OS-SRV-USG:terminated_at')) + " \n"
            info += "OS-SRV-USG:launched_at         : " + str(getattr(self.nova_server, 'OS-SRV-USG:launched_at')) + " \n"
            for net in self.nova_server.addresses:
                info += "IP (self.nova_server.addresses[str(net)][0]['addr']   : " + str(self.nova_server.addresses[str(net)][0]['addr']) + " \n"
        except Exception as e:
                LOG.info('get_info_str exception: ' + str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()));

        return info

    def _start_vm(self, tenant_id, instance_type, ami, ssh_key, user_data_file, name):
        #Boot the vm
        retries = 3
        timeout = 10
        status = None
        for i in range(retries):
            try:
                #setup connection to nova
                #nova_client= client.Client('2', os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'], os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL'],connection_pool=True);
                
                #find nova properties
                #flavor=self.nova_client.flavors.list()[6]
                #flavor=self.nova_client.flavors.list()[1]
                LOG.debug('instance_type = ' + str(instance_type))
                flavor=None
                for i in self.nova_client.flavors.list():
                    #LOG.debug('Checking image: ' + str(i))
                    if i.name == instance_type:
                        flavor = i
                        break
                LOG.debug('Found flavor: ' + str(flavor.name))
                

                #image=self.nova_client.images.list()[0]
                LOG.debug('ami = ' + str(ami))
                image=None
                for i in self.nova_client.images.list():
                    #LOG.debug('Checking image: ' + str(i))
                    if i.name == ami:
                        image = i
                        break
                LOG.debug('Found image: ' + str(image.name))
                    

                network=[]
                for n in self.nova_client.networks.list():
                    LOG.debug('Network: ' +  str(n.label) + ", " + str(n.id))
                    if n.label == "flat-data-net":
                        network.append({ 'net-id': n.id })
                        break
                key=self.nova_client.keypairs.find(name=tenant_id)
                
                #start vm
                LOG.info('KEY: ' + str(key))
                LOG.info('NAME: ' + str(name))
                LOG.info('IMAGE: ' + str(image))
                LOG.info('FLAVOR: ' + str(flavor))
                LOG.info('NICS: ' + str(network))
                LOG.info('USERDATA (file name): ' + str(user_data_file))

                user_data=''
                try:
                    f = open(user_data_file, 'r')
                    user_data = f.read()
                    LOG.info('USERDATA (content): ' + str(user_data))
                    f.close()
                except Exception as e:
                    LOG.info('Exception: ' + str(e))
                    LOG.info('USERDATA (content): No userdata (file unreadable)')

                #ensure the file is closed
                try:
                    f.close()
                except:
                    pass
                            

                self.nova_server = self.nova_client.servers.create(name,image,flavor,nics=network,key_name='pruth',userdata=user_data)
                #instance = nova_client.servers.create(name,image,flavor,nics=network,key=key,userdata=user_data_file)
              
                #LOG.info('**************   Printing server attributes ******************' )
                #LOG.info('dir\n: ' + str(dir(self.nova_server)))
                #LOG.info('dir\n: ' + str(self.nova_server.__dict__))
                #LOG.info('***************************************************************')
                          
  
                instance_id = str(self.nova_server.id)
                LOG.info("PRUTH: instance - ID = " + str(self.nova_server.id)  + ", name = " + str(self.nova_server.name)  + ", status = " + str(self.nova_server.status))
                         
                status_check_retries=100
                status_check_timeout=10
                for j in range(status_check_retries):
                    self.nova_server = self.nova_client.servers.get(self.nova_server.id)

                    if str(self.nova_server.status) == 'ERROR':
                       LOG.info('nova boot fail: ID = ' + str(self.nova_server.id)  + ', name = ' + str(self.nova_server.name)  + ',  status: ' + str(self.nova_server.status))
                       self.nova_server.delete()
                       raise Nova_Command_Fail, 'nova boot failed with VM error: ' +  + str(self.nova_server.id)  + ', name = ' + str(self.nova_server.name)  + ',  status: ' + str(self.nova_server.status)
                    if str(self.nova_server.status) == 'ACTIVE':
                       LOG.info('nova boot success:  ID = ' + str(self.nova_server.id)  + ', name = ' + str(self.nova_server.name)  + ', status: ' + str(self.nova_server.status))
                       return str(self.nova_server.id)
                    LOG.info('booting VM (status_check '+ str(j) + ') ID = ' + str(self.nova_server.id)  + ', name = ' + str(self.nova_server.name)  + ', status: ' + str(self.nova_server.status))
                    time.sleep(status_check_timeout)
            
                LOG.info('booting VM timeout, clean up and retry '+ str(i) + ') ID = ' + str(self.nova_server.id)  + ', name = ' + str(self.nova_server.name)  + ', status: ' + str(self.nova_server.status))
                self.nova_server.delete()
            
            except Exception as e:
                LOG.info('booting VM exception (retry '+ str(i) + ') ' + str(name) + ', ' + str(e))

            time.sleep(timeout)
            
        #too many retries, give up
        raise Nova_Command_Fail, 'nova boot failed after ' + str(i) + ' retries, giving up'

    
    @classmethod
    def start(self, tenant_id, instance_type, ami, aki, ari, ssh_key, startup_retries, ping_retries, ssh_retries, user_data_file, name):
        LOG.debug("start " + str(name))
        self.nova_client= novaclient.Client('2', os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'], os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL'],connection_pool=True);
        new_vm = VM()
        new_vm._start_vm(tenant_id, instance_type, ami, ssh_key, user_data_file, name)
        return new_vm

    @classmethod
    def get_vm(self, id):
        LOG.debug("get_vm " + str(id))
        self.nova_client= novaclient.Client('2', os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'], os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL'],connection_pool=True)
                              
        vm = VM(self.nova_client.servers.get(id))
        
        LOG.debug("get_vm: " + str(vm))
        return vm 

    def __init__(self, nova_server=None):
        LOG.debug("creating new VM object ") 
        self.nova_server = nova_server

    def stop(self):
        LOG.debug("Stopping vm: " + self.nova_server.id)
        try:
            #setup connection to nova                                                                                                                                                                 #nova_client= client.Client('2', os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'], os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL']);

            #start vm                                                                                                                                                                                 #instance = nova_client.servers.get(id)
            
            LOG.info("PRUTH: instance - ID = " + str(self.nova_server.id)  + ", name = " + str(self.nova_server.name)  + ", status = " + str(self.nova_server.status))
            self.nova_server.delete()
        except:
            exception_msg += ", Failed cleaning up vm (" + str(self.nova_server.id) + ")"

        return

    def _get_network_id_from_network_name(self, network_name):
        neutron_client = neutronclient.Client('2.0', 
                                               username=os.environ['OS_USERNAME'], 
                                               password=os.environ['OS_PASSWORD'], 
                                               auth_url=os.environ['OS_AUTH_URL'], 
                                               tenant_name=os.environ['OS_TENANT_NAME'],
                                               connection_pool=True)

        networks = neutron_client.list_networks()

        for net in networks['networks']:
            if net['name'] == network_name:
                return net['id']

        return "netork_not_found"


    def add_iface(self, tenant, network, mac):
        LOG.info("PRUTH: add_iface not implemented")
        LOG.debug("add_iface: tenant " + tenant + ", network " + network + ", mac " + mac)

        try:
            #neutron_client = neutronclient.Client('2.0',
            #                                      username=os.environ['OS_USERNAME'],
            #                                      password=os.environ['OS_PASSWORD'],
            #                                      auth_url=os.environ['OS_AUTH_URL'],
            #                                      tenant_name=os.environ['OS_TENANT_NAME'],
            #                                      connection_pool=True)
            
            network_id = self._get_network_id_from_network_name('net-'+network)
            
            #port = {'network_id': str(network_id) ,'admin_state_up': True}
            #port = neutron_client.create_port({'port':  port})

            
            #LOG.debug("Network = " + str(network) + ", network_id = " + str(network_id))
            #LOG.debug("port = " + str(port))


            LOG.info("PRUTH: server:  id = " + str(self.nova_server.id)  + ", name = " + str(self.nova_server.name)  + ", status = " + str(self.nova_server.status))
                        
            #interface_attach(self, port_id, net_id, fixed_ip)
            self.nova_server.interface_attach(net_id=network_id, port_id=None, fixed_ip=None)
            #self.nova_server.interface_attach(port_id=port['port']['id'],net_id=None,fixed_ip=None)
        except Exception as e:
            LOG.debug("Failed add_iface (" + str(self.nova_server.id)  + ")")
            LOG.error("neutron-add-iface: " + str(type(e)) + " : " + str(e) + "\n" + str(traceback.format_exc()))

    def del_iface(self):
        #interface_detach(self, port_id)
        #interface_list(self):

        LOG.info("PRUTH: del_iface not implemented")

    def get_id(self):
        return self.nova_server.id

    def get_host_id(self):
        return self.nova_server.hostId

    def get_host_name(self):
        return str(getattr(self.nova_server, 'OS-EXT-SRV-ATTR:host'))

    def get_name(self):
        return self.nova_server.name

    def get_addresses(self):
        return self.nova_server.addresses

    def get_image(self):
        return self.nova_server.image

    def get_flavor(self):
        return self.nova_server.flavor

    def get_status(self):
        return self.nova_server.status

    def get_key_name(self):
        return self.nova_server.key_name

    def get_created_date(self):
        return self.nova_server.created
    
    def get_ip(self):
        LOG.debug("Get ip for vm: " + str(self.get_name()) + ", GET IP NOT IMPLEMENTED")
        return "GET IP NOT IMPLEMENTED"

        ip=""
        try:
                #setup connection to nova 
                nova_client= novaclient.Client('2', os.environ['OS_USERNAME'], os.environ['OS_PASSWORD'], os.environ['OS_TENANT_NAME'], os.environ['OS_AUTH_URL']);

                #start vm 
                self.nova_server = nova_client.servers.get(id)

                LOG.info("PRUTH: instance - ID = " + str(self.nova_server.id)  + ", name = " + str(self.nova_server.name)  + ", status = " + str(self.nova_server.status) + ", interface_list = " + str(self.nova_server.networks) )
                ip = self.nova_server.networks['flat-data-net'][0]
        except:
            LOG.error("Failed to get ip for self.nova_server " + str(self.nova_server.id)) 
             
        LOG.info("PRUTH: instance - ID = " + str(self.nova_server.id)  + ", returning ip: " + str(ip))
        return ip

    
# Upon import, read in the needed OpenStack credentials from one of the right places.
if (os.path.isfile(os.environ['EUCA_KEY_DIR'] + "/novarc")):
    Commands.source(os.environ['EUCA_KEY_DIR'] + "/novarc")
elif (os.path.isfile(os.environ['EUCA_KEY_DIR'] + "/openrc")):
    Commands.source(os.environ['EUCA_KEY_DIR'] + "/openrc")
else:
    pass
