# Copyright 2017 AT&T Intellectual Property.  All other rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Driver for controlling OOB interface via IPMI.

Based on Openstack Ironic Pyghmi driver.
"""

import time

from pyghmi.ipmi.command import Command
from pyghmi.exceptions import IpmiException
try:
    from pyghmi.ipmi.private import localsession, session
except ImportError:
    localsession = None
    session = None

from drydock_provisioner.orchestrator.actions.orchestrator import BaseAction

import drydock_provisioner.error as errors

import drydock_provisioner.objects.fields as hd_fields


"""Needed until proper Session logout is enabled upstream
Logout currently hangs when using pyghmi based BMC
remove session from Session.initting_sessions"""
class BridgeableSession(session.Session):
    def __new__(cls,
                bmc,
                userid,
                password,
                port=623,
                kg=None,
                onlogon=None,
                privlevel=4,
                keepalive=True,
                bridge_request=()):

        return super().__new__(cls=cls,
                                bmc=bmc,
                                userid=userid,
                                password=password,
                                port=port,
                                kg=kg,
                                onlogon=onlogon,                     
                                privlevel=privlevel
                                # keepalive=keepalive # 1.4.1
                                )
    def __init__(self,
                 bmc,
                 userid,
                 password,
                 port=623,
                 kg=None,
                 onlogon=None,
                 privlevel=4,
                 keepalive=True,
                 bridge_request=()):

        """Set bridge_request."""
        self.bridge_request = bridge_request

        super().__init__(bmc=bmc,
                         userid=userid,
                         password=password,
                         port=port,
                         kg=kg,
                         onlogon=onlogon,                     
                         privlevel=privlevel
                         # keepalive=keepalive  # 1.4.1
                         )
    
    def logout(self, sessionok=True):
        result = super().logout() # (sessionok=sessionok) # 1.4.1

        if result.get('success', False):
            try:
                logging.debug("Clossing Session: %s" % self.sessionid)
                # Added to initting_sessions in __new__
                # userid and password are initialized as utf-8 encoded in __init__
                del Session.initting_sessions[(self.bmc, 
                                            self.userid.decode('utf-8'),
                                            self.password.decode('utf-8'),
                                            self.port,
                                            self.kgo)]
            except KeyError:
                pass
        
        return result


"""Needed until proper Command bridging is enabled upstream
Logout currently hangs when using pyghmi based BMC
remove session from Session.initting_sessions"""
class BridgeableCommand(Command):
    """Send Bridged IPMI commands to BMCs.
    
    :param bmc: hostname or ip address of the BMC (default is local)
    :param userid: username to use to connect (default to no user)
    :param password: password to connect to the BMC (defaults to no password)
    :param onlogon: function to run when logon completes in an asynchronous
                    fashion.  This will result in a greenthread behavior.
    :param kg: Optional parameter to use if BMC has a particular Kg configured
    :param bridge_request: The target slave address and channel number for
                               the bridge request.
    """
    def __init__(self, bmc=None, userid=None, password=None, port=623,
                 onlogon=None, kg=None,  privlevel=4, verifycallback=None,
                 keepalive=True, bridge_request=()):

        """Set bridge_request."""
        self.bridge_request = bridge_request

        # super().__init__(bmc=bmc, userid=userid, password=password, port=port,
        #                  onlogon=onlogon, kg=kg, privlevel=4)


        # TODO(jbjohnso): accept tuples and lists of each parameter for mass
        # operations without pushing the async complexities up the stack
        self.onlogon = onlogon
        self.bmc = bmc
        self._sdrcachedir = None
        self._sdr = None
        self._oem = None
        self._oemknown = False
        # self._netchannel = bridge_request.get('channel', None)
        self._netchannel = None
        self._ipv6support = None
        self.certverify = verifycallback
        if bmc is None:
            self.ipmi_session = localsession.Session()
        elif onlogon is not None:
            self.ipmi_session = BridgeableSession(bmc=bmc,
                                                userid=userid,
                                                password=password,
                                                onlogon=self.logged,
                                                port=port,
                                                kg=kg,
                                                privlevel=privlevel,
                                                keepalive=keepalive,
                                                bridge_request=bridge_request)
            # induce one iteration of the loop, now that we would be
            # prepared for it in theory
            BridgeableSession.wait_for_rsp(0)
        else:
            self.ipmi_session = BridgeableSession(bmc=bmc,
                                                userid=userid,
                                                password=password,
                                                port=port,
                                                kg=kg,
                                                privlevel=privlevel,
                                                keepalive=keepalive,
                                                bridge_request=bridge_request)
    def __init__(self, bmc=None, userid=None, password=None, port=623,
                 onlogon=None, kg=None, bridge_request=()):

        """Set bridge_request."""
        self.bridge_request = bridge_request

        super().__init__(bmc=bmc, userid=userid, password=password, port=port,
                         onlogon=onlogon, kg=kg)
    
    def raw_command(self, netfn, command, bridge_request=(), data=(),
                    delay_xmit=None, retry=True, timeout=None):
        """Send raw ipmi command to BMC

        This allows arbitrary IPMI bytes to be issued.  This is commonly used
        for certain vendor specific commands.

        Example: ipmicmd.raw_command(netfn=0,command=4,data=(5))

        :param netfn: Net function number
        :param command: Command value
        :param bridge_request: The target slave address and channel number for
                               the bridge request.
        :param data: Command data as a tuple or list
        :param retry: Whether or not to retry command if no response received.
                      Defaults to True
        :param timeout: A custom amount of time to wait for initial reply
        :returns: dict -- The response from IPMI device
        """

        """Replace param bridge_request if empty."""
        if self.bridge_request and not bridge_request:
            bridge_request = self.bridge_request

        return super().raw_command(netfn=netfn, command=command,
                                   bridge_request=bridge_request,
                                   data=data, delay_xmit=delay_xmit,
                                   retry=retry, timeout=timeout)

class PyghmiBaseAction(BaseAction):
    """Base action for Pyghmi executed actions."""

    def get_ipmi_session(self, node):
        """Initialize a Pyghmi IPMI session to the node.

        :param node: instance of objects.BaremetalNode
        :return: An instance of pyghmi.ipmi.command.Command initialized to nodes' IPMI interface
        """
        def get_int_or_none(value):
            """Get int or None.
            
            :param value: value to convert to int
            :return: int or None if error
            """

            if value is not None:
                try:
                    value = int(value)
                except ValueError:
                    """Set value to None"""                                   
                    value = None
            return value

        if node.oob_type != 'ipmi':
            raise errors.DriverError("Node OOB type is not IPMI")

        ipmi_network = node.oob_parameters['network']
        ipmi_address = node.get_network_address(ipmi_network)

        if ipmi_address is None:
            raise errors.DriverError(
                "Node %s has no IPMI address" % (node.name))

        ipmi_account = node.oob_parameters['account']
        ipmi_credential = node.oob_parameters['credential']

        """The remote IPMI RMCP port. 
            By default pyghmi will use the port 623"""
        ipmi_port = get_int_or_none(node.oob_parameters.get('port', 623))

        """The bridging type.
            Default is 'no' or None; other supported values are 'single' for single bridge"""
        bridge_request = None
        ipmi_bridging = node.oob_parameters.get('bridging', 'no')
        """TODO: add support for 'dual' for double bridge to bring parity with openstack ironic"""
        if ipmi_bridging == 'single':
            """The target slave address and channel number for the bridge request.
               Required only if ipmi_bridging is set to 'single'."""
            ipmi_target_address = get_int_or_none(
                node.oob_parameters.get('target_address', 0x0))
            ipmi_target_channel = get_int_or_none(
                node.oob_parameters.get('target_channel', 0x0))
            bridge_request = { 'addr': ipmi_target_address, 
                               'channel': ipmi_target_channel }

            self.logger.info("IPMI Command Bridging enabled with target address (%s) and channel (%s)" %
                             (ipmi_target_address, ipmi_target_channel))

        self.logger.debug("Starting IPMI session to %s with %s/%s" %
                          (ipmi_address, ipmi_account, ipmi_credential[:1]))
        ipmi_session = BridgeableCommand(
            bmc=ipmi_address, userid=ipmi_account, password=ipmi_credential, 
            port=ipmi_port, bridge_request=bridge_request)

        return ipmi_session

    def exec_ipmi_command(self, node, func, *args):
        """Call an IPMI command after establishing a session.

        :param node: Instance of objects.BaremetalNode to execute against
        :param func: The pyghmi Command method to call
        :param args: The args to pass the func
        """
        attempts = 0
        while attempts < 5:
            try:
                self.logger.debug("Initializing IPMI session")
                ipmi_session = self.get_ipmi_session(node)
            except (IpmiException, errors.DriverError) as iex:
                self.logger.error(
                    "Error initializing IPMI session for node %s" % node.name)
                self.logger.debug("IPMI Exception: %s" % str(iex))
                self.logger.warning(
                    "IPMI command failed, retrying after 15 seconds...")
                time.sleep(15)
                attempts = attempts + 1
                continue

            try:
                self.logger.debug("Calling IPMI command %s on %s" %
                                  (func.__name__, node.name))
                response = func(ipmi_session, *args)
                ipmi_session.ipmi_session.logout()
                return response
            except IpmiException as iex:
                self.logger.error("Error sending command: %s" % str(iex))
                self.logger.warning(
                    "IPMI command failed, retrying after 15 seconds...")
                time.sleep(15)
                attempts = attempts + 1

        raise errors.DriverError("IPMI command failed.")


class ValidateOobServices(PyghmiBaseAction):
    """Action to validation OOB services are available."""

    def start(self):
        self.task.add_status_msg(
            msg="OOB does not require services.",
            error=False,
            ctx='NA',
            ctx_type='NA')
        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.success()
        self.task.save()

        return


class ConfigNodePxe(PyghmiBaseAction):
    """Action to configure PXE booting via OOB."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            self.task.add_status_msg(
                msg="Pyghmi doesn't configure PXE options.",
                error=True,
                ctx=n.name,
                ctx_type='node')
        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.failure()
        self.task.save()
        return


class SetNodeBoot(PyghmiBaseAction):
    """Action to configure a node to PXE boot."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            self.logger.debug("Setting bootdev to PXE for %s" % n.name)
            self.task.add_status_msg(
                msg="Setting node to PXE boot.",
                error=False,
                ctx=n.name,
                ctx_type='node')
            self.exec_ipmi_command(n, BridgeableCommand.set_bootdev, 'pxe')

            time.sleep(3)

            bootdev = self.exec_ipmi_command(n, BridgeableCommand.get_bootdev)

            if bootdev is not None and (bootdev.get('bootdev',
                                                    '') == 'network'):
                self.task.add_status_msg(
                    msg="Set bootdev to PXE.",
                    error=False,
                    ctx=n.name,
                    ctx_type='node')
                self.logger.debug("%s reports bootdev of network" % n.name)
                self.task.success(focus=n.name)
            else:
                self.task.add_status_msg(
                    msg="Unable to set bootdev to PXE.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.task.failure(focus=n.name)
                self.logger.warning(
                    "Unable to set node %s to PXE boot." % (n.name))

        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.save()
        return


class PowerOffNode(PyghmiBaseAction):
    """Action to power off a node via IPMI."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            self.logger.debug("Sending set_power = off command to %s" % n.name)
            self.task.add_status_msg(
                msg="Sending set_power = off command.",
                error=False,
                ctx=n.name,
                ctx_type='node')
            self.exec_ipmi_command(n, BridgeableCommand.set_power, 'off')

            i = 18

            while i > 0:
                self.logger.debug("Polling powerstate waiting for success.")
                power_state = self.exec_ipmi_command(n, BridgeableCommand.get_power)
                if power_state is not None and (power_state.get(
                        'powerstate', '') == 'off'):
                    self.task.add_status_msg(
                        msg="Node reports power off.",
                        error=False,
                        ctx=n.name,
                        ctx_type='node')
                    self.logger.debug(
                        "Node %s reports powerstate of off" % n.name)
                    self.task.success(focus=n.name)
                    break
                time.sleep(10)
                i = i - 1

            if power_state is not None and (power_state.get('powerstate', '')
                                            != 'off'):
                self.task.add_status_msg(
                    msg="Node failed to power off.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.logger.error("Giving up on IPMI command to %s" % n.name)
                self.task.failure(focus=n.name)

        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.save()
        return


class PowerOnNode(PyghmiBaseAction):
    """Action to power on a node via IPMI."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            self.logger.debug("Sending set_power = off command to %s" % n.name)
            self.task.add_status_msg(
                msg="Sending set_power = on command.",
                error=False,
                ctx=n.name,
                ctx_type='node')
            self.exec_ipmi_command(n, BridgeableCommand.set_power, 'off')

            i = 18

            while i > 0:
                self.logger.debug("Polling powerstate waiting for success.")
                power_state = self.exec_ipmi_command(n, BridgeableCommand.get_power)
                if power_state is not None and (power_state.get(
                        'powerstate', '') == 'on'):
                    self.logger.debug(
                        "Node %s reports powerstate of on" % n.name)
                    self.task.add_status_msg(
                        msg="Node reports power on.",
                        error=False,
                        ctx=n.name,
                        ctx_type='node')
                    self.task.success(focus=n.name)
                    break
                time.sleep(10)
                i = i - 1

            if power_state is not None and (power_state.get('powerstate', '')
                                            != 'on'):
                self.task.add_status_msg(
                    msg="Node failed to power on.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.logger.error("Giving up on IPMI command to %s" % n.name)
                self.task.failure(focus=n.name)

        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.save()
        return


class PowerCycleNode(PyghmiBaseAction):
    """Action to hard powercycle a node via IPMI."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            self.logger.debug("Sending set_power = off command to %s" % n.name)
            self.task.add_status_msg(
                msg="Power cycling node via IPMI.",
                error=False,
                ctx=n.name,
                ctx_type='node')
            self.exec_ipmi_command(n, BridgeableCommand.set_power, 'off')

            # Wait for power state of off before booting back up
            # We'll wait for up to 3 minutes to power off
            i = 18

            while i > 0:
                power_state = self.exec_ipmi_command(n, BridgeableCommand.get_power)
                if power_state is not None and power_state.get(
                        'powerstate', '') == 'off':
                    self.logger.debug("%s reports powerstate of off" % n.name)
                    break
                elif power_state is None:
                    self.logger.debug(
                        "No response on IPMI power query to %s" % n.name)
                time.sleep(10)
                i = i - 1

            if power_state.get('powerstate', '') == 'on':
                self.task.add_status_msg(
                    msg="Failed to power down during power cycle.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.logger.warning(
                    "Failed powering down node %s during power cycle task" %
                    n.name)
                self.task.failure(focus=n.name)
                break

            self.logger.debug("Sending set_power = on command to %s" % n.name)
            self.exec_ipmi_command(n, BridgeableCommand.set_power, 'on')

            i = 18

            while i > 0:
                power_state = self.exec_ipmi_command(n, BridgeableCommand.get_power)
                if power_state is not None and power_state.get(
                        'powerstate', '') == 'on':
                    self.logger.debug("%s reports powerstate of on" % n.name)
                    break
                elif power_state is None:
                    self.logger.debug(
                        "No response on IPMI power query to %s" % n.name)
                time.sleep(10)
                i = i - 1

            if power_state is not None and (power_state.get('powerstate',
                                                            '') == 'on'):
                self.task.add_status_msg(
                    msg="Node power cycle complete.",
                    error=False,
                    ctx=n.name,
                    ctx_type='node')
                self.task.success(focus=n.name)
            else:
                self.task.add_status_msg(
                    msg="Failed to power up during power cycle.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.logger.warning(
                    "Failed powering up node %s during power cycle task" %
                    n.name)
                self.task.failure(focus=n.name)

        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.save()
        return


class InterrogateOob(PyghmiBaseAction):
    """Action to complete a basic interrogation of the node IPMI interface."""

    def start(self):
        self.task.set_status(hd_fields.TaskStatus.Running)
        self.task.save()

        design_status, site_design = self.orchestrator.get_effective_site(
            self.task.design_ref)
        node_list = self.orchestrator.process_node_filter(
            self.task.node_filter, site_design)

        for n in node_list:
            try:
                self.logger.debug(
                    "Interrogating node %s IPMI interface." % n.name)
                powerstate = self.exec_ipmi_command(n, BridgeableCommand.get_power)
                if powerstate is None:
                    raise errors.DriverError()
                self.task.add_status_msg(
                    msg="IPMI interface interrogation yielded powerstate %s" %
                    powerstate.get('powerstate'),
                    error=False,
                    ctx=n.name,
                    ctx_type='node')
                self.task.success(focus=n.name)
            except errors.DriverError:
                self.logger.debug(
                    "Interrogating node %s IPMI interface failed." % n.name)
                self.task.add_status_msg(
                    msg="IPMI interface interrogation failed.",
                    error=True,
                    ctx=n.name,
                    ctx_type='node')
                self.task.failure(focus=n.name)

        self.task.set_status(hd_fields.TaskStatus.Complete)
        self.task.save()
        return
