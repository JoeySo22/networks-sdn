from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 3000
    first_rule.match.dl_type = 0x0806 # Value for ARP packets
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 2000
    second_rule.match.dl_type = 0x0800 # ip here
    second_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    second_rule.match.nw_proto = 1 # icmp
    self.connection.send(second_rule)
    #put switch 1 rules here
    # Send here connection.send()
    pass

  def s2_setup(self):
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 3000
    first_rule.match.dl_type = 0x0806 # Value for ARP packets
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 2000
    second_rule.match.dl_type = 0x0800 # ip here
    second_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    second_rule.match.nw_proto = 1
    self.connection.send(second_rule)
    #put switch 2 rules here
    # Send here connection.send()
    pass

  def s3_setup(self):
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 3000
    first_rule.match.dl_type = 0x0806 # Value for ARP packets
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 2000
    second_rule.match.dl_type = 0x0800 # ip here
    second_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    second_rule.match.nw_proto = 1
    self.connection.send(second_rule)
    #put switch 3 rules here
    # Send here connection.send()
    pass

  def cores21_setup(self):
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 2000
    first_rule.match.dl_type = 0x0806 # Value for ARP packets
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 3000
    second_rule.match.dl_type = 0x0800 # ip here
    second_rule.match.nw_dst = IPAddr("172.16.10.100")
    second_rule.match.nw_src = IPAddr("10.0.1.10")
    second_rule.actions.append(of.ofp_action_output(port = 1)) 
    second_rule.match.nw_proto = 1 # icmp
    self.connection.send(second_rule)
    
    w_rule = of.ofp_flow_mod()
    w_rule.priority = 3000
    w_rule.match.dl_type = 0x0800 # ip here
    w_rule.match.nw_dst = IPAddr("172.16.10.100")
    w_rule.match.nw_src = IPAddr("10.0.2.20")
    w_rule.actions.append(of.ofp_action_output(port = 1)) 
    w_rule.match.nw_proto = 1
    self.connection.send(w_rule)
    
    a_rule = of.ofp_flow_mod()
    a_rule.priority = 3000
    a_rule.match.dl_type = 0x0800 # ip here
    a_rule.match.nw_dst = IPAddr("172.16.10.100")
    a_rule.match.nw_src = IPAddr("10.0.3.30")
    a_rule.actions.append(of.ofp_action_output(port = 1)) 
    a_rule.match.nw_proto = 1
    self.connection.send(a_rule)
    
    b_rule = of.ofp_flow_mod()
    b_rule.priority = 3000
    b_rule.match.dl_type = 0x0800 # ip here
    b_rule.match.nw_dst = IPAddr("172.16.10.100")
    b_rule.match.nw_src = IPAddr("10.0.4.10")
    b_rule.actions.append(of.ofp_action_output(port = 1)) 
    b_rule.match.nw_proto = 1
    self.connection.send(b_rule)
    
    third_rule = of.ofp_flow_mod()
    third_rule.priority = 2800
    #third_rule.match.dl_src = EthAddr((IPS["hnotrust"][1]))
    third_rule.match.dl_type = 0x0800 # ip here
    third_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    third_rule.matchnw_proto = 1
    self.connection.send(third_rule)
    #put core switch rules here
    # Send here connection.send()
    pass

  def dcs31_setup(self):
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 3000
    first_rule.match.dl_type = 0x0806 # Value for ARP packets
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 2000
    second_rule.match.dl_type = 0x0800 # ip here
    second_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    second_rule.match.nw_proto = 1
    self.connection.send(second_rule)
    #put datacenter switch rules here
    # Send here connection.send()
    pass

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
