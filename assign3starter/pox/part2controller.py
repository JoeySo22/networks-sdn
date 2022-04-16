from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)


    ''' It seems like dl_type of the match allows us to specify the protocols'''
    # Create an action that takes any ipv4 src & dest, and icmp protocol, and accept
    first_rule = of.ofp_flow_mod()
    first_rule.priority = 3000
    first_rule.match.dl_type = 0x0800 # Value for ipv4
    first_rule.match.nw_proto = 1 # icmp selection
    first_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # Send to all
    self.connection.send(first_rule)
    # Create an action that takes any kind of src & dest, and arp protocol, and accept
    second_rule = of.ofp_flow_mod()
    second_rule.priority = 2000
    second_rule.match.dl_type = 0x0806 # arp here
    second_rule.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) 
    self.connection.send(second_rule)
    # Create an action that takes an ipv4 src & dest, and any protocol, and drop
    third_rule = of.ofp_flow_mod()
    third_rule.priority = 1000
    third_rule.match.dl_type = 0x0800 # IP
    third_rule.buffer_id = None
    self.connection.send(third_rule)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    
    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet :" + str(packet.dump()))

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
