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

    #add switch rules here

    # Create an action that takes any ipv4 src & dest, and icmp protocol, and accept
    flow_mod_1 = of.ofp_flow_mod()
    flow_mod_1.match = of.ofp_match(
    # Create an action that takes any kind of src & dest, and arp protocol, and accept
    # Create an action that takes an ipv4 src & dest, and any protocol, and drop

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    
    # Define here what to do with protocols and ipv4
    ipv4_packet = packet.find('ipv4')
    if ipv4_packet:
        # 1) ipv4 src | ipv4 dest | icmp | accept
        tcp_packet = event.parsed.find('icmp')
    

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
