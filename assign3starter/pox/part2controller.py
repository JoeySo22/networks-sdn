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
    self.macToPort = {} # Keep track of which host is at what port

    # Create an action that takes any ipv4 src & dest, and icmp protocol, and accept
    # Create an action that takes any kind of src & dest, and arp protocol, and accept
    # Create an action that takes an ipv4 src & dest, and any protocol, and drop

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    
    # Add packet to the mactoport
    self.macToPort[packet.src] = event.port

    # Define accept
    def accept(priority = 5000):
        msg = of.ofp_flow_mod()
        msg.priority = priority
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.actions.append(of.ofp_action_output(port = self.macToPort[packet.dst]))
        msg.data = event.ofp
        self.connection.send(msg)

    # Define drop
    def drop():
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    
    # Define here what to do with protocols and ipv4
    ipv4_packet = packet.find('ipv4')
    if ipv4_packet:
        # 1) ipv4 src | ipv4 dest | icmp | accept
        icmp_packet = event.parsed.find('icmp')
        if icmp_packet:
            accept(priority = 4000) #Highest priority
        else:
            # 3) ipv4 src | ipv4 dest | any protocol | drop
            drop()
    else:
        arp_packet = event.parsed.find('arp')
        # 2) any src | any dest | arp | accept
        if arp_packet:
            accept(priority = 3000) # second priority

    
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
