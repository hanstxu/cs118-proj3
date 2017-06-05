/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

void
SimpleRouter::getPacket(const Buffer& ether_hdr, const Buffer& payload) {
  return;
}



// IMPLEMENT THIS METHOD
std::string get_str_mac(const unsigned char* addr) {
  char sep = ':';
  char s[18];
  std::string res = "";
  
  snprintf(s, sizeof(s), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x",
           addr[0], sep, addr[1], sep, addr[2], sep,
           addr[3], sep, addr[4], sep, addr[5]);
  
  res = std::string(s);
  return res;
}

void 
SimpleRouter::handleARP(const Buffer& packet, const std::string& inIface) {

  // print_hdr_arp(packet.data() + 14);

  Buffer eth_src_addr(packet.begin() + 6, packet.end() + 12);
  std::string src_addr = macToString(eth_src_addr);
  
  uint8_t* arp_frame = (uint8_t*)(packet.data() + sizeof(ethernet_hdr));
  const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(arp_frame);
  std::string arp_src_addr = get_str_mac(hdr->arp_sha);
  
  // ignore other requests
  if (src_addr.compare(arp_src_addr) != 0) {
    fprintf(stderr, "ERROR: ethernet src mac does not match with ARP src mac");
    return;
  }
  
  std::shared_ptr<ArpEntry> entry = m_arp.lookup(hdr->arp_tip);

  //entry == nullptr means that the entry was not in the cache

  //currently just send, TODO: if statement to check if we should reply back to client
  if (entry == nullptr) {
	  arp_hdr arp_reply;
    arp_reply.arp_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
    arp_reply.arp_pro = htons(ethertype_ip);                 /* format of protocol address   */
    arp_reply.arp_hln = ETHER_ADDR_LEN;               /* length of hardware address   */
    arp_reply.arp_pln = 0x04;                         /* length of protocol address   */
    arp_reply.arp_op = htons(arp_op_reply);                /* ARP opcode (command)         */

    //mac address of router
    const Interface* iface = findIfaceByName(inIface);
    if (iface == nullptr) {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }
    Buffer mac_addr = iface->addr;
    memcpy(arp_reply.arp_sha, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));      //sender hardware address
    arp_reply.arp_sip = iface->ip;

    //TODO: Fill in with proper arp_target hardware address
    memcpy(arp_reply.arp_tha, hdr->arp_sha, ETHER_ADDR_LEN * sizeof(unsigned char));                 /* target hardware address      */
    arp_reply.arp_tip = hdr->arp_sip;                 /* target IP address            */
    

    // // std::cerr << "Debug Print: " << arp_reply.arp_sha << " " << arp_reply.arp_tha << std::endl;
    std::cerr << "Should be the destination ethernet address: " << get_str_mac(hdr->arp_sha) << std::endl;
    std::cerr << "Should be the source ethernet address: " << get_str_mac(mac_addr.data()) << std::endl;
    

    ethernet_hdr ether_reply;
    memcpy(ether_reply.ether_dhost, (hdr->arp_sha), ETHER_ADDR_LEN * sizeof(unsigned char)); /* destination ethernet address */
    memcpy(ether_reply.ether_shost, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char)); /* source ethernet address */
    ether_reply.ether_type = htons(ethertype_arp);                  /* packet type ID */


    Buffer send_packet1;
    send_packet1.assign((unsigned char*)&ether_reply, (unsigned char*)&ether_reply + 14);
    Buffer send_packet2;
    send_packet2.assign((unsigned char*)&arp_reply, (unsigned char*)&arp_reply + 28);

    send_packet1.insert(send_packet1.end(), send_packet2.begin(), send_packet2.end());
    print_hdrs(send_packet1);

    std::cerr<< "Hello world"<< std::endl;
    std::cerr << "arp_reply.arp_tip" << arp_reply.arp_tip;

    //const Interface* oiface = findIfaceByIp(arp_reply.arp_tip);


    //std::string oiface = findIfaceByIp(arp_reply.arp_tip)->name;
    
    //std::cerr << "Print oiface: " << oiface << std::endl;
    sendPacket(send_packet1, inIface);

    // queue
    // m_arp.queueRequest(hdr->arp_tip, send_buffer, inIface);
    //send arp req
    const std::string outIface = "";
    // sendPacket(send_packet, outIface);
    


  }
  else {
	  // forward IP address
	  // arp_hdr send_arp;
	  
	  // sendPacket();
  }
  
  
  return;
}

void
SimpleRouter::handleIP(const Buffer& packet, const std::string& inIface) {
  // 14 = size of ethernet header
  uint16_t ip_size = packet.size() - 14;
  // TODO: maybe or maybe not include
  if (ip_size < 2) {
    std::cerr << "Invalid ip size length" << std::endl;
  }

  uint8_t* frame = (uint8_t*)(packet.data());
  uint8_t* ip_frame = frame + sizeof(ethernet_hdr);
  const ip_hdr *iphdr = (const ip_hdr *)(ip_frame);
  uint16_t min_size = sizeof(icmp_hdr);
  if (ip_size < min_size) {
    fprintf(stderr, "Failed sent IP packet, insufficient length for header\n");
  }

  uint16_t ip_id = iphdr->ip_id;
  
  // ICMP packet
  if (ip_id == 0x01) {
	  
  }
  // forward packet
  else {
	  
  }


  return;
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  //std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  std::cerr << "Printing..." << std::endl;
  
  print_hdrs(packet);

  //convert packet data into a *uint8_t so we can access it better
  uint8_t* hdr = (uint8_t*)(packet.data());
  
  uint16_t e_type = ethertype(hdr);
  
  // if the ethrnet frame is not ARP or IPv4
  if(e_type != ethertype_arp && e_type != ethertype_ip) {
    // TODO: print a message?
	std::cerr << "ERROR: Not ARP or IPv4 Ether type" << std::endl;
  }
  
  // get current interface
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  
  std::string dest_addr = macToString(packet);
  std::cerr << "Incoming packet dest hardware address (MAC address): ";
  std::cerr << dest_addr << std::endl;
  
  std::string iface_addr = macToString(iface->addr);
  std::cerr << "This interface mac address: ";
  std::cerr << macToString(iface->addr) << std::endl;
  
  if (dest_addr.compare("ff:ff:ff:ff:ff:ff") && dest_addr.compare(iface_addr)) {
    // TODO: decide whether to print a message
	std::cerr << "Dropped packet, since destination MAC address is invalid";
	std::cerr << std::endl;
  }

  if (e_type == ethertype_arp) {
	  handleARP(packet, inIface);
  }
  else if (e_type == ethertype_ip) {
	  handleIP(packet, inIface);
  }
  else {
	  // TODO: reformat control statements
	  std::cerr << "Packet should be dropped" << std::endl;
  }
  
  //Prints the routing table info
  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
