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

// IMPLEMENT THIS METHOD

void
SimpleRouter::forwardPacket(const Buffer& packet, const std::string& outIface, const Buffer& src_addr) {  
  const Interface* iface = findIfaceByName(outIface);

  ethernet_hdr eth_hdr;
  memcpy(eth_hdr.ether_dhost, src_addr.data(), ETHER_ADDR_LEN *
    sizeof(unsigned char));
  memcpy(eth_hdr.ether_shost, (iface->addr).data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  eth_hdr.ether_type = htons(ethertype_ip);
  Buffer eth_frame;
  eth_frame.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr + 14);

  const ip_hdr *iphdr = (const ip_hdr*)(packet.data() + 14);
  ip_hdr iph;
  iph.ip_hl = iphdr->ip_hl;
  iph.ip_v = iphdr->ip_v;
  iph.ip_tos = iphdr->ip_tos;
  iph.ip_len = iphdr->ip_len;
  iph.ip_id = iphdr->ip_id;
  iph.ip_off = iphdr->ip_off;
  iph.ip_ttl = ((iphdr->ip_ttl) - 1);
  iph.ip_p = iphdr->ip_p;
  iph.ip_sum = 0;
  iph.ip_src = iphdr->ip_src;
  iph.ip_dst = iphdr->ip_dst;
  
  //below
  Buffer ip_cksum;
  ip_cksum.assign((unsigned char*)&iph, (unsigned char*)&iph
    + sizeof(ip_hdr));
  iph.ip_sum = cksum(ip_cksum.data(), ip_cksum.size());

  Buffer ip_frame;
  ip_frame.assign((unsigned char*)&iph, (unsigned char*)&iph + sizeof(ip_hdr));
  
  eth_frame.insert(eth_frame.end(), ip_frame.begin(), ip_frame.end());
  eth_frame.insert(eth_frame.end(), packet.data() + sizeof(ethernet_hdr) +
    sizeof(ip_hdr), packet.data() + packet.size());
  
  sendPacket(eth_frame, outIface);
}

void
SimpleRouter::sendPacketToDestination(std::shared_ptr<ArpRequest> req, Buffer& dst_macAddr, const std::string& outIface) {
  const Interface* iface = findIfaceByName(outIface);
  Buffer src_addr = iface->addr;

  for(const auto& p : req->packets) {
    ethernet_hdr eth_hdr;
    memcpy(eth_hdr.ether_dhost, dst_macAddr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
    memcpy(eth_hdr.ether_shost, src_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
    eth_hdr.ether_type = htons(ethertype_ip);
    Buffer eth_frame;
    eth_frame.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr + 14);

    const ip_hdr *iphdr = (const ip_hdr*)(p.packet.data() + 14);
    ip_hdr iph;
    iph.ip_hl = iphdr->ip_hl;
    iph.ip_v = iphdr->ip_v;
    iph.ip_tos = iphdr->ip_tos;
    iph.ip_len = iphdr->ip_len;
    iph.ip_id = iphdr->ip_id;
    iph.ip_off = iphdr->ip_off;
    iph.ip_ttl = (iphdr->ip_ttl) - 1;
    iph.ip_p = iphdr->ip_p;
    iph.ip_sum = 0;
    iph.ip_src = iphdr->ip_src;
    iph.ip_dst = iphdr->ip_dst;

    Buffer ip_cksum;
    ip_cksum.assign((unsigned char*)&iph, (unsigned char*)&iph
      + sizeof(ip_hdr));
    iph.ip_sum = cksum(ip_cksum.data(), ip_cksum.size());

    Buffer ip_frame;
    ip_frame.assign((unsigned char*)&iph, (unsigned char*)&iph + sizeof(ip_hdr));

    eth_frame.insert(eth_frame.end(), ip_frame.begin(), ip_frame.end());
    eth_frame.insert(eth_frame.end(), p.packet.data() + sizeof(ethernet_hdr) +
      sizeof(ip_hdr), p.packet.data() + p.packet.size());

    std::cerr << "Iface: " << outIface << std::endl;
    std::cerr << "\n*******************************" << std::endl;
    std::cerr << "* Forwarding packet from router *" << std::endl;
    std::cerr << "*********************************" << std::endl;
    print_hdrs(eth_frame);
    sendPacket(eth_frame, outIface);
  }

  return;
}

void
SimpleRouter::sendTimeExceeded(const Buffer& packet, const std::string& inIface,
  uint8_t type, uint8_t code, uint32_t ip, const Buffer& addr) {
  const ethernet_hdr *ehdr = (const ethernet_hdr *)(packet.data());
  const ip_hdr *iphdr = (const ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

  // ethernet header
  ethernet_hdr eth_hdr;
  memcpy(eth_hdr.ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(eth_hdr.ether_shost, addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  eth_hdr.ether_type = htons(ethertype_ip);

  // ip header
  ip_hdr iph;
  iph.ip_hl = iphdr->ip_hl;
  iph.ip_v = iphdr->ip_v;
  iph.ip_tos = iphdr->ip_tos;
  iph.ip_len = htons(56);
  iph.ip_id = iphdr->ip_id;
  iph.ip_off = iphdr->ip_off;
  iph.ip_ttl = 64;
  iph.ip_p = ip_protocol_icmp;
  iph.ip_sum = 0;
  iph.ip_src = ip;
  iph.ip_dst = iphdr->ip_src;

    //below
  Buffer ip_cksum;
  ip_cksum.assign((unsigned char*)&iph, (unsigned char*)&iph
    + sizeof(ip_hdr));
  iph.ip_sum = cksum(ip_cksum.data(), ip_cksum.size());

  // icmp header
  icmp_t3_hdr icmph;
  icmph.icmp_type = type;    
  icmph.icmp_code = code;    //type 0
  icmph.icmp_sum = 0x0;
  icmph.unused = 0x0;       //pad with 0
  icmph.next_mtu = 0x0;     //pad with 0

  std::copy(packet.data() + sizeof(ethernet_hdr), packet.data() + sizeof(ethernet_hdr) + ICMP_DATA_SIZE, icmph.data);
 
  
  Buffer icmp_cksum;
  icmp_cksum.assign((unsigned char*)&icmph, (unsigned char*)&icmph
    + sizeof(icmp_t3_hdr));
  // icmp_cksum.insert(icmp_cksum.end(), packet.data() + sizeof(ethernet_hdr),
    // packet.data() + sizeof(ethernet_hdr) + ICMP_DATA_SIZE);
  icmph.icmp_sum = cksum(icmp_cksum.data(), icmp_cksum.size());
  
  Buffer eth_frame;
  eth_frame.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr + sizeof(ethernet_hdr));
  Buffer ip_frame;
  ip_frame.assign((unsigned char*)&iph, (unsigned char*)&iph + sizeof(ip_hdr));
  Buffer icmp_frame;
  icmp_frame.assign((unsigned char*)&icmph, (unsigned char*)&icmph + sizeof(icmp_t3_hdr));
  
  eth_frame.insert(eth_frame.end(), ip_frame.begin(), ip_frame.end());
  eth_frame.insert(eth_frame.end(), icmp_frame.begin(), icmp_frame.end());
  // eth_frame.insert(eth_frame.end(), packet.data() + sizeof(ethernet_hdr),
    // packet.data() + sizeof(ethernet_hdr) + ICMP_DATA_SIZE);
  
  std::cerr << "\n******************************" << std::endl;
  std::cerr << "* Sending ICMP Time Exceeded Response back to client *" << std::endl;
  std::cerr << "******************************" << std::endl;
  print_hdrs(eth_frame);
  sendPacket(eth_frame, inIface);
  return;
}


Buffer
SimpleRouter::getICMPResponse(const Buffer& packet, const std::string& inIface) {
  const ethernet_hdr *ehdr = (const ethernet_hdr *)(packet.data());
  const ip_hdr *iphdr = (const ip_hdr *)(packet.data() + sizeof(ethernet_hdr));
	
  // ethernet header
  ethernet_hdr eth_hdr;
  memset(eth_hdr.ether_dhost, 0, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(eth_hdr.ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN * sizeof(unsigned char));
  eth_hdr.ether_type = htons(ethertype_ip);
  
  // ip header
  ip_hdr iph;
  iph.ip_hl = iphdr->ip_hl;
  iph.ip_v = iphdr->ip_v;
  iph.ip_tos = iphdr->ip_tos;
  iph.ip_len = iphdr->ip_len;
  iph.ip_id = iphdr->ip_id;
  iph.ip_off = iphdr->ip_off;
  iph.ip_ttl = 65;
  iph.ip_p = iphdr->ip_p;
  iph.ip_sum = iphdr->ip_sum;
  iph.ip_src = iphdr->ip_dst;
  iph.ip_dst = iphdr->ip_src;
  
  // icmp header
  icmp_hdr icmph;
  icmph.icmp_type = 0x0;
  icmph.icmp_code = 0x0;
  icmph.icmp_sum = 0x0;
  
  Buffer icmp_cksum;
  icmp_cksum.assign((unsigned char*)&icmph, (unsigned char*)&icmph
    + sizeof(icmp_hdr));
  icmp_cksum.insert(icmp_cksum.end(), packet.data() + sizeof(ethernet_hdr)
    + sizeof(ip_hdr) + sizeof(icmp_hdr), packet.data() + packet.size());
  icmph.icmp_sum = cksum(icmp_cksum.data(), icmp_cksum.size());
  
  Buffer eth_frame;
  eth_frame.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr + sizeof(ethernet_hdr));
  Buffer ip_frame;
  ip_frame.assign((unsigned char*)&iph, (unsigned char*)&iph + sizeof(ip_hdr));
  Buffer icmp_frame;
  icmp_frame.assign((unsigned char*)&icmph, (unsigned char*)&icmph + sizeof(icmp_hdr));
  
  eth_frame.insert(eth_frame.end(), ip_frame.begin(), ip_frame.end());
  eth_frame.insert(eth_frame.end(), icmp_frame.begin(), icmp_frame.end());
  eth_frame.insert(eth_frame.end(), packet.data() + sizeof(ethernet_hdr)
    + sizeof(ip_hdr) + sizeof(icmp_hdr), packet.data() + packet.size());
  
  std::cerr << "\n******************************" << std::endl;
  std::cerr << "* Constructing ICMP Response back to client *" << std::endl;
  std::cerr << "******************************" << std::endl;
  print_hdrs(eth_frame);
  return eth_frame;
}

void SimpleRouter::sendARPRequest(uint32_t ip) {
  RoutingTableEntry r_entry = m_routingTable.lookup(ip);
  const Interface* outIface = findIfaceByName(r_entry.ifName);
  
  // ARP header
  Buffer send_arp_req;
  arp_hdr arp_req;
  arp_req.arp_hrd = htons(arp_hrd_ethernet);
  arp_req.arp_pro = htons(ethertype_ip);
  arp_req.arp_hln = ETHER_ADDR_LEN;
  arp_req.arp_pln = 0x04;
  arp_req.arp_op = htons(arp_op_request);
  
  // source ip and hardware address
  Buffer mac_addr = outIface->addr;
  memcpy(arp_req.arp_sha, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  arp_req.arp_sip = outIface->ip;

  // target ip and hardware address
  uint8_t broadcast[6];
  memset(broadcast, 0x00, 6);
  memcpy(arp_req.arp_tha, &broadcast, ETHER_ADDR_LEN * sizeof(unsigned char));
  arp_req.arp_tip = ip;
  
  memset(broadcast, 0xFF, 6);
  
  // ethernet header
  ethernet_hdr eth_hdr;
  memcpy(eth_hdr.ether_dhost, &broadcast, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(eth_hdr.ether_shost, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  eth_hdr.ether_type = htons(ethertype_arp);
  
  // create packet
  Buffer packet;
  packet.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr + 14);
  Buffer arp_packet;
  arp_packet.assign((unsigned char*)&arp_req, (unsigned char*)&arp_req + 28);
  packet.insert(packet.end(), arp_packet.begin(), arp_packet.end());
  
  // send the packet
  std::cerr << "\n*********************************" << std::endl;
  std::cerr << "* Sending ARP request from router *" << std::endl;
  std::cerr << "***********************************" << std::endl;
  print_hdrs(packet);
  sendPacket(packet, outIface->name);
}

void 
SimpleRouter::handleArpRequest(const Buffer& packet, const std::string& inIface) {
  const arp_hdr *arphdr = reinterpret_cast<const arp_hdr*>(packet.data()
    + sizeof(ethernet_hdr));
  
  // Check if ARP Request is to the router
  const Interface* iface = findIfaceByIp(arphdr->arp_tip);
  if (iface == nullptr) {
    std::cerr << "IP address is does not match any of the router interfaces";
    std::cerr << std::endl;
    return;
  }

  // Sending MAC address of router interface
  // ARP formats
  arp_hdr arp_reply;
  arp_reply.arp_hrd = htons(arp_hrd_ethernet);
  arp_reply.arp_pro = htons(ethertype_ip);
  arp_reply.arp_hln = ETHER_ADDR_LEN;
  arp_reply.arp_pln = 0x04;
  arp_reply.arp_op = htons(arp_op_reply);
  
  // source ip and hardware address
  Buffer mac_addr = iface->addr;
  memcpy(arp_reply.arp_sha, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  arp_reply.arp_sip = iface->ip;

  // target ip and hardware address
  memcpy(arp_reply.arp_tha, arphdr->arp_sha, ETHER_ADDR_LEN * sizeof(unsigned char));
  arp_reply.arp_tip = arphdr->arp_sip;
  
  // ethernet header
  ethernet_hdr eth_hdr;
  memcpy(eth_hdr.ether_dhost, arphdr->arp_sha, ETHER_ADDR_LEN * sizeof(unsigned char));
  memcpy(eth_hdr.ether_shost, mac_addr.data(), ETHER_ADDR_LEN * sizeof(unsigned char));
  eth_hdr.ether_type = htons(ethertype_arp);
  
  // Making Buffers of ethernet and arp headwe
  Buffer send_packet;
  send_packet.assign((unsigned char*)&eth_hdr, (unsigned char*)&eth_hdr
    + sizeof(ethernet_hdr));
  Buffer arp_packet;
  arp_packet.assign((unsigned char*)&arp_reply, (unsigned char*)&arp_reply
    + sizeof(arp_hdr));

  // Combining the Buffers
  send_packet.insert(send_packet.end(), arp_packet.begin(), arp_packet.end());
  
  std::cerr << "\n******************************" << std::endl;
  std::cerr << "* Sending ARP back to client *" << std::endl;
  std::cerr << "******************************" << std::endl;
  print_hdrs(send_packet);
  sendPacket(send_packet, inIface);
  
  return;
}


void 
SimpleRouter::handleArpReply(const Buffer& packet, const std::string& inIface) {
  const arp_hdr *arphdr = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
  Buffer mac_address(arphdr->arp_sha, arphdr->arp_sha + ETHER_ADDR_LEN);
 
  std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac_address, arphdr->arp_sip);

  if(req != nullptr) {
    //send all packets
    sendPacketToDestination(req, mac_address, inIface);
    m_arp.removeRequest(req);
  }
}

void
SimpleRouter::handleIP(const Buffer& packet, const std::string& inIface) {
  const ip_hdr *iphdr = (const ip_hdr *)(packet.data() + sizeof(ethernet_hdr));
  //Insufficient header length
  if (iphdr->ip_hl < 5) {
    fprintf(stderr, "Insufficient length for header of IP packet\n");
  }

  //Failed checksum
  uint8_t* ip_frame = (uint8_t*)(packet.data() + sizeof(ethernet_hdr));
  if (cksum(ip_frame, iphdr->ip_hl * 4) != 0xFFFF) {
	  fprintf(stderr, "Failed checksum, discard IP packet\n");
  }

  
  const Interface* iface = findIfaceByIp(iphdr->ip_dst);
  // Directed to router
  if (iface != nullptr) {
    // ICMP packet
    if (iphdr->ip_p == ip_protocol_icmp) {
      Buffer response = getICMPResponse(packet, inIface);
	  RoutingTableEntry r_entry = m_routingTable.lookup(iphdr->ip_src);
      std::shared_ptr<ArpEntry> a_entry = m_arp.lookup(iphdr->ip_src);
      if(a_entry == nullptr) {
        //queue mapping
        m_arp.queueRequest(iphdr->ip_src, response, r_entry.ifName);
      }
      else {
        //forward back to client
        forwardPacket(response, r_entry.ifName, a_entry->mac);
      }
    }
    else if (iphdr->ip_p == 0x11 || iphdr->ip_p == 0x06)  {
      const Interface* iface_icmp = findIfaceByIp(iphdr->ip_dst);
      sendTimeExceeded(packet, inIface, 0x0003, 0x0003, iphdr->ip_dst,
        iface_icmp->addr);
    }
    // Discard all other packets directed to router that is not ICMP
    else {
      std::cerr << "Discarded non-ICMP packet to router" << std::endl;
      return;  
    }
  }
  // Not directed to router
  else {
    //TTL is 0
    if(iphdr->ip_ttl == 1) {
      std::cerr << "TTL will be 0" << std::endl;
      const Interface* iface_icmp = findIfaceByName(inIface);
      sendTimeExceeded(packet, inIface, 0x000B, 0x0000, iface_icmp->ip,
	    iface_icmp->addr);
      return;
    }
    
    RoutingTableEntry r_entry = m_routingTable.lookup(iphdr->ip_dst);
    //finds entry
	std::shared_ptr<ArpEntry> a_entry = m_arp.lookup(iphdr->ip_dst);
	
    //IP to MAC mapping not in cache
    if(a_entry == nullptr) {
      //queue mapping
      m_arp.queueRequest(iphdr->ip_dst, packet, r_entry.ifName);
    }
    else {
      //forward back to client
      forwardPacket(packet, r_entry.ifName, a_entry->mac);
    }
  }
  
  return;
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "\n********************************" << std::endl;
  std::cerr << "* Packet received, printing... *" << std::endl;
  std::cerr << "********************************" << std::endl;
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  
  print_hdrs(packet);

  // get current interface
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring";
    std::cerr << std::endl;
    return;
  }
  
  std::string dest_addr = macToString(packet);
  std::string iface_addr = macToString(iface->addr);
  if (dest_addr.compare("ff:ff:ff:ff:ff:ff") && dest_addr.compare(iface_addr)) {
	  std::cerr << "Dropped packet, since destination MAC address is invalid";
	  std::cerr << std::endl;
	  return;
  }
  
  //convert packet data into a *uint8_t so we can access it better
  uint8_t* hdr = (uint8_t*)(packet.data());
  uint16_t e_type = ethertype(hdr);
  
  // if the ethrnet frame is not ARP or IPv4
  if(e_type != ethertype_arp && e_type != ethertype_ip) {
	std::cerr << "ERROR: Not ARP or IPv4 Ether type" << std::endl;
  }
  // Packet is ARP
  else if (e_type == ethertype_arp) {
    const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(packet.data()+sizeof(ethernet_hdr));
    if(ntohs(hdr->arp_op) == arp_op_request) {
      handleArpRequest(packet, inIface);
    }
	// handle arp_op_reply
    else {
      handleArpReply(packet, inIface);
    }
  }
  // Packet is IP
  else {
	  handleIP(packet, inIface);
  }
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
