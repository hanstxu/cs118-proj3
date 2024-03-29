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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// IMPLEMENT THIS METHOD

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // FILL THIS IN
  std::list<std::shared_ptr<ArpEntry>> cacheEntriesToRemove;
  uint32_t req_size = m_arpRequests.size();
  
  //Handle all requests in queued requests
  for(auto& request : m_arpRequests) {
    handle_arpreq(request);
	if (req_size != m_arpRequests.size())
		return;
  }
  
  std::shared_ptr<ArpEntry> remove_entry;
  
  // Remove invalid entries
  for (auto& entry : m_cacheEntries) {
    if(!entry->isValid) {
      //record entry for removal
      cacheEntriesToRemove.push_back(entry);
    }
  }
  
  //remove entry marked for removal
  for (auto& entry : cacheEntriesToRemove) {
	  m_cacheEntries.remove(entry);
  }
}

void
ArpCache::handle_arpreq(std::shared_ptr<ArpRequest>& req) {
  time_point now = steady_clock::now();
  //int elapsed_time = 
  //  std::chrono::duration_cast<std::chrono::microseconds>((now - req->timeSent)).count();
  //int one_second = std::chrono::duration_cast<std::chrono::microseconds>(seconds(1)).count();
  //int diff = elapsed_time - one_second;
  //std::cerr << diff << " microseconds\n";
   bool hasBeenOneSecond = ((now - req->timeSent ) > seconds(1));
  if(hasBeenOneSecond) {
    if(req->nTimesSent >= 5){
      std::cerr << "Request has been sent out at least 5 times\n";
	  std::cerr << "Remove request from cache\n";
	  Buffer orig_packet = req->packets.front().packet;
	  const ip_hdr *iphdr = (const ip_hdr *)(orig_packet.data() + sizeof(ethernet_hdr));
	  RoutingTableEntry r_entry = m_router.getRoutingTable().lookup(iphdr->ip_src);
	  std::cerr << r_entry.ifName << std::endl;
	  const Interface* iface = m_router.findIfaceByName(r_entry.ifName);
	  Buffer mac_addr = iface->addr;
	  std::cerr << macToString(mac_addr) << std::endl;
	  m_router.sendTimeExceeded(orig_packet, r_entry.ifName, 0x0003, 0x0001,
	    iface->ip, mac_addr);
      m_arpRequests.remove(req);
    }
    else {
      req->timeSent = now;
      req->nTimesSent++;
      std::cerr << "nTimes sent: " << req->nTimesSent << std::endl;
      m_router.sendARPRequest(req->ip);
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}




std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  // print_hdr_arp(packet.data() + 14);
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
