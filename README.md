# CS118 Project 3

Brandon Liu, 004439799
Steven Xu, 604450388

For this project, we mainly did pair programming as there wasn't that
much code to write in this project per se. The hardest thing about
this project was understanding how a router works, understanding all
the code and functions that were already written, and figuring out how
to test any new code that we added to the sample code.

Thus, we both worked together on implementing the handlePacket function in
simple-router.cpp and implementing the periodicCheckArpRequestsAndCacheEntries
function and handle_arpreq function in arp-cache.cpp. Steven worked on
implementing the lookup function for routing-table.cpp

## High-level design of handlePacket

For the functions in routing-table.cpp and arp-cache.cpp, we just followed
the instructions on the spec and the pseudocode in the comments to implement
them.

The handlePacket function was a bulk of our work. In the simple-router.cpp
itself, we wrote numerous helper functions that would construct and send
the different types of ICMP, ARP, and forwarded IP packets as we needed.
Examples of this include:

    sendICMP, sendTimeExceeded, sendARPRequest, forwardPacket,
    sendPacketToDestination
	
We also wrote helper functions to divide the control flow of handlePacket. For
example, we wrote handleArpRequest and handleArpReply to handle ARP requests
and ARP replies, respectively. We wrote handleIP to handle IP packets. Within
these functions and the handlePacket function, we added conditional statements
to check if the packets were valid for their specified types (i.e. ARP, IP, or
ICMP) and situations that they were in (i.e. packet destined to router is
only replied to if it contains an ICMP payload).

## Additional libraries

We didn't really use any additional libraries as most of there were already
provided in the sample code.

## Problems We ran into

The biggest problem we had was starting the project. At first, we were not
exactly sure how the ARP protocol worked and for the longest time, we didn't
realize that the client didn't have the MAC address of the router at the
beginning. Once we realized that important fact, our progress on the project
was much better.

Also, it was a little hard at first to read the spec and understand how all
the already-written functions worked and which ones were helpful for us (i.e.
didn't know at first that the length parameter in the cksum was in bytes).

It was also a little difficult to read and understand all the code and we were
unfamiliar with some syntax that we barely touched upon or never used before
(i.e. the c++ vector and list data structures, auto keyword in the for loop,
etc.).

## References

For the libraries already given, we referenced documentation on cplusplus.com,
man7.org, and linux.die.net.

We also referenced the textbook and wikipedia to gain a better understanding of
the ARP protocol, how ethernet works, how router works, how the IP headers
worked, and how ICMP messages work.

We also referenced piazza for any spec clarifications and other questions we had.

## Extra Credit

We completed the first extra credit (i.e. sending an ICMP destination
unreachable when no ARP reply after 5 requests).

We also think that we completed the other extra credit because
it seems like a requirement for the other traceroutes to work.