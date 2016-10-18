#include "stdafx.h"
#include "protocols.h"

protocols::protocols()
{
	index = -1;
	name = "NULL";
}

protocols::protocols(int aindex, char* aname)
{
	this->index = aindex;
	this->name = aname;
}


protocols::~protocols()
{
}

char* protocols::getname(int ptc_index)
{
	int i = 20;
	for (; i >= -1; i--)
	{
		if (ptc_index==protocol[i].index)
		{
			break;
		}

	}
	return protocol[i].name;
}

protocols protocols::protocol[20] = {
protocols(0,"IP"),
protocols(1, "ICMP"),
protocols(3, "GGP"),
protocols(6, "TCP"),
protocols(8, "EGP"),
protocols(12, "PUP"),
protocols(17, "UDP"),
protocols(20, "HMP"),
protocols(22, "XNS - IDP"),
protocols(27, "RDP"),
protocols(41, "IPv6"),
protocols(43, "IPv6 - Route"),
protocols(44, "IPv6 - Frag"),
protocols(50, "ESP"),
protocols(51, "AH"),
protocols(58, "IPv6 - ICMP"),
protocols(59, "IPv6 - NoNxt"),
protocols(60, "IPv6 - Opts"),
protocols(66, "RVD")
};