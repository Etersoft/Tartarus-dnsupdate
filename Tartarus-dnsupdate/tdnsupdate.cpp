#include <Ice/Ice.h>
#include <stdexcept>
#include <krb5user.h>

#include "DNS/DNS.h"

static const Ice::CommunicatorPtr& getIceCommunicator()
{
	static Ice::CommunicatorPtr ic = 0;

	if (!ic)
	{
		Ice::InitializationData init;
		init.properties = Ice::createProperties();
		init.properties->load("/etc/Tartarus/clients/all.config");
		init.properties->load("/etc/Tartarus/clients/tdnsupdate.config");
		ic = Ice::initialize(init);
	}

	return ic;
}

namespace DNS = Tartarus::iface::DNS;

static const DNS::ServerPrx& getServerPrx()
{
	static DNS::ServerPrx prx;

	const Ice::CommunicatorPtr& communicator = getIceCommunicator();

	if (!prx) {
		Ice::ObjectPrx base = communicator->propertyToProxy("Tartarus.DNS.ServerPrx");
		if (!base)
			throw std::runtime_error("Could not create DNS-Server/Server proxy");
		prx = DNS::ServerPrx::checkedCast(base);
		if (!prx)
			throw std::runtime_error("Invalid DNS-Server/Server proxy");
	}
	
	return prx;
}

static void kinit(const char *princname, const char* ccname)
{
	krb5user_error_code e = 0;
	const char* what = 0;

	try {
		e = krb5user_kinit_keytab(princname, 0, 0, ccname, &what);
		if (e)
			throw e;

		e = krb5user_set_ccname(ccname, &what);
		if (e)
			throw e;

	} catch (krb5user_error_code e) {
		std::string err(krb5user_error_message(e));
		err += std::string(": ") + what;
		throw (std::runtime_error(err));
	}
}

//#include <cstdlib>
//#include <iostream>

int main()
{
	try {
		kinit("host", "MEMORY:0");
//		std::cerr << "KRB5CCNAME: " << std::getenv("KRB5CCNAME") << std::endl;
		getServerPrx()->updateThisHost();
	} catch (const Ice::Exception& e) {
		std::cerr << "Ice error: " << e << std::endl;
		return 1;
	} catch (const std::exception& e) {
		std::cerr << "STL error: " << e.what() << std::endl;
		return 2;
	} catch (...) {
		std::cerr << "Unknown error" << std::endl;
		return 3;
	}
	return 0;
}
