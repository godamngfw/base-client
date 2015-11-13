//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Generic, cross-platform tun interface that drives a TunBuilderBase API.
// Fully supports IPv6.  To make this work on a given platform, define
// a TunBuilderBase for the platform.

#ifndef OPENVPN_TUN_BUILDER_CLIENT_H
#define OPENVPN_TUN_BUILDER_CLIENT_H

#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunpersist.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/tun/tunio.hpp>

namespace openvpn {
namespace TunBuilderClient {

OPENVPN_EXCEPTION(tun_builder_error);

// struct used to pass received tun packets
struct PacketFrom
{
	typedef ScopedPtr<PacketFrom> SPtr;
	BufferAllocated buf;
};

// our TunPersist class, specialized for Unix file descriptors
typedef TunPersistTemplate<ScopedFD> TunPersist;

// A simplified tun interface where pre-existing
// socket is provided.
template <typename ReadHandler>
class Tun : public TunIO<ReadHandler, PacketFrom, boost::asio::posix::stream_descriptor>
{
	typedef TunIO<ReadHandler, PacketFrom, boost::asio::posix::stream_descriptor> Base;

public:
	typedef boost::intrusive_ptr<Tun> Ptr;

	Tun(boost::asio::io_service& io_service,
	    const int socket,
	    const bool retain_sd_arg,
	    const bool tun_prefix_arg,
	    ReadHandler read_handler_arg,
	    const Frame::Ptr& frame_arg,
	    const SessionStats::Ptr& stats_arg)
		: Base(read_handler_arg, frame_arg, stats_arg)
	{
		Base::stream = new boost::asio::posix::stream_descriptor(io_service, socket);
		Base::name_ = "tun";
		Base::retain_stream = retain_sd_arg;
		Base::tun_prefix = tun_prefix_arg;
	}

	~Tun() { Base::stop(); }
};

// A factory for the Client class
class ClientConfig : public TunClientFactory
{
public:
	typedef boost::intrusive_ptr<ClientConfig> Ptr;

	TunProp::Config tun_prop;
	int n_parallel;            // number of parallel async reads on tun socket
	bool retain_sd;
	bool tun_prefix;
	Frame::Ptr frame;
	SessionStats::Ptr stats;

	TunPersist::Ptr tun_persist;

	TunBuilderBase* builder;

	static Ptr new_obj()
	{
		return new ClientConfig;
	}

	virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
	                                      TunClientParent& parent);

	virtual void finalize(const bool disconnected)
	{
		if (disconnected)
			tun_persist.reset();
	}

private:
	ClientConfig()
		: n_parallel(8), retain_sd(false), tun_prefix(false), builder(NULL) {}
};

// The tun interface
class Client : public TunClient
{
	friend class ClientConfig;  // calls constructor
	friend class TunIO<Client*, PacketFrom, boost::asio::posix::stream_descriptor>;  // calls tun_read_handler

	typedef Tun<Client*> TunImpl;

public:
	virtual void client_start(const OptionList& opt, TransportClient& transcli)
	{
		if (!impl)
		{
			halt = false;
			if (config->tun_persist)
				tun_persist = config->tun_persist; // long-term persistent
			else
				tun_persist.reset(new TunPersist(false, config->retain_sd, config->builder)); // short-term

			try {
				int sd = -1;
				const IP::Addr server_addr = transcli.server_endpoint_addr();

				// Check if persisted tun session matches properties of to-be-created session
				if (tun_persist->use_persisted_tun(server_addr, config->tun_prop, opt))
				{
					sd = tun_persist->obj();
					state = tun_persist->state();
					OPENVPN_LOG("TunPersist: reused tun context");
				}
				else
				{
					TunBuilderBase* tb = config->builder;

					// reset target tun builder object
					if (!tb->tun_builder_new())
						throw tun_builder_error("tun_builder_new failed");

					// notify parent
					parent.tun_pre_tun_config();

					// configure the tun builder
					TunProp::configure_builder(tb, state.get(), config->stats.get(), server_addr,
					                           config->tun_prop, opt, false);

					// start tun
					sd = tb->tun_builder_establish();
				}

				if (sd == -1)
				{
					parent.tun_error(Error::TUN_IFACE_CREATE, "cannot acquire tun interface socket");
					return;
				}

				// persist state
				if (tun_persist->persist_tun_state(sd, state))
					OPENVPN_LOG("TunPersist: saving tun context:" << std::endl << tun_persist->options());

				impl.reset(new TunImpl(io_service,
				                       sd,
				                       true,
				                       config->tun_prefix,
				                       this,
				                       config->frame,
				                       config->stats
				                      ));
				impl->start(config->n_parallel);

				// signal that we are connected
				parent.tun_connected();
			}
			catch (const std::exception& e)
			{
				if (tun_persist)
					tun_persist->close();
				stop();
				parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
			}
		}
	}

	virtual bool tun_send(BufferAllocated& buf)
	{
		return send(buf);
	}

	virtual std::string tun_name() const
	{
		if (impl)
			return impl->name();
		else
			return "UNDEF_TUN";
	}

	virtual std::string vpn_ip4() const
	{
		if (state->vpn_ip4_addr.specified())
			return state->vpn_ip4_addr.to_string();
		else
			return "";
	}

	virtual std::string vpn_ip6() const
	{
		if (state->vpn_ip6_addr.specified())
			return state->vpn_ip6_addr.to_string();
		else
			return "";
	}

	virtual void stop() { stop_(); }
	virtual ~Client() { stop_(); }

private:
	Client(boost::asio::io_service& io_service_arg,
	       ClientConfig* config_arg,
	       TunClientParent& parent_arg)
		:  io_service(io_service_arg),
		   config(config_arg),
		   parent(parent_arg),
		   halt(false),
		   state(new TunProp::State())
	{
	}

	bool send(Buffer& buf)
	{
		if (impl)
			return impl->write(buf);
		else
			return false;
	}

	void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
	{
		parent.tun_recv(pfp->buf);
	}

	void tun_error_handler(const Error::Type errtype, // called by TunImpl
	                       const boost::system::error_code* error)
	{
	}

	void stop_()
	{
		if (!halt)
		{
			halt = true;

			// stop tun
			if (impl)
				impl->stop();
			tun_persist.reset();
		}
	}


	boost::asio::io_service& io_service;
	TunPersist::Ptr tun_persist; // owns the tun socket descriptor
	ClientConfig::Ptr config;
	TunClientParent& parent;
	TunImpl::Ptr impl;
	bool halt;
	TunProp::State::Ptr state;
};

inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
        TunClientParent& parent)
{
	return TunClient::Ptr(new Client(io_service, this, parent));
}

}
}

#endif
