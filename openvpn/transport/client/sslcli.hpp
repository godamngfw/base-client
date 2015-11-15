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

// SSL transport object specialized for client.

#ifndef OPENVPN_TRANSPORT_CLIENT_SSLCLI_H
#define OPENVPN_TRANSPORT_CLIENT_SSLCLI_H

#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/ssl/protostack.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/client/remotelist.hpp>

namespace openvpn {
namespace SSLTransport {

template <typename SSL_API>
class ClientConfig : public TransportClientFactory
{
public:
	typedef boost::intrusive_ptr<ClientConfig> Ptr;

	typename SSL_API::Ptr ssl_ctx;
	TimePtr now;

	RemoteList::Ptr remote_list;
	size_t send_queue_max_size;
	size_t free_list_max_size;
	Frame::Ptr frame;
	SessionStats::Ptr stats;

	SocketProtect* socket_protect;

	static Ptr new_obj()
	{
		return new ClientConfig;
	}

	virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
	        TransportClientParent& parent);

private:
	ClientConfig()
		: send_queue_max_size(1024),
		  free_list_max_size(8),
		  socket_protect(NULL)
	{}
};

// Packet structure for managing network packets, passed as a template
// parameter to ProtoStackBase
class Packet
{
public:
	Packet() {}
	explicit Packet(const BufferPtr& buf_arg)
		: buf(buf_arg) {

	}
	operator bool() const {return bool(buf);}
	bool is_raw() const {return false;}
	void reset() {
		buf.reset();
	}
	id_t id() const {return id_;}
	void set_id(id_t id) {id_ = id;}
	const BufferPtr& buffer_ptr() {return buf;}
	const Buffer& buffer() const { return *buf; }
	void frame_prepare(const Frame& frame, const unsigned int context) {
		if (!buf)
			buf.reset(new BufferAllocated());
		frame.prepare(context, *buf);
	}
private:
	id_t id_;
	BufferPtr buf;
};

template <typename SSL_API>
class Client : ProtoStackBase<SSL_API, Packet>, public TransportClient
{
	friend class ClientConfig<SSL_API>;         // calls constructor
	friend class TCPTransport::Link<Client*, true>; // calls tcp_read_handler

	typedef TCPTransport::Link<Client*, true> LinkImpl;

	typedef AsioDispatchResolve<Client,
	        void (Client::*)(const boost::system::error_code&,
	                         boost::asio::ip::tcp::resolver::iterator),
	        boost::asio::ip::tcp::resolver::iterator> AsioDispatchResolveTCP;

	typedef ProtoStackBase<SSL_API, Packet> Base;

	// ProtoStackBase member functions
	using Base::rel_recv; 
	
	using Base::start_handshake;
	using Base::app_send;
	using Base::net_recv;
	using Base::flush;

public:
	virtual void start()
	{
		if (!impl)
		{
			halt = false;
			if (config->remote_list->endpoint_available(&server_host, &server_port, NULL))
			{
				start_connect_();
			}
			else
			{
				boost::asio::ip::tcp::resolver::query query(server_host,
				        server_port);
				parent.transport_pre_resolve();
				resolver.async_resolve(query, AsioDispatchResolveTCP(&Client::do_resolve_, this));
			}
		}
	}

	//由于SSL使用了RAW TCP，不会在包前加上包的长度，所以需要我们自己来加
	//同样，接收的时候也需要自己来处理包长度，可参考tcplink中的!raw_mode代码
	bool pre_app_send(BufferPtr& buf) {
		PacketStream::prepend_size(*buf);
		Base::app_send(buf);
		Base::flush();
		return true;
	}

	virtual bool transport_send_const(const Buffer& cbuf)
	{
		BufferPtr buf(new BufferAllocated(cbuf, 0));
		return pre_app_send(buf);
		
	}

	virtual bool transport_send(BufferAllocated& cbuf)
	{
		BufferPtr buf = new BufferAllocated();
		buf->move(cbuf);
		return pre_app_send(buf);
		
	}

	virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const
	{
		host = server_host;
		port = server_port;
		const IP::Addr addr = server_endpoint_addr();
		proto = "TCP";
		proto += addr.version_string();
		ip_addr = addr.to_string();
	}

	virtual IP::Addr server_endpoint_addr() const
	{
		return IP::Addr::from_asio(server_endpoint.address());
	}

	virtual void stop() { stop_(); }
	virtual ~Client() { stop_(); }

private:
	Client(boost::asio::io_service& io_service_arg,
	       ClientConfig<SSL_API>* config_arg,
	       TransportClientParent& parent_arg)
		:  Base(*config_arg->ssl_ctx, config_arg->now, config_arg->frame, 
				Frame::READ_TRANSPORT_SSL_CLEARTEXT, config_arg->stats, 4, 4),
		   frame_context((*config_arg->frame)[Frame::READ_TRANSPORT_SSL_CIPHERTEXT]),
		   io_service(io_service_arg),
		   socket(io_service_arg),
		   config(config_arg),
		   parent(parent_arg),
		   resolver(io_service_arg),
		   halt(false)
	{
		frame_context.prepare(frame_buffer);
	}

	// VIRTUAL METHODS -- derived class must define these virtual methods

	// Encapsulate packet, use id as sequence number.  If xmit_acks is non-empty,
	// try to piggy-back ACK replies from xmit_acks to sender in encapsulated
	// packet. Any exceptions thrown will invalidate session, i.e. this object
	// can no longer be used.
	virtual void encapsulate(id_t id, Packet& pkt) {
		pkt.set_id(id);
	}

	// Perform integrity check on packet.  If packet is good, unencapsulate it and
	// pass it into the rel_recv object.  Any ACKs received for messages previously
	// sent should be marked in rel_send.  Message sequence number should be recorded
	// in xmit_acks.  Exceptions may be thrown here and they will be passed up to
	// caller of net_recv and will not invalidate the session.
	// Method should return true if packet was placed into rel_recv.
	virtual bool decapsulate(Packet& pkt) {
		//Buffer& recv = *pkt.buffer_ptr();
		//const id_t id = ReliableAck::read_id(recv);
		static id_t id = 0;
		Base::rel_recv.receive(pkt, id++);
		return true;
	}

	// Generate a standalone ACK message in buf based on ACKs in xmit_acks
	// (PACKET will be already be initialized by frame_prepare()).
	virtual void generate_ack(Packet& pkt) {

	}

	// Transmit encapsulated ciphertext packet to peer.  Method may not modify
	// or take ownership of net_pkt or underlying data unless it copies it.
	virtual void net_send(const Packet& net_pkt, const typename Base::NetSendType nstype) {
		if (impl)
		{
			BufferAllocated buf(net_pkt.buffer(), 0);
			impl->send(buf);
			Base::rel_send.ack(net_pkt.id());
		}
	}

	// Pass cleartext data up to application.  Method may take ownership
	// of to_app_buf by making private copy of BufferPtr then calling
	// reset on to_app_buf.
	virtual void app_recv(BufferPtr& to_app_buf) {
		BufferAllocated buf(*to_app_buf, 0);
		//to_app_buf.reset();
		BufferAllocated pkt;
		put_pktstream(buf, pkt);
		if (!buf.allocated() && pkt.allocated()) // recycle pkt allocated buffer
			buf.move(pkt);
		frame_context.prepare(frame_buffer);
	}

	void put_pktstream(BufferAllocated& buf, BufferAllocated& pkt)
	{
		while (buf.size())
		{
			pktstream.put(buf, frame_context);
			if (pktstream.ready())
			{
				pktstream.get(pkt);
				parent.transport_recv(pkt);
			}
		}
	}
	// Pass raw data up to application.  A packet is considered to be raw
	// if is_raw() method returns true.  Method may take ownership
	// of raw_pkt underlying data as long as it resets raw_pkt so that
	// a subsequent call to PACKET::frame_prepare will revert it to
	// a ready-to-use state.
	virtual void raw_recv(Packet& raw_pkt) {
		OPENVPN_LOG("SSL Transport raw_pkt");
	}

	// called if session is invalidated by an error (optional)
	virtual void invalidate_callback() {}

	// END of VIRTUAL METHODS
/*
	bool send_const(const Buffer& cbuf)
	{
		if (impl)
		{
			BufferAllocated buf(cbuf, 0);
			return impl->send(buf);
		}
		else
			return false;
	}

	bool send(BufferAllocated& buf)
	{
		if (impl)
			return impl->send(buf);
		else
			return false;
	}
	*/

	void tcp_eof_handler() // called by LinkImpl
	{
		config->stats->error(Error::NETWORK_EOF_ERROR);
		tcp_error_handler("NETWORK_EOF_ERROR");
	}

	void tcp_read_handler(BufferAllocated& buf) // called by LinkImpl
	{
		BufferPtr bp = new BufferAllocated();
		bp->move(buf);
		Packet pkt(bp);
		Base::net_recv(pkt);
		Base::flush();
	}

	void tcp_error_handler(const char *error) // called by LinkImpl
	{
		std::ostringstream os;
		os << "Transport error on '" << server_host << ": " << error;
		stop();
		parent.transport_error(Error::UNDEF, os.str());
	}

	void stop_()
	{
		if (!halt)
		{
			halt = true;
			if (impl)
				impl->stop();

			socket.close();
			resolver.cancel();
		}
	}

	// do DNS resolve
	void do_resolve_(const boost::system::error_code& error,
	                 boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
		if (!halt)
		{
			if (!error)
			{
				// save resolved endpoint list in remote_list
				config->remote_list->set_endpoint_list(endpoint_iterator);
				start_connect_();
			}
			else
			{
				std::ostringstream os;
				os << "DNS resolve error on '" << server_host << "' for TCP session: " << error.message();
				config->stats->error(Error::RESOLVE_ERROR);
				stop();
				parent.transport_error(Error::UNDEF, os.str());
			}
		}
	}

	// do TCP connect
	void start_connect_()
	{
		config->remote_list->get_endpoint(server_endpoint);
		OPENVPN_LOG("Contacting " << server_endpoint << " via TCP-via-SSL");
		parent.transport_wait();
		parent.ip_hole_punch(server_endpoint_addr());
		socket.open(server_endpoint.protocol());
#ifdef OPENVPN_PLATFORM_TYPE_UNIX
		if (config->socket_protect)
		{
			if (!config->socket_protect->socket_protect(socket.native_handle()))
			{
				config->stats->error(Error::SOCKET_PROTECT_ERROR);
				stop();
				parent.transport_error(Error::UNDEF, "socket_protect error (TCP)");
				return;
			}
		}
#endif
		socket.set_option(boost::asio::ip::tcp::no_delay(true));
		socket.async_connect(server_endpoint, asio_dispatch_connect(&Client::start_impl_, this));
	}

	// start I/O on TCP socket
	void start_impl_(const boost::system::error_code& error)
	{
		if (!halt)
		{
			if (!error)
			{
				impl.reset(new LinkImpl(this,
				                        socket,
				                        config->send_queue_max_size,
				                        config->free_list_max_size,
				                        (*config->frame)[Frame::READ_LINK_TCP],
				                        config->stats));
				impl->start();

				Base::start_handshake();
				Base::flush();
				parent.transport_connecting();
				
			}
			else
			{
				std::ostringstream os;
				os << "TCP connect error on '" << server_host << ':' << server_port << "' (" << server_endpoint << "): " << error.message();
				config->stats->error(Error::TCP_CONNECT_ERROR);
				stop();
				parent.transport_error(Error::UNDEF, os.str());
			}
		}
	}

	std::string server_host;
	std::string server_port;

	//use to refragment the packet after decrypto
	BufferAllocated frame_buffer;
	const Frame::Context frame_context;
	PacketStream pktstream;
	//use to refragment the packet after decrypto
	
	boost::asio::io_service& io_service;
	boost::asio::ip::tcp::socket socket;
	typename ClientConfig<SSL_API>::Ptr config;
	TransportClientParent& parent;
	typename LinkImpl::Ptr impl;
	boost::asio::ip::tcp::resolver resolver;
	TCPTransport::Endpoint server_endpoint;
	bool halt;
};

template <typename SSL_API>
inline TransportClient::Ptr ClientConfig<SSL_API>::new_client_obj(boost::asio::io_service& io_service,
        TransportClientParent& parent)
{
	return TransportClient::Ptr(new Client<SSL_API>(io_service, this, parent));
}
}
} // namespace openvpn

#endif
