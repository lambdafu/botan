/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_HAS_BOOST_ASIO)

#include <iostream>
#include <string>
#include <vector>
#include <thread>

#define _GLIBCXX_HAVE_GTHR_DEFAULT
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <botan/tls_server.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
   #include <botan/tls_session_manager_sqlite.h>
#endif

#include "credentials.h"

namespace Botan_CLI {

namespace {

using boost::asio::ip::tcp;

inline void log_exception(const char* where, const std::exception& e)
   {
   std::cout << where << ' ' << e.what() << std::endl;
   }

inline void log_error(const char* where, const boost::system::error_code& error)
   {
   std::cout << where << ' ' << error.message() << std::endl;
   }

class HTTP_Parser
   {

   };

static const size_t READBUF_SIZE = 4096;

class TLS_Asio_HTTP_Session final : public boost::enable_shared_from_this<TLS_Asio_HTTP_Session>,
                                public Botan::TLS::Callbacks
   {
   public:
      typedef boost::shared_ptr<TLS_Asio_HTTP_Session> pointer;

      static pointer create(
         boost::asio::io_service& io,
         Botan::TLS::Session_Manager& session_manager,
         Botan::Credentials_Manager& credentials,
         Botan::TLS::Policy& policy)
         {
         return pointer(new TLS_Asio_HTTP_Session(io, session_manager, credentials, policy));
         }

      tcp::socket& client_socket()
         {
         return m_client_socket;
         }

      void start()
         {
         m_c2s.resize(READBUF_SIZE);
         client_read(boost::system::error_code(), 0); // start read loop
         }

      void stop()
         {
         m_tls.close();
         }

   private:
      TLS_Asio_HTTP_Session(boost::asio::io_service& io,
                            Botan::TLS::Session_Manager& session_manager,
                            Botan::Credentials_Manager& credentials,
                            Botan::TLS::Policy& policy)
         : m_strand(io)
         , m_client_socket(io)
         , m_tls(*this, session_manager, credentials, policy, m_rng) {}

      void client_read(const boost::system::error_code& error,
                       size_t bytes_transferred)
         {
         if(error)
            {
            log_error("Read failed", error);
            stop();
            return;
            }

         try
            {
            m_tls.received_data(&m_c2s[0], bytes_transferred);
            }
         catch(Botan::Exception& e)
            {
            log_exception("TLS connection failed", e);
            stop();
            return;
            }

         m_client_socket.async_read_some(
            boost::asio::buffer(&m_c2s[0], m_c2s.size()),
            m_strand.wrap(
               boost::bind(
                  &TLS_Asio_HTTP_Session::client_read, shared_from_this(),
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred)));
         }

      void handle_client_write_completion(const boost::system::error_code& error)
         {
         if(error)
            {
            log_error("Client write", error);
            stop();
            return;
            }

         m_s2c.clear();

         if(m_s2c_pending.empty() && m_tls.is_closed())
            {
            m_client_socket.close();
            }
         tls_emit_data(nullptr, 0); // initiate another write if needed
         }

      void tls_record_received(uint64_t /*rec_no*/, const uint8_t buf[], size_t buf_len) override
         {
         m_http_parser->consume_input(buf, buf_len);
         }

      void handle_http_request(const std::string& verb,
                               const std::string& location,
                               const std::map<std::string, std::string>& headers,
                               const std::string& body) override
         {
         std::ostringstream response;
         if(verb != "GET")
            {
            response << "HTTP/1.0 405 Method Not Allowed\r\n\r\n";
            }
         else
            {
            if(location == "/" || location == "/status")
               {
               response << "HTTP/1.0 200 OK\r\n\r\n"
                        << "Hi!\r\n";
               }
            else
               {
               response << "HTTP/1.0 404 Not Found\r\n\r\n";
               }
            }

         m_tls.send(response.str());
         }

      void tls_emit_data(const uint8_t buf[], size_t buf_len) override
         {
         if(buf_len > 0)
            {
            m_s2c_pending.insert(m_s2c_pending.end(), buf, buf + buf_len);
            }

         // no write now active and we still have output pending
         if(m_s2c.empty() && !m_s2c_pending.empty())
            {
            std::swap(m_s2c_pending, m_s2c);

            boost::asio::async_write(
               m_client_socket,
               boost::asio::buffer(&m_s2c[0], m_s2c.size()),
               m_strand.wrap(
                  boost::bind(
                     &TLS_Asio_HTTP_Session::handle_client_write_completion,
                     shared_from_this(),
                     boost::asio::placeholders::error)));
            }
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         m_hostname = session.server_info().hostname();
         return true;
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            m_tls.close();
            return;
            }
         else
            {
            std::cout << "Alert " << alert.type_string() << std::endl;
            }
         }

      boost::asio::io_service::strand m_strand;

      tcp::socket m_client_socket;

      Botan::AutoSeeded_RNG m_rng; // RNG per connection
      Botan::TLS::Server m_tls;
      std::string m_hostname;

      std::vector<uint8_t> m_c2s;
      std::vector<uint8_t> m_s2c;
      std::vector<uint8_t> m_s2c_pending;
   };

class TLS_Asio_HTTP_Server final
   {
   public:
      typedef TLS_Asio_HTTP_Session session;

      TLS_Asio_HTTP_Server(
         boost::asio::io_service& io, unsigned short port,
         tcp::resolver::iterator endpoints,
         Botan::Credentials_Manager& creds,
         Botan::TLS::Policy& policy,
         Botan::TLS::Session_Manager& session_mgr)
         : m_acceptor(io, tcp::endpoint(tcp::v4(), port))
         , m_server_endpoints(endpoints)
         , m_creds(creds)
         , m_policy(policy)
         , m_session_manager(session_mgr)
         {
         session::pointer new_session = make_session();

         m_acceptor.async_accept(
            new_session->client_socket(),
            boost::bind(
               &TLS_Asio_HTTP_Server::handle_accept,
               this,
               new_session,
               boost::asio::placeholders::error));
         }

   private:
      session::pointer make_session()
         {
         return session::create(
                   m_acceptor.get_io_service(),
                   m_session_manager,
                   m_creds,
                   m_policy,
                   m_server_endpoints);
         }

      void handle_accept(session::pointer new_session,
                         const boost::system::error_code& error)
         {
         if(!error)
            {
            new_session->start();
            new_session = make_session();

            m_acceptor.async_accept(
               new_session->client_socket(),
               boost::bind(
                  &TLS_Asio_HTTP_Server::handle_accept,
                  this,
                  new_session,
                  boost::asio::placeholders::error));
            }
         }

      tcp::acceptor m_acceptor;

      Botan::Credentials_Manager& m_creds;
      Botan::TLS::Policy& m_policy;
      Botan::TLS::Session_Manager& m_session_manager;
   };

}

class TLS_HTTP_Server final : public Command
   {
   public:
      TLS_HTTP_Server() : Command("tls_proxy server_cert server_key "
                                  "--port=443 --policy= --threads=0 "
                                  "--session-db= --session-db-pass=") {}

      void go() override
         {
         const size_t listen_port = get_arg_sz("listen_port");

         const std::string server_crt = get_arg("server_cert");
         const std::string server_key = get_arg("server_key");

         const size_t num_threads = get_arg_sz("threads") || std::thread::hardware_concurrency() || 2;

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         Botan::TLS::Policy policy; // TODO: Read policy from text file

         std::unique_ptr<Botan::TLS::Session_Manager> session_mgr;

         const std::string sessions_db = get_arg("session-db");

         if(!sessions_db.empty())
            {
#if defined(BOTAN_HAS_TLS_SQLITE3_SESSION_MANAGER)
            const std::string sessions_passphrase = get_arg("session-db-pass");
            session_mgr.reset(new Botan::TLS::Session_Manager_SQLite(sessions_passphrase, rng(), sessions_db));
#else
            throw CLI_Error_Unsupported("Sqlite3 support not available");
#endif
            }

         if(!session_mgr)
            {
            session_mgr.reset(new Botan::TLS::Session_Manager_In_Memory(rng()));
            }

         TLS_Asio_HTTP_Server server(io, listen_port, creds, policy, *session_mgr);

         std::vector<std::shared_ptr<std::thread>> threads;
         boost::asio::io_service io;

         // run forever... first thread is main calling io.run below
         for(size_t i = 2; i <= num_threads; ++i)
            {
            threads.push_back(std::make_shared<std::thread>([&io]() { io.run(); }));
            }

         io.run();

         for(size_t i = 0; i < threads.size(); ++i)
            {
            threads[i]->join();
            }
         }
   };

BOTAN_REGISTER_COMMAND("tls_http_server", TLS_HTTP_Server);

}

#endif
