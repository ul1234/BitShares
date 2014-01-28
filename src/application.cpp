#include <fc/io/raw_fwd.hpp>
#include <bts/bitchat/bitchat_messages.hpp>
#include <bts/application.hpp>
#include <bts/bitname/bitname_client.hpp>
#include <bts/bitchat/bitchat_client.hpp>
#include <bts/network/upnp.hpp>
#include <bts/network/ipecho.hpp>
#include <bts/rpc/rpc_server.hpp>
#include <bts/blockchain/blockchain_client.hpp>

#include <fc/reflect/variant.hpp>
#include <fc/thread/thread.hpp>
#include <fc/io/fstream.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fc/io/raw.hpp>

#include <mail/mail_connection.hpp>

#include <fstream>

namespace bts {

  profile_ptr get_profile() { return application::instance()->get_profile(); }

  namespace detail
  {
    class application_impl : public bts::bitname::client_delegate,
                             public bts::bitchat::client_delegate,
                             public mail::connection_delegate
    {
       public:
          application_impl()
          :_delegate(nullptr),
           _quit_promise( new fc::promise<void>() ),
           _mail_con(this),_mail_connected(false)
           {
           }
          std::vector<fc::ecc::private_key> _keys;

          virtual ~application_impl(){}

          application_delegate*             _delegate;
          fc::optional<application_config>  _config;
          profile_ptr                       _profile;
          fc::path                          _profile_dir;

          bts::network::server_ptr          _server;
          bts::peer::peer_channel_ptr       _peers;
          bts::bitname::client_ptr          _bitname_client;
          bts::bitchat::client_ptr          _bitchat_client;     
      //    bts::blockchain::client_ptr         _blockchain_client;     
          bts::network::upnp_service        _upnp;
          bts::rpc::server                  _rpc_server;

          fc::future<void>                  _connect_loop_complete;
          fc::future<void>                  _mail_connect_loop_complete;

          fc::promise<void>::ptr            _quit_promise;

          void set_mining_intensity(int intensity) { _bitname_client->set_mining_intensity(intensity); }
          int  get_mining_intensity()              { return _bitname_client->get_mining_intensity(); }

          mail::connection                  _mail_con;
          bool                              _mail_connected;

          void        configure( const application_config& cfg );
          /// Common implementation of profile loading.
          profile_ptr loadProfile(const fc::path& profileName, const std::string& password);

          void mail_connect_loop()
          {
             assert(!!_config );
             _mail_connected = false;
             while( !_quit_promise->ready() )
             {
                for( auto itr = _config->default_mail_nodes.begin(); itr != _config->default_mail_nodes.end(); ++itr )
                {
                     try {
                        ilog( "mail connect ${e}", ("e",*itr) );
                        _mail_con.connect(*itr);
                        _mail_con.set_last_sync_time( _profile->get_last_sync_time() );

                        bts::bitchat::client_info_message cli_info;
                        cli_info.version   = 0;
                        cli_info.sync_time = _profile->get_last_sync_time();
                        _mail_con.send( mail::message( cli_info ) );
                        _mail_connected = true;
                        return;
                     } 
                     catch ( const fc::exception& e )
                     {
                        wlog( "${e}", ("e",e.to_detail_string()));
                     }
                }
                fc::usleep( fc::seconds(3) );
             }
          }
          void connect_loop()
          {
             assert(!!_config );
             while( !_quit_promise->ready() )
             {
                for( auto itr = _config->default_nodes.begin();
                    _quit_promise->ready() == false && itr != _config->default_nodes.end(); ++itr )
                {
                     try {
                        ilog( "${e}", ("e",*itr) );
                        _server->connect_to(*itr);
                     } 
                     catch ( const fc::exception& e )
                     {
                        wlog( "${e}", ("e",e.to_detail_string()));
                     }
                }

                if(_quit_promise->ready())
                  break;

                fc::usleep( fc::seconds(3) );
             }
          }

          // mail::connection...
          virtual void on_connection_message( mail::connection& c, const mail::message& m )
          {
             if( m.type == bts::bitchat::encrypted_message::type )
             {
                auto pm = m.as<bts::bitchat::encrypted_message>();
                for( auto key = _keys.begin(); key != _keys.end(); ++key )
                {
                   bts::bitchat::decrypted_message dm;
                   if( pm.decrypt( *key, dm ) )
                   {
                      bitchat_message_received( dm );
                   }
                }
                _profile->set_last_sync_time( pm.timestamp );
             }
             if( m.type == bts::bitchat::server_info_message::type )
             {
                 server_time_offset = fc::time_point::now() - m.as<bts::bitchat::server_info_message>().server_time;
             }
          }
          fc::microseconds server_time_offset;

          virtual void on_connection_disconnected( mail::connection& c )
          {
              _mail_connected = false;
              start_mail_connect_loop();
          }
          void start_mail_connect_loop()
          {
          ilog("start_mail_connect_loop");
              _mail_connect_loop_complete = fc::async( [=](){
                  fc::usleep(fc::seconds(5));
                  mail_connect_loop(); 
                 } );
          }


          virtual void bitchat_message_received( const bitchat::decrypted_message& msg )
          {
              ilog( "received ${msg}", ("msg", msg) );
              if( _profile ) _profile->cache( msg );
              switch( msg.msg_type )
              {
                 case bitchat::private_message_type::text_msg:
                 {
                   auto txt = msg.as<bitchat::private_text_message>();
                   ilog( "text message ${msg}", ("msg",txt) );

                   if( _delegate ) _delegate->received_text( msg );
                   break;
                 }
                 case bitchat::private_message_type::email_msg:
                 {
                   auto email = msg.as<bitchat::private_email_message>();
                   ilog( "email message ${msg}", ("msg",email) );
                   if( _delegate ) _delegate->received_email( msg );//, *m.from_key, m.decrypt_key->get_public_key() );
                   break;
                 }
              }
          }

          virtual void bitname_block_added( const bts::bitname::name_block& h )
          {
        //      ilog( "${h}", ("h",h) );
          }
         
          virtual void bitname_header_pending( const bts::bitname::name_header& h )
          {
         //     ilog( "${h}", ("h",h) );
              /*
              if( h.name_hash == current_name )
              {
                 current_name = fc::time_point::now().time_since_epoch().count();
          
                auto next_name = std::string(fc::time_point::now()); 
                ilog( "registering next name ${name}", ("name",next_name));
                 _client->mine_name( next_name,
                                         fc::ecc::private_key::generate().get_public_key() );
              }
              */
          }  
    };

  void application_impl::configure(const application_config& cfg)
  {
  try 
  {
    ilog("application::configure");
    _config = cfg;

    _server = std::make_shared<bts::network::server>();

    try
    {
      ilog("calling get_external_ip");
      auto ext_ip = bts::network::get_external_ip();
      ilog( "external IP ${ip}", ("ip",ext_ip) );
      if( cfg.enable_upnp )
      {
        ilog("enable_upnp");
        _upnp.map_port( cfg.network_port );
        _server->set_external_ip( _upnp.external_ip() );
      }
      else
      {
        ilog("set_external_ip");
        _server->set_external_ip( ext_ip );
      }
    }
    catch (fc::exception e)
    {
      elog("Failed to connect to external IP address: ${e}", ("e",e.to_detail_string()));
    }
    catch (...)
    {
      elog("unrecognized exception while setting external ip, but we're ignoring it");
    }

    ilog("configuring server");
    bts::network::server::config server_cfg;
    server_cfg.port = cfg.network_port;

    _server->configure( server_cfg );

    ilog("configure bitname client");
    _peers            = std::make_shared<bts::peer::peer_channel>(_server);
    _bitname_client   = std::make_shared<bts::bitname::client>(_peers);
    _bitname_client->set_delegate(this);

    bitname::client::config bitname_config;
    bitname_config.data_dir = cfg.data_dir / "bitname";

    _bitname_client->configure( bitname_config );

    ilog("configure bitchat client");
    _bitchat_client  = std::make_shared<bts::bitchat::client>(_peers, this);
    _bitchat_client->configure( cfg.data_dir / "bitchat" );

    ilog("configuring rpc_server");
    _rpc_server.configure( cfg.rpc_config );
    _rpc_server.set_bitname_client(_bitname_client);
    ilog("done configuring rpc_server");

    ilog("end application::configure");
    }
    FC_RETHROW_EXCEPTIONS( warn, "", ("config",cfg) ) 
  }

  profile_ptr application_impl::loadProfile(const fc::path& profileName, const std::string& password)
    {
    try {
    if(_profile)
      _profile.reset();

    fc::path loadedProfileDir = _profile_dir/profileName;

    // note: stored in temp incase open throws.
    auto tmp_profile = std::make_shared<profile>();
    tmp_profile->open(loadedProfileDir, password);

    fc::path configFilePath = loadedProfileDir/"config.json";

    FC_ASSERT( fc::exists(configFilePath) );
    auto app_config = fc::json::from_file(configFilePath).as<bts::application_config>();
    configure(app_config);

    std::vector<fc::ecc::private_key> recv_keys;
    auto keychain =  tmp_profile->get_keychain();

    std::vector<bts::addressbook::wallet_identity> idents = tmp_profile->identities();
    for(const auto& id : idents)
    {
      recv_keys.push_back(keychain.get_identity_key(id.dac_id_string));
    }
    
    _keys = recv_keys;
    _bitchat_client->set_receive_keys( recv_keys );

    return _profile = tmp_profile;
  }
  FC_RETHROW_EXCEPTIONS( warn, "" ) 
  }

  } /// namespace bts::detail

  application::application()
  :my( new detail::application_impl() )
  {
  }

  application::~application() {}

  void application::set_profile_directory( const fc::path& profile_dir )
  {
     my->_profile_dir = profile_dir;
     fc::create_directories( my->_profile_dir );
  }

  void application::configure( const application_config& cfg )
  {
  my->configure(cfg);
  }

  void application::connect_to_network()
  {
    // START CONNECT LOOP
    my->start_mail_connect_loop();
    my->_connect_loop_complete = fc::async( [=]{ my->connect_loop(); } );
  }

  bool application::is_mail_connected()const
  {
     return my->_mail_connected;
  }

  bts::network::server_ptr application::get_network()const
  {
      return my->_server;
  }

  application_config application::get_configuration()const
  {
     FC_ASSERT( my->_config );
     return *my->_config;
  }

  void      application::set_application_delegate( application_delegate* del )
  {
     my->_delegate = del;
  }

  bool          application::has_profile()const
  {
     return get_profiles().size() != 0;
  }

  profile_ptr   application::get_profile()
  {
    return my->_profile;
  }

  std::vector<std::wstring>  application::get_profiles()const
  { try {
    std::vector<std::wstring> profileDirs;
     std::vector<std::string> logCapableProfileDirs;
     fc::directory_iterator   profile_dir(my->_profile_dir);
     while( profile_dir != fc::directory_iterator() )
     {
        auto p = *profile_dir;
        if( fc::is_directory(p) && fc::exists( p / "config.json" ) )
        {
           ilog( "${p}", ("p",p) );
           fc::path fName = p.filename();
           profileDirs.push_back(fName.generic_wstring() );
           logCapableProfileDirs.push_back(fName.generic_string());
        }
        ++profile_dir;
     }
     ilog( "profiles ${p}", ("p", logCapableProfileDirs) );
     return profileDirs;
  } FC_RETHROW_EXCEPTIONS( warn, "error getting profiles" ) }

  profile_ptr application::load_profile(const std::wstring& profileName, const std::string& password)
  {
    return my->loadProfile(fc::path(profileName), password);
  }

  profile_ptr application::load_profile(const std::string& profileName, const std::string& password)
  {
    return my->loadProfile(fc::path(profileName), password);
  }

  void  application::add_receive_key( const fc::ecc::private_key& k )
  {
     my->_keys.push_back(k);
     my->_bitchat_client->add_receive_key( k );
  }

  profile_ptr   application::create_profile( const std::wstring& profileName,
                                             const profile_config& cfg, const std::string& password, 
                                             std::function<void(double)> progress )
  { try {
     fc::path fcProfPath(profileName);
     auto pro_dir = my->_profile_dir / fcProfPath;
     fc::create_directories( pro_dir );
     auto config_file = pro_dir / "config.json";
     
     ilog("config_file: ${file}", ("file", config_file) );
     if (fc::exists(config_file) == false)
     {
       bts::application_config default_cfg;
       default_cfg.data_dir = pro_dir / "data";
       fc::create_directories(default_cfg.data_dir);
       default_cfg.network_port = 0;
       default_cfg.rpc_config.port = 0;
       //DLNFIX Quiet error messages as there's no server listening to this port currently.
       //       Let's setup a peer server soon somewhere that does handle connection attempts.
       // default_cfg.default_nodes.push_back( fc::ip::endpoint( std::string("162.243.67.4"), 9876 ) );
       default_cfg.default_mail_nodes.push_back( fc::ip::endpoint( std::string("162.243.67.4"), 7896 ) );
       
       /** \warning Don't use fc::ostream - this class doesn't provide info about write/opening
           operation status.
       */
       //std::ofstream out(config_file.generic_wstring());
       fc::ofstream out(config_file);
       //if(out)
        out << fc::json::to_pretty_string(default_cfg);
       //else
       //  FC_THROW("Cannot write config file: ${path}", ("path", config_file));
     }

     auto app_config = fc::json::from_file(config_file).as<bts::application_config>();
     fc::ofstream out(config_file);
     out << fc::json::to_pretty_string(app_config);
     
     
     // note: stored in temp incase create throws.
     auto tmp_profile = std::make_shared<profile>();
     
     tmp_profile->create( pro_dir, cfg, password, progress );
     tmp_profile->open( pro_dir, password );
     
     configure(app_config);
     return my->_profile = tmp_profile;

  } FC_RETHROW_EXCEPTIONS( warn, "" ) }

                              
  fc::optional<bitname::name_record>   application::lookup_name( const std::string& name )
  { try {
    FC_ASSERT( my->_config );
    return my->_bitname_client->lookup_name( name );
  } FC_RETHROW_EXCEPTIONS( warn, "", ("name",name) ) }

  fc::optional<bitname::name_record>   application::reverse_name_lookup( const fc::ecc::public_key& key )
  { try {
    FC_ASSERT( my->_config );
    return my->_bitname_client->reverse_name_lookup( key );
  } FC_RETHROW_EXCEPTIONS( warn, "", ("key",key) ) }

  void                        application::mine_name( const std::string& name, const fc::ecc::public_key& key, float effort )
  { try {
     FC_ASSERT( my->_config );
     my->_bitname_client->mine_name( name, key );
  } FC_RETHROW_EXCEPTIONS( warn, "name: ${name}", ("name",name) ) }

  void  application::send_contact_request( const fc::ecc::public_key& to, const fc::ecc::private_key& from )
  {
     FC_ASSERT( my->_config );
  }

  void  application::send_email( const bitchat::private_email_message& email, 
                                 const fc::ecc::public_key& to, const fc::ecc::private_key& from )
  { try {
     FC_ASSERT( my->_config );
     //DLNFIX Later change to using derived class which has bcc_list as requested by bytemaster,
     //       but this is safer for now.
     bitchat::private_email_message email_no_bcc_list(email);
     email_no_bcc_list.bcc_list.clear();
     bitchat::decrypted_message msg( email_no_bcc_list );
     msg.sign(from);
     auto cipher_message = msg.encrypt( to );
     cipher_message.timestamp = fc::time_point::now() + my->server_time_offset;
     my->_mail_con.send( mail::message( cipher_message) );
     //my->_bitchat_client->send_message( msg, to, 0/* chan 0 */ );

  } FC_RETHROW_EXCEPTIONS( warn, "" ) }


  void  application::send_text_message( const bitchat::private_text_message& txtmsg, 
                                        const fc::ecc::public_key& to, const fc::ecc::private_key& from )
  { try {
     FC_ASSERT( my->_config );

     bitchat::decrypted_message msg( txtmsg );
     msg.sign(from);
     my->_bitchat_client->send_message( msg, to, 0/* chan 0 */ );

  } FC_RETHROW_EXCEPTIONS( warn, "" ) }

  void  application::add_node( const fc::ip::endpoint& remote_ep )
  { try {
     FC_ASSERT( my->_config );
     my->_server->connect_to(remote_ep);
  } FC_RETHROW_EXCEPTIONS( warn, "", ("endpoint",remote_ep) ) }


  void application::set_mining_intensity(int intensity) { my->set_mining_intensity(intensity); }
  int application::get_mining_intensity() { return my->get_mining_intensity(); }

  void application::quit()
  { try {
       /// Notify quit to break direct connection and mail connection loops
       my->_quit_promise->set_value();
       
       /// Wait until direct connection loop finishes.
       if(my->_connect_loop_complete.valid())
         my->_connect_loop_complete.wait();
       
       /// Wait until mail connection loop finishes.
       if(my->_mail_connect_loop_complete.valid())
         my->_mail_connect_loop_complete.wait();

       if(my->_server)
         my->_server->close();

       my.reset();
  } FC_RETHROW_EXCEPTIONS( warn, "" ) }
 
  application_ptr application::instance()
  {
      static application_ptr app = std::make_shared<application>();
      return app;
  }

  void application::wait_until_quit()
  { try {
      auto wait_ptr_copy = my->_quit_promise; 
      wait_ptr_copy->wait();
  } FC_RETHROW_EXCEPTIONS( warn, "" ) }
} // namespace bts
