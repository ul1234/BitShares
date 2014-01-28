#pragma once
#include <bts/config.hpp>
#include <bts/profile.hpp>
#include <bts/bitchat/bitchat_private_message.hpp>
#include <bts/bitname/bitname_client.hpp>
#include <bts/rpc/rpc_server.hpp>

namespace bts {

  namespace detail { class application_impl; }

  struct application_config
  {
      application_config()
      :network_port(NETWORK_DEFAULT_PORT),
       enable_upnp(false){}

      fc::path                      data_dir;
      uint16_t                      network_port;
      bool                          enable_upnp;
      rpc::server::config           rpc_config;
      std::vector<fc::ip::endpoint> default_nodes;
      std::vector<std::string>      default_mail_nodes;
  };

  class application_delegate
  {
     public:

     virtual ~application_delegate(){}

     virtual void connection_count_changed( int count ){}
     virtual void received_text( const bitchat::decrypted_message& msg) {}
     virtual void received_email( const bitchat::decrypted_message& msg) {}
  };
  

  /**
   *  This class serves as the interface between the GUI and the back end
   *  business logic.  All external interfaces (RPC, Web, Qt, etc) should
   *  interact with this API and not access lower-level apis directly.  
   */
  class application
  {
    public:
      application();
      ~application();

      void                                 quit();
      static std::shared_ptr<application>  instance();

      void                                 set_profile_directory( const fc::path& dir );
      void                                 configure( const application_config& cfg );
      void                                 connect_to_network();
      application_config                   get_configuration()const;

      void                                 add_node( const fc::ip::endpoint& remote_node_ip_port );
      void                                 set_application_delegate( application_delegate* del );

      bool                                 has_profile()const;
      std::vector<std::wstring>            get_profiles()const;

      profile_ptr                          get_profile();
      profile_ptr                          load_profile( const std::wstring& profile_name, 
                                                         const std::string& password );
      /** This version is needed only by bts::rpc::details::server_impl::register_bitname_methods
          and it should be removed when fc::variant will fully support std::wstring convertion.
      */
      profile_ptr                          load_profile( const std::string& profile_name, 
                                                         const std::string& password );

      profile_ptr                          create_profile( const std::wstring& profile_name, 
                                                           const profile_config& cfg, 
                                                           const std::string& password, std::function<void(double)> progress = std::function<void(double)>() );
                                  
      void                                 add_receive_key( const fc::ecc::private_key& k );

      fc::optional<bitname::name_record>   lookup_name( const std::string& name );
      fc::optional<bitname::name_record>   reverse_name_lookup( const fc::ecc::public_key& key );

      void                                 mine_name( const std::string& name, 
                                                      const fc::ecc::public_key& key, 
                                                      float effort = 0.1 );

      bool  is_mail_connected()const;
      void  send_contact_request( const fc::ecc::public_key& to, const fc::ecc::private_key& from );
      void  send_email( const bitchat::private_email_message& email, 
                        const fc::ecc::public_key& to, const fc::ecc::private_key& from );
      void  send_text_message( const bitchat::private_text_message& txtmsg, 
                               const fc::ecc::public_key& to, const fc::ecc::private_key& from );
      void  set_mining_intensity(int intensity);
      int   get_mining_intensity();

      void  wait_until_quit();

      bts::network::server_ptr get_network()const;

    private:
      std::unique_ptr<detail::application_impl> my;
  };

  typedef std::shared_ptr<application> application_ptr;

} // namespace bts

FC_REFLECT( bts::application_config, (data_dir)(network_port)(rpc_config)(enable_upnp)(default_nodes)(default_mail_nodes) )
