#pragma once
#include <bts/bitchat/bitchat_private_message.hpp>
#include <bts/bitchat/bitchat_message_db.hpp>
#include <bts/bitchat/email_draft.hpp>
#include <bts/addressbook/addressbook.hpp>
#include <bts/keychain.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/variant_object.hpp>
#include <fc/filesystem.hpp>

namespace bts {
  namespace detail { class profile_impl; }

  /*
  struct meta_transaction 
  {
     bts::blockchain::meta_trx           trx;
     fc::time_point                      date;
     std::string                         memo;
     uint32_t                            confirmations;
     fc::optional<std::string>           error_message;
  };
  */

  /**
   *  By salting your the seed with easy-to-remember personal
   *  information, it enhances the security of the password from
   *  bruteforce, untargeted, attacks.  Someone specifically
   *  targeting you could find out this information and then
   *  attempt to attack your password.  
   *
   *  @note all of this information, save your password, is
   *        on your credit report.  You should still pick
   *        a reasonable length, uncommon password. We also
   *        cache this information on disk encrypted with just
   *        password so you don't have to enter it all of the
   *        time.   If your computer is compromised, atacks
   *        will become easier.
   */
  struct profile_config
  {
      profile_config()
      :birth_month(0),birth_day_of_month(0),birth_year(0){}

      std::string firstname;
      std::string middlename;
      std::string lastname;
      std::string birth_state;
      uint8_t     birth_month;
      uint8_t     birth_day_of_month;
      uint16_t    birth_year;
      std::string governmentid;
      std::string brainkey;
  };


  /**
   *   A user's profile is backed by a master password that can unlock all of their
   *   private keys.  This profile is the *true identity* of an individual and it
   *   must be protected rigoriously as identity thieves will attempt to derive
   *   the master password and then steal all of your pseudonyms and account balances.
   *
   *   Because passwords can be guessed and checked in a decentralized manner, it is
   *   critical that the password be partially derived from unique personal information 
   *   so that untargeted dictionary attacks are not useable.  
   *
   *   Your profile information will be stored locally on disk in an encrypted manner,
   *   but the security of your local files is only as secure as the password itself 
   *   because the profile will cache the rest.  Your profile may also be compromised
   *   by key loggers if your local computer is compromised.  It is ultimately up to the
   *   the GUI developer to design a secure means of entering the password and enforcing
   *   password quality.
   */
  class profile
  {
    public:
      profile();
      ~profile();
      void  create( const fc::path& profile_dir, const profile_config& cfg, const std::string& password, std::function<void(double)> progress = std::function<void(double)>() );
      void  open( const fc::path& profile_dir, const std::string& password );

      std::vector<addressbook::wallet_identity>   identities()const;

      void                                        removeIdentity( const std::string& id);

      bool                                        isIdentityPresent( const std::string& id);

      void                                        store_identity( const addressbook::wallet_identity& id );
      /** 
       * @throw key_not_found_exception if no such identity has been created
       */
      addressbook::wallet_identity                get_identity(const std::string& dac_id_string )const;
      
      /**
       *  Checks the transaction to see if any of the inp
       */
      //void                        cache( const bts::blockchain::meta_transaction& mtrx );
      void                          cache( const bts::bitchat::decrypted_message& msg    );

      // std::vector<meta_transaction> get_transactions()const;
      bitchat::message_db_ptr       get_inbox_db()const;
      bitchat::message_db_ptr       get_draft_db()const;
      bitchat::message_db_ptr       get_pending_db()const;
      bitchat::message_db_ptr       get_sent_db()const;
      bitchat::message_db_ptr       get_chat_db()const;
      bitchat::message_db_ptr       get_request_db()const;
      bitchat::message_db_ptr       get_auth_db()const;
      addressbook::addressbook_ptr  get_addressbook()const;
      keychain                      get_keychain()const;
      std::wstring                  get_name()const;

      fc::time_point                get_last_sync_time()const;
      void                          set_last_sync_time( const fc::time_point& n );
    private:
      std::unique_ptr<detail::profile_impl> my;
  };

  typedef std::shared_ptr<profile> profile_ptr;
  profile_ptr get_profile();



} // namespace bts

FC_REFLECT( bts::profile_config,
  (firstname)
  (middlename)
  (lastname)
  (birth_state)
  (birth_month)
  (birth_day_of_month)
  (birth_year)
  (governmentid)
  (brainkey)
)
