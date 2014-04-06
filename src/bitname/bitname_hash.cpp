#include <fc/crypto/city.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
#include <algorithm>
#include <locale>
#include <iomanip>
#include <sstream>

#include <unicode/translit.h>
#include <unicode/usprep.h>
#include <unicode/uspoof.h>
#include <unicode/uidna.h>

#define VERBOSE_DEBUG 1

extern "C"
{
/* Declare this function provided by ICU, but not exposed in the public
   headers (normally it's called as a final step of ICU's exposed uidna_toASCII 
   function, but that does extra processing that we're not interested in */
U_CFUNC int32_t u_strToPunycode(const UChar *src, int32_t srcLength,
                                UChar *dest, int32_t destCapacity,
                                const UBool *caseFlags,
                                UErrorCode *pErrorCode);
}

namespace bts { namespace bitname {

class keyhotee_id_hash_generator {
private:
  /** Performs the following operations on the unicode string:
   *  - removes accents
   *  - removes whitespace
   *  - case folds to lowercase
   *  - converts to the compatibility composed normalization form (NFKC)
   */
  std::unique_ptr<Transliterator> _transliterator;
  UStringPrepProfile*             _stringprep;
  USpoofChecker*                  _spoofchecker;

  keyhotee_id_hash_generator();
  ~keyhotee_id_hash_generator();

  std::string normalize_unicode_chars(const std::string& stringToNormalize);
  static void convertToPunycode(const std::string& input, std::string* buffer);
  static void convertToASCII(const std::string& input, std::string* buffer);
  static bool is_invalid_char(char c);
  static void replace_dot_runs(std::string& s);
  static char replace_similar(char c);
public:
  static keyhotee_id_hash_generator* get_instance();
  uint64_t name_hash(const std::string& n);
};

keyhotee_id_hash_generator* keyhotee_id_hash_generator::get_instance()
{
  static keyhotee_id_hash_generator hashGenerator;
  return &hashGenerator;
}

keyhotee_id_hash_generator::keyhotee_id_hash_generator() :
  _stringprep(0),
  _spoofchecker(0)
{
  UErrorCode status = U_ZERO_ERROR;
  UnicodeString filter("NFD; [:Nonspacing Mark:] Remove; [:WhiteSpace:] Remove; Lower; NFKC");
  _transliterator.reset(Transliterator::createInstance(filter, UTRANS_FORWARD, status));
  if (U_FAILURE(status))
  {
    elog("unable to create transliterator");
    _transliterator.reset();
  }

  _stringprep = usprep_openByType(USPREP_RFC3491_NAMEPREP, &status);
  if (U_FAILURE(status))
  {
    elog("unable to create stringprep");
    _stringprep = 0;
  }

  _spoofchecker = uspoof_open(&status);
  if (U_FAILURE(status))
  {
    elog("unable to create spoofchecker");
    _spoofchecker = 0;
  }
  if (_spoofchecker)
  {
    uspoof_setChecks(_spoofchecker, USPOOF_MIXED_SCRIPT_CONFUSABLE | USPOOF_INVISIBLE, &status);
    if (U_FAILURE(status))
    {
      elog("unable to configure spoofchecker");
      uspoof_close(_spoofchecker);
      _spoofchecker = 0;
    }
    uspoof_setRestrictionLevel(_spoofchecker, USPOOF_UNRESTRICTIVE);
  }

}

keyhotee_id_hash_generator::~keyhotee_id_hash_generator()
{
  if (_stringprep)
    usprep_close(_stringprep);
  _stringprep = 0;
  if (_spoofchecker)
    uspoof_close(_spoofchecker);
  _spoofchecker = 0;
}

std::string keyhotee_id_hash_generator::normalize_unicode_chars(const std::string& stringToNormalize)
{
  UnicodeString unicodeStringToNormalize(UnicodeString::fromUTF8(stringToNormalize.c_str()));

  /* First step in normalizing the string.  Run it through a filter that:
   */
  UnicodeString unicodeOutputString(unicodeStringToNormalize);
  if (_transliterator)
    _transliterator->transliterate(unicodeOutputString);
  else
    wlog("Unable to run transliterate on khid, other clients may not be able to verify this id");

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    std::ostringstream bytes;
    std::string utf8OutputString;
    unicodeOutputString.toUTF8String(utf8OutputString);
    for (unsigned i = 0; i < utf8OutputString.size(); ++i)
      bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8OutputString[i] << " ";
    ilog("Keyhotee ID after transliterating unicode characters: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", stringToNormalize)("dest", utf8OutputString)("bytes",bytes.str()));
  }
#endif

  /* Second step: Use the spoof checker to generate the 'skeleton' of the string,
   * using confusables.txt version 3.0-draft Revision 1580.
   * I suspect before full release we'll standardize on something later
   * (6.3.0, revision 1.32 looks like the likely candidate)
   */
  if (_spoofchecker)
  {
    UErrorCode status = U_ZERO_ERROR;
    UnicodeString unicodeSkeletonString;
    uspoof_getSkeletonUnicodeString(_spoofchecker, 0, unicodeOutputString, unicodeSkeletonString, &status);
    if (U_FAILURE(status))
      FC_THROW("Error generating skeleton string from khid");
    unicodeOutputString = unicodeSkeletonString;

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
    {
      std::ostringstream bytes;
      std::string utf8OutputString;
      unicodeOutputString.toUTF8String(utf8OutputString);
      for (unsigned i = 0; i < utf8OutputString.size(); ++i)
        bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8OutputString[i] << " ";
      ilog("Keyhotee ID after converting to skeleton: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", stringToNormalize)("dest", utf8OutputString)("bytes",bytes.str()));
    }
#endif
  }
  else
    wlog("Unable to run spoofchecker khid, other clients may not be able to verify this id");    

  /* Third step in normalizing the string.  Run it the first filter again.  
   * Generating the skeleton could have introduced new uppercase, accented
   * characters, or whitespace, so this will get rid of them
   */
  if (_transliterator)
    _transliterator->transliterate(unicodeOutputString);
  else
    wlog("Unable to run transliterate on khid, other clients may not be able to verify this id");
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    std::ostringstream bytes;
    std::string utf8OutputString;
    unicodeOutputString.toUTF8String(utf8OutputString);
    for (unsigned i = 0; i < utf8OutputString.size(); ++i)
      bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8OutputString[i] << " ";
    ilog("Keyhotee ID after second transliteration: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", stringToNormalize)("dest", utf8OutputString)("bytes",bytes.str()));
  }
#endif


  //if (_stringprep)
  //{
  //  UErrorCode status = U_ZERO_ERROR;
  //  UParseError parseError;

  //  size_t bufferLength = 1024;
  //  std::unique_ptr<UChar[]> buf;

  //  do {
  //    buf.reset(new UChar[bufferLength]);
  //    int32_t retLen = usprep_prepare(_stringprep, unicodeStringToNormalize.getBuffer(), unicodeStringToNormalize.length(), 
  //                                    buf.get(), bufferLength, USPREP_ALLOW_UNASSIGNED, 
  //                                    &parseError, &status);
  //    bufferLength *= 2;
  //  } while (status == U_BUFFER_OVERFLOW_ERROR);

  //  if (U_FAILURE(status))
  //  {
  //    if (status == U_INVALID_CHAR_FOUND)
  //      FC_THROW("Invalid character in Keyhotee ID at line ${line} offset ${offset}", ("line", parseError.line)("offset", parseError.offset));
  //    else if (status == U_INDEX_OUTOFBOUNDS_ERROR)
  //      FC_THROW("Keyhotee ID contains too many code points at line ${line} offset ${offset}", ("line", parseError.line)("offset", parseError.offset));
  //    else
  //      FC_THROW("Keyhotee ID failed stringprep at line ${line} offset ${offset}", ("line", parseError.line)("offset", parseError.offset));
  //  }
  //
  //  unicodeOutputString = UnicodeString(buf.get());
  //}
  //else
  //{
  //  wlog("Unable to run stringprep on khid, other clients may not be able to verify this id");
  //  unicodeOutputString = unicodeStringToNormalize;
  //}

//#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
//  std::ostringstream bytes;
//  std::string utf8TempString;
//  unicodeOutputString.toUTF8String(utf8TempString);
//  for (unsigned i = 0; i < utf8TempString.size(); ++i)
//    bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8TempString[i] << " ";
//  ilog("Keyhotee ID after stringprep: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", stringToNormalize)("dest", utf8TempString)("bytes",bytes.str()));
//#endif

#if 0
  size_t bufferLength = 1024;
  std::unique_ptr<UChar[]> buf(new UChar[bufferLength]);
  UErrorCode status = U_ZERO_ERROR;
  UParseError parseError;

  size_t destLen = uidna_toASCII(unicodeOutputString.getBuffer(), unicodeOutputString.length(), buf.get(), bufferLength, 
                                 UIDNA_DEFAULT, &parseError, &status);
  if(status == U_BUFFER_OVERFLOW_ERROR)
  {
    status = U_ZERO_ERROR;
    bufferLength = destLen + 1;
    buf.reset(new UChar[bufferLength]);
    uidna_toASCII(unicodeOutputString.getBuffer(), unicodeOutputString.length(), buf.get(), bufferLength, 
                  UIDNA_DEFAULT, &parseError, &status);
  }
  if(U_SUCCESS(status))
  {
    unicodeOutputString = buf.get();
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
    {
      std::ostringstream bytes;
      std::string utf8OutputString;
      unicodeOutputString.toUTF8String(utf8OutputString);
      for (unsigned i = 0; i < utf8OutputString.size(); ++i)
        bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8OutputString[i] << " ";
      ilog("Keyhotee ID after punycode: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", stringToNormalize)("dest", utf8OutputString)("bytes",bytes.str()));
    }
#endif
  }
  else
    wlog("Unable to convert khid to punycode string, other clients may not be able to verify this id");
#endif

  std::string utf8OutputString;
  unicodeOutputString.toUTF8String(utf8OutputString);
  return utf8OutputString;
}

void keyhotee_id_hash_generator::convertToPunycode(const std::string& input, std::string* buffer)
{
  UnicodeString unicodeOutputString(UnicodeString::fromUTF8(input.c_str()));

  size_t bufferLength = 1024;
  std::unique_ptr<UChar[]> buf(new UChar[bufferLength]);
  UErrorCode status = U_ZERO_ERROR;
  UParseError parseError;

  size_t destLen = u_strToPunycode(unicodeOutputString.getBuffer(), unicodeOutputString.length(), buf.get(), bufferLength, 
                                   NULL, &status);
  if(status == U_BUFFER_OVERFLOW_ERROR)
  {
    status = U_ZERO_ERROR;
    bufferLength = destLen + 1;
    buf.reset(new UChar[bufferLength]);
    u_strToPunycode(unicodeOutputString.getBuffer(), unicodeOutputString.length(), buf.get(), bufferLength, 
                    NULL, &status);
  }
  if(U_SUCCESS(status))
  {
    unicodeOutputString = buf.get();
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
    {
      std::ostringstream bytes;
      std::string utf8OutputString;
      unicodeOutputString.toUTF8String(utf8OutputString);
      for (unsigned i = 0; i < utf8OutputString.size(); ++i)
        bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8OutputString[i] << " ";
      ilog("Keyhotee ID after punycode: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", input)("dest", utf8OutputString)("bytes",bytes.str()));
    }
#endif
  }
  else
    wlog("Unable to convert khid to punycode string, other clients may not be able to verify this id");

  buffer->clear();
  unicodeOutputString.toUTF8String(*buffer);
}

void keyhotee_id_hash_generator::convertToASCII(const std::string& input, std::string* buffer)
{
  assert(buffer != nullptr);
  buffer->reserve(input.size());

  for(const auto& c : input)
    {
    unsigned int cCode = c;
    if(cCode > 0x7F)
      {
      /// Non ASCII character
      char numBuffer[64];
      sprintf(numBuffer, "_0x%X_", cCode);
      buffer->append(numBuffer);
      }
    else
      {
      *buffer += toupper(c);
      }
    }
}

/** valid chars:  A-Z 0-9 _ - . */
bool keyhotee_id_hash_generator::is_invalid_char( char c )
{
  return c == 0;
}

/** @note assumes c has already been converted to upper case asci  */
char keyhotee_id_hash_generator::replace_similar(char c)
{
  switch( c )
  {
     case 'h': return 'h';
     case '4': 
     case 'a': return 'a';


     case '6':
     case 'g': return 'g';

     case 'k': return 'k';

     case '9': // 9999PPP999999P99999P 
     case 'p': return 'p';

     case '2':
     case 'z': 
     case '5':  
     case 's': return 's';

     case '7':
     case 't': return 't';

     case 'x': return 'x';
     case 'y': return 'y'; 

     case '3': 
     case 'e': return 'e';
     case 'f': return 'f';

     case 'l':
     case 'i':
     case '1': return 'i';
     case 'j': return 'j';

     case 'r': // when next to m or n is confusing ie: rn rm 
     case 'm':
     case 'n': return 'n';

     case 'c': return 'c';
     case '0': 
     case '8': // D 0 8 O B are all easily confused
     case 'b': 
     case 'd':
     case 'o':
     case 'q': return 'o';

     case 'u':
     case 'w':
     case 'v': return 'u';

     case '.': 
     case '_': 
     case '-': return '.';

     default:
       return 0;
  }

}

void keyhotee_id_hash_generator::replace_dot_runs(std::string& s)
{
  if (s.size() > 1)
    for (size_t p = 0; p < s.size() - 1;)
      if (s[p] == '.' && s[p + 1] == '.')
        s.erase(p, 1);
      else
        ++p;
}

/**
 * @param n - the name in UTF-8 format
 */
uint64_t keyhotee_id_hash_generator::name_hash( const std::string& keyhotee_id )
{
  if( keyhotee_id.size() == 0 )
    return 0;

  // Note: there was an old todo here suggesting we use http://www.gnu.org/software/libidn/doxygen/ to 
  // convert Chinese to ASCII.  That seemed like a good idea because it's standardized and it
  // generates compact output.  Unfortunately, we already have Chinese keyhotee IDs out in the 
  // wild, and switching to use libidn now will break them.
  
  // Instead, we do something similar unicode processing (RFC 3491 stringprep), followed by
  // a step that strips out accents, and then continues with our legacy ascii-fication.
  // This should give us most of the benefits of libidn's unicode processing except for the
  // compact output.
  std::string normalized_id;
  try
  {
    normalized_id = normalize_unicode_chars(keyhotee_id);
  }
  catch (fc::exception& e)
  {
    wlog("Error normalizing unicode characters in Keyhotee ID string: ${error}", ("error", e.to_detail_string()));
    return 0;
  }

  std::string punyName;
  convertToPunycode(normalized_id, &punyName);

  // a punycode string consists of two parts: all the standard ASCII characters are grouped
  // together at the front, followed by a hyphen, then an encoded version of the non-ASCII
  // characters at the end.
  // We still want to apply stricter spoof-proofing rules to the ASCII part, but there's no
  // sense in spoof-proofing the encoded unicode characters.  Split off the ASCII bit
  // to work on here:
  size_t lastHyphenPos = punyName.rfind('-');
  std::string asciiPortion;
  std::string unicodePortion;
  if (lastHyphenPos != std::string::npos)
  {
    unicodePortion = punyName.substr(lastHyphenPos + 1);
    asciiPortion = punyName.substr(0, lastHyphenPos);
  }
  else
    unicodePortion = punyName;

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("split Punycode string into ASCII part \"${ascii}\" and Unicode part \"${unicode}\"",("ascii", asciiPortion)("unicode", unicodePortion));
#endif


  // replace similar-looking characters in the ASCII part that could be confusing
  std::transform(asciiPortion.begin(), asciiPortion.end(), asciiPortion.begin(), &replace_similar);

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    std::ostringstream stringWithNulls;
    for (unsigned i = 0; i < asciiPortion.size(); ++i)
      if (asciiPortion[i])
        stringWithNulls << asciiPortion[i];
      else
        stringWithNulls << "\0";
    ilog("after replace_similar: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", stringWithNulls.str()));
  }
#endif

  // remove any and all hidden or invalid characters
  asciiPortion.erase(std::remove_if(asciiPortion.begin(), asciiPortion.end(), is_invalid_char), asciiPortion.end());

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("after removing invaid chars: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", asciiPortion));
#endif

  // replace NN UU ___ etc with a single instance to avoid any
  // confusion this way... yes this means mom, moon, noon will be the same.. boob, bob, bo will
  // all be treated the same, so one person can 'claim' all of those names with a single 
  // name registration. 
  //DLN disabled this, as we allowed keyhotee Founder IDs like C and CC
  replace_dot_runs(asciiPortion);
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("after removing runs of '.': \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",("source", keyhotee_id)("dest", asciiPortion));
#endif

  if( asciiPortion.size() && asciiPortion.front() == '.' )
    asciiPortion.erase(0,1);

  if( asciiPortion.size() && asciiPortion.back() == '.' )
    asciiPortion.erase(asciiPortion.size() - 1);

#ifndef NDEBUG
  ilog("after all keyhotee id processing on ascii portion: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", asciiPortion));
#endif

  std::string asciiName = asciiPortion;
  if (!unicodePortion.empty())
  {
    asciiName += "-";
    asciiName += unicodePortion;
  }

#ifndef NDEBUG
  ilog("after all keyhotee id processing: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", asciiName));
#endif

  if(asciiName.empty())
    return 0;

  // secure hash function
  fc::sha256 h = fc::sha256::hash( asciiName.c_str(), asciiName.size() );

  // compress it down to 64 bits
  return fc::hash64( (char*)&h, sizeof(h) );
}

uint64_t name_hash( const std::string& n )
{
  return keyhotee_id_hash_generator::get_instance()->name_hash(n);
}

} } 
