#include <fc/crypto/city.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/exception/exception.hpp>
#include <fc/log/logger.hpp>
#include <algorithm>
#include <locale>
#include <iomanip>
#include <sstream>

#include <unicode/translit.h>
#include <unicode/uidna.h>
#include <unicode/usprep.h>
#include <unicode/uspoof.h>
#include <unicode/utypes.h>

//#define VERBOSE_DEBUG

///////////////////////////////////////////////////////////////////////////////////////////////////
///   Code below was originally placed inside ICU, but punycode conversion was needed here      ///
///////////////////////////////////////////////////////////////////////////////////////////////////
namespace {
  /* Punycode parameters for Bootstring */
#define BASE            36
#define TMIN            1
#define TMAX            26
#define SKEW            38
#define DAMP            700
#define INITIAL_BIAS    72
#define INITIAL_N       0x80

  /* "Basic" Unicode/ASCII code points */
#define _HYPHEN         0X2d
#define DELIMITER       _HYPHEN

#define _ZERO_          0X30
#define _NINE           0x39

#define _SMALL_A        0X61
#define _SMALL_Z        0X7a

#define _CAPITAL_A      0X41
#define _CAPITAL_Z      0X5a

#define IS_BASIC(c) ((c)<0x80)
#define IS_BASIC_UPPERCASE(c) (_CAPITAL_A<=(c) && (c)<=_CAPITAL_Z)

  /**
  * digitToBasic() returns the basic code point whose value
  * (when used for representing integers) is d, which must be in the
  * range 0 to BASE-1. The lowercase form is used unless the uppercase flag is
  * nonzero, in which case the uppercase form is used.
  */
  static inline char
    digitToBasic(int32_t digit, UBool uppercase) {
      /*  0..25 map to ASCII a..z or A..Z */
      /* 26..35 map to ASCII 0..9         */
      if(digit < 26) {
        if(uppercase) {
          return (char)(_CAPITAL_A + digit);
          }
        else {
          return (char)(_SMALL_A + digit);
          }
        }
      else {
        return (char)((_ZERO_ - 26) + digit);
        }
    }

  static inline char
    asciiCaseMap(char b, UBool uppercase) {
      if(uppercase) {
        if(_SMALL_A <= b && b <= _SMALL_Z) {
          b -= (_SMALL_A - _CAPITAL_A);
          }
        }
      else {
        if(_CAPITAL_A <= b && b <= _CAPITAL_Z) {
          b += (_SMALL_A - _CAPITAL_A);
          }
        }
      return b;
    }

  /* Bias adaptation function. */
  static int32_t
    adaptBias(int32_t delta, int32_t length, UBool firstTime) {
      int32_t count;

      if(firstTime) {
        delta /= DAMP;
        }
      else {
        delta /= 2;
        }

      delta += delta / length;
      for(count = 0; delta > ((BASE - TMIN)*TMAX) / 2; count += BASE) {
        delta /= (BASE - TMIN);
        }

      return count + (((BASE - TMIN + 1)*delta) / (delta + SKEW));
    }

  /**
  * NUL-terminate a UChar * string if possible.
  * If length  < destCapacity then NUL-terminate.
  * If length == destCapacity then do not terminate but set U_STRING_NOT_TERMINATED_WARNING.
  * If length  > destCapacity then do not terminate but set U_BUFFER_OVERFLOW_ERROR.
  *
  * @param dest Destination buffer, can be NULL if destCapacity==0.
  * @param destCapacity Number of UChars available at dest.
  * @param length Number of UChars that were (to be) written to dest.
  * @param pErrorCode ICU error code.
  * @return length
  */
  U_CAPI int32_t U_EXPORT2
    u_terminateUChars(UChar *dest, int32_t destCapacity, int32_t length, UErrorCode *pErrorCode);

#define MAX_CP_COUNT    200

  U_CFUNC int32_t
    u_strToPunycode(const UChar *src, int32_t srcLength,
    UChar *dest, int32_t destCapacity,
    const UBool *caseFlags,
    UErrorCode *pErrorCode) {

      int32_t cpBuffer[MAX_CP_COUNT];
      int32_t n, delta, handledCPCount, basicLength, destLength, bias, j, m, q, k, t, srcCPCount;
      UChar c, c2;

      /* argument checking */
      if(pErrorCode == NULL || U_FAILURE(*pErrorCode)) {
        return 0;
        }

      if(src == NULL || srcLength < -1 || (dest == NULL && destCapacity != 0)) {
        *pErrorCode = U_ILLEGAL_ARGUMENT_ERROR;
        return 0;
        }

      /*
      * Handle the basic code points and
      * convert extended ones to UTF-32 in cpBuffer (caseFlag in sign bit):
      */
      srcCPCount = destLength = 0;
      if(srcLength == -1) {
        /* NUL-terminated input */
        for(j = 0; /* no condition */; ++j) {
          if((c = src[j]) == 0) {
            break;
            }
          if(srcCPCount == MAX_CP_COUNT) {
            /* too many input code points */
            *pErrorCode = U_INDEX_OUTOFBOUNDS_ERROR;
            return 0;
            }
          if(IS_BASIC(c)) {
            cpBuffer[srcCPCount++] = 0;
            if(destLength < destCapacity) {
              dest[destLength] =
                caseFlags != NULL ?
                asciiCaseMap((char)c, caseFlags[j]) :
                (char)c;
              }
            ++destLength;
            }
          else {
            n = (caseFlags != NULL && caseFlags[j]) << 31L;
            if(U16_IS_SINGLE(c)) {
              n |= c;
              }
            else if(U16_IS_LEAD(c) && U16_IS_TRAIL(c2 = src[j + 1])) {
              ++j;
              n |= (int32_t)U16_GET_SUPPLEMENTARY(c, c2);
              }
            else {
              /* error: unmatched surrogate */
              *pErrorCode = U_INVALID_CHAR_FOUND;
              return 0;
              }
            cpBuffer[srcCPCount++] = n;
            }
          }
        }
      else {
        /* length-specified input */
        for(j = 0; j < srcLength; ++j) {
          if(srcCPCount == MAX_CP_COUNT) {
            /* too many input code points */
            *pErrorCode = U_INDEX_OUTOFBOUNDS_ERROR;
            return 0;
            }
          c = src[j];
          if(IS_BASIC(c)) {
            cpBuffer[srcCPCount++] = 0;
            if(destLength < destCapacity) {
              dest[destLength] =
                caseFlags != NULL ?
                asciiCaseMap((char)c, caseFlags[j]) :
                (char)c;
              }
            ++destLength;
            }
          else {
            n = (caseFlags != NULL && caseFlags[j]) << 31L;
            if(U16_IS_SINGLE(c)) {
              n |= c;
              }
            else if(U16_IS_LEAD(c) && (j + 1) < srcLength && U16_IS_TRAIL(c2 = src[j + 1])) {
              ++j;
              n |= (int32_t)U16_GET_SUPPLEMENTARY(c, c2);
              }
            else {
              /* error: unmatched surrogate */
              *pErrorCode = U_INVALID_CHAR_FOUND;
              return 0;
              }
            cpBuffer[srcCPCount++] = n;
            }
          }
        }

      /* Finish the basic string - if it is not empty - with a delimiter. */
      basicLength = destLength;
      if(basicLength > 0) {
        if(destLength < destCapacity) {
          dest[destLength] = DELIMITER;
          }
        ++destLength;
        }

      /*
      * handledCPCount is the number of code points that have been handled
      * basicLength is the number of basic code points
      * destLength is the number of chars that have been output
      */

      /* Initialize the state: */
      n = INITIAL_N;
      delta = 0;
      bias = INITIAL_BIAS;

      /* Main encoding loop: */
      for(handledCPCount = basicLength; handledCPCount < srcCPCount; /* no op */) {
        /*
        * All non-basic code points < n have been handled already.
        * Find the next larger one:
        */
        for(m = 0x7fffffff, j = 0; j < srcCPCount; ++j) {
          q = cpBuffer[j] & 0x7fffffff; /* remove case flag from the sign bit */
          if(n <= q && q<m) {
            m = q;
            }
          }

        /*
        * Increase delta enough to advance the decoder's
        * <n,i> state to <m,0>, but guard against overflow:
        */
        if(m - n>(0x7fffffff - MAX_CP_COUNT - delta) / (handledCPCount + 1)) {
          *pErrorCode = U_INTERNAL_PROGRAM_ERROR;
          return 0;
          }
        delta += (m - n)*(handledCPCount + 1);
        n = m;

        /* Encode a sequence of same code points n */
        for(j = 0; j < srcCPCount; ++j) {
          q = cpBuffer[j] & 0x7fffffff; /* remove case flag from the sign bit */
          if(q < n) {
            ++delta;
            }
          else if(q == n) {
            /* Represent delta as a generalized variable-length integer: */
            for(q = delta, k = BASE; /* no condition */; k += BASE) {

              /** RAM: comment out the old code for conformance with draft-ietf-idn-punycode-03.txt

              t=k-bias;
              if(t<TMIN) {
              t=TMIN;
              } else if(t>TMAX) {
              t=TMAX;
              }
              */

              t = k - bias;
              if(t < TMIN) {
                t = TMIN;
                }
              else if(k >= (bias + TMAX)) {
                t = TMAX;
                }

              if(q < t) {
                break;
                }

              if(destLength < destCapacity) {
                dest[destLength] = digitToBasic(t + (q - t) % (BASE - t), 0);
                }
              ++destLength;
              q = (q - t) / (BASE - t);
              }

            if(destLength < destCapacity) {
              dest[destLength] = digitToBasic(q, (UBool)(cpBuffer[j] < 0));
              }
            ++destLength;
            bias = adaptBias(delta, handledCPCount + 1, (UBool)(handledCPCount == basicLength));
            delta = 0;
            ++handledCPCount;
            }
          }

        ++delta;
        ++n;
        }

      return u_terminateUChars(dest, destCapacity, destLength, pErrorCode);
    }

} /// anonymous
///////////////////////////////////////////////////////////////////////////////////////////////////
///                   End of Code ICU code supporting, punycode conversion                      ///
///////////////////////////////////////////////////////////////////////////////////////////////////


namespace bts { namespace bitname {

/** this singleton class manages the Transliterator and USpoofChecker objects
 * we use from ICU.  They're somewhat expensive to create, so we keep them
 * around between invocations.
 */ 
class keyhotee_id_hash_generator {
private:
  /** Performs the following operations on the unicode string:
   *  - removes accents
   *  - removes whitespace
   *  - case folds to lowercase
   *  - converts to the compatibility composed normalization form (NFKC)
   */
  std::unique_ptr<Transliterator> _transliterator;
  USpoofChecker*                  _spoofchecker;

  keyhotee_id_hash_generator();
  ~keyhotee_id_hash_generator();

  std::string normalize_unicode_chars(const std::string& string_to_normalize);
  static void convert_to_punycode(const std::string& input, std::string* buffer);
  static bool is_invalid_char(char c);
  static void collapse_runs_of_char(std::string& stringToModify, char charToCollapse);
  static char replace_similar(char c);
  static uint64_t get_name_hash_for_skeleton(const std::string& keyhotee_id_skeleton);
public:
  static keyhotee_id_hash_generator* get_instance();
  std::string get_keyhotee_id_skeleton(const std::string& keyhotee_id);
  uint64_t name_hash(const std::string& keyhotee_id);
};

keyhotee_id_hash_generator* keyhotee_id_hash_generator::get_instance()
{
  static keyhotee_id_hash_generator hash_generator;
  return &hash_generator;
}

keyhotee_id_hash_generator::keyhotee_id_hash_generator() :
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

  _spoofchecker = uspoof_open(&status);
  if (U_FAILURE(status))
  {
    elog("unable to create spoofchecker");
    _spoofchecker = 0;
  }
  if (_spoofchecker)
  {
    // configure it
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
  if (_spoofchecker)
    uspoof_close(_spoofchecker);
  _spoofchecker = 0;
}

std::string keyhotee_id_hash_generator::normalize_unicode_chars(const std::string& string_to_normalize)
{
  UnicodeString unicode_string_to_normalize(UnicodeString::fromUTF8(string_to_normalize.c_str()));

  /* First step in normalizing the string.  Run it through a filter that:
   *  - removes accents
   *  - removes whitespace
   *  - case folds to lowercase
   *  - converts to the compatibility composed normalization form (NFKC)
   */
  UnicodeString unicode_output_string(unicode_string_to_normalize);
  if (_transliterator)
    _transliterator->transliterate(unicode_output_string);
  else
    wlog("Unable to run transliterate on khid, other clients may not be able to verify this id");

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    std::ostringstream bytes;
    std::string utf8_output_string;
    unicode_output_string.toUTF8String(utf8_output_string);
    for (unsigned i = 0; i < utf8_output_string.size(); ++i)
      bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8_output_string[i] << " ";
    ilog("Keyhotee ID after transliterating unicode characters: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",
         ("source", string_to_normalize)("dest", utf8_output_string)("bytes",bytes.str()));
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
    UnicodeString unicode_skeleton_string;
    uspoof_getSkeletonUnicodeString(_spoofchecker, 0, unicode_output_string, unicode_skeleton_string, &status);
    if (U_FAILURE(status))
      FC_THROW("Error generating skeleton string from khid");
    unicode_output_string = unicode_skeleton_string;

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
    {
      std::ostringstream bytes;
      std::string utf8_output_string;
      unicode_output_string.toUTF8String(utf8_output_string);
      for (unsigned i = 0; i < utf8_output_string.size(); ++i)
        bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8_output_string[i] << " ";
      ilog("Keyhotee ID after converting to skeleton: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",
           ("source", string_to_normalize)("dest", utf8_output_string)("bytes",bytes.str()));
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
    _transliterator->transliterate(unicode_output_string);
  else
    wlog("Unable to run transliterate on khid, other clients may not be able to verify this id");
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    std::ostringstream bytes;
    std::string utf8_output_string;
    unicode_output_string.toUTF8String(utf8_output_string);
    for (unsigned i = 0; i < utf8_output_string.size(); ++i)
      bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8_output_string[i] << " ";
    ilog("Keyhotee ID after second transliteration: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",
         ("source", string_to_normalize)("dest", utf8_output_string)("bytes",bytes.str()));
  }
#endif

  std::string utf8_output_string;
  unicode_output_string.toUTF8String(utf8_output_string);
  return utf8_output_string;
}

void keyhotee_id_hash_generator::convert_to_punycode(const std::string& input, std::string* buffer)
{
  UnicodeString unicode_output_string(UnicodeString::fromUTF8(input.c_str()));

  size_t buffer_length = 1024;
  std::unique_ptr<UChar[]> buf(new UChar[buffer_length]);
  UErrorCode status = U_ZERO_ERROR;

  size_t destLen = u_strToPunycode(unicode_output_string.getBuffer(), unicode_output_string.length(), 
                                   buf.get(), buffer_length, 
                                   NULL, &status);
  if(status == U_BUFFER_OVERFLOW_ERROR)
  {
    status = U_ZERO_ERROR;
    buffer_length = destLen + 1;
    buf.reset(new UChar[buffer_length]);
    u_strToPunycode(unicode_output_string.getBuffer(), unicode_output_string.length(), 
                    buf.get(), buffer_length, 
                    NULL, &status);
  }
  if(U_SUCCESS(status))
  {
    unicode_output_string = buf.get();
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
    {
      std::ostringstream bytes;
      std::string utf8_output_string;
      unicode_output_string.toUTF8String(utf8_output_string);
      for (unsigned i = 0; i < utf8_output_string.size(); ++i)
        bytes << std::hex << std::setw(2) << std::setfill('0') << (unsigned)(unsigned char)utf8_output_string[i] << " ";
      ilog("Keyhotee ID after punycode: \"${source}\" -> \"${dest}\" (output bytes: ${bytes})",
           ("source", input)("dest", utf8_output_string)("bytes",bytes.str()));
    }
#endif
  }
  else
    wlog("Unable to convert khid to punycode string, other clients may not be able to verify this id");

  buffer->clear();
  unicode_output_string.toUTF8String(*buffer);
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

  case '0': // 0 O Q
  case 'q':
  case 'o': return 'o';

  case 'd': return 'd';

  case '8': // 8 B are easily confused
  case 'b': return 'b';

  case 'u':
  case 'w':
  case 'v': return 'u';

  case '.': return '.';
  case '_': 
  case '-': return '_';

  default:
    return 0;
  }
}

/** Replace runs of multiple consecutive '.' characters with a single '.'
 * This is executed after the replace_similar has already converted
 * '.', '_', and '-' to '.', so the effect is that a string like
 * "foo------bar" becomes equivalent to "foo-bar"
 */
void keyhotee_id_hash_generator::collapse_runs_of_char(std::string& stringToModify, char charToCollapse)
{
  if (stringToModify.size() > 1)
    for (size_t p = 0; p < stringToModify.size() - 1;)
      if (stringToModify[p] == charToCollapse && stringToModify[p + 1] == charToCollapse)
        stringToModify.erase(p, 1);
      else
        ++p;
}

uint64_t keyhotee_id_hash_generator::get_name_hash_for_skeleton(const std::string& keyhotee_id_skeleton)
{
  if(keyhotee_id_skeleton.empty())
    return 0;

  return fc::hash64(keyhotee_id_skeleton.c_str(), keyhotee_id_skeleton.size());
}

/**
 * @param keyhotee_id - the name in UTF-8 format
 */
std::string keyhotee_id_hash_generator::get_keyhotee_id_skeleton( const std::string& keyhotee_id )
{
  if( keyhotee_id.size() == 0 )
    return "";

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
    return "";
  }

  std::string puny_name;
  convert_to_punycode(normalized_id, &puny_name);

  // a punycode string consists of two parts: all the standard ASCII characters are grouped
  // together at the front, followed by a hyphen, then an encoded version of the non-ASCII
  // characters at the end.
  // We still want to apply stricter spoof-proofing rules to the ASCII part, but there's no
  // sense in spoof-proofing the encoded unicode characters.  Split off the ASCII bit
  // to work on here:
  size_t last_hyphen_pos = puny_name.rfind('-');
  std::string ascii_portion;
  std::string unicode_portion;
  if (last_hyphen_pos != std::string::npos)
  {
    unicode_portion = puny_name.substr(last_hyphen_pos + 1);
    ascii_portion = puny_name.substr(0, last_hyphen_pos);
  }
  else
    unicode_portion = puny_name;

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("split Punycode string into ASCII part \"${ascii}\" and Unicode part \"${unicode}\"",("ascii", ascii_portion)("unicode", unicode_portion));
#endif


  // replace similar-looking characters in the ASCII part that could be confusing
  std::transform(ascii_portion.begin(), ascii_portion.end(), ascii_portion.begin(), &replace_similar);

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  {
    // replace_similar puts null characters in the string, we need to remove those before printing it
    std::ostringstream string_with_nulls;
    for (unsigned i = 0; i < ascii_portion.size(); ++i)
      if (ascii_portion[i])
        string_with_nulls << ascii_portion[i];
      else
        string_with_nulls << "\\0";
    ilog("after replace_similar: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", string_with_nulls.str()));
  }
#endif

  // remove any and all hidden or invalid characters
  ascii_portion.erase(std::remove_if(ascii_portion.begin(), ascii_portion.end(), is_invalid_char), ascii_portion.end());

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("after removing invaid chars: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", ascii_portion));
#endif

  // replace long runs of .... characters with a single . 
  collapse_runs_of_char(ascii_portion, '.');
  // replace long runs of ___ and --- with a single _
  collapse_runs_of_char(ascii_portion, '_');
#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("after removing runs of '.': \"${source}\" -> \"${dest}\")",("source", keyhotee_id)("dest", ascii_portion));
#endif

  // remove a leading or trailing '.', because they can be easily missed, especially near the end 
  // of a sentence
  if( ascii_portion.size() && ascii_portion.front() == '.' )
    ascii_portion.erase(0,1);
  if( ascii_portion.size() && ascii_portion.back() == '.' )
    ascii_portion.erase(ascii_portion.size() - 1);

  // note, we're not removing leading and trailing underscores or hyphens.  That will 
  // allow people to register 'foo' and '_foo' as different IDs, but these 
  // are harder to miss.

#if !defined(NDEBUG) && defined(VERBOSE_DEBUG)
  ilog("after all keyhotee id processing on ascii portion: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", ascii_portion));
#endif

  std::string ascii_name = ascii_portion;
  if (!unicode_portion.empty())
  {
    ascii_name += "-";
    ascii_name += unicode_portion;
  }

#ifndef NDEBUG
  ilog("after all keyhotee id processing: \"${source}\" -> \"${dest}\"",("source", keyhotee_id)("dest", ascii_name));
#endif

  return ascii_name;
}

/**
 * @param keyhotee_id - the name in UTF-8 format
 */
uint64_t keyhotee_id_hash_generator::name_hash(const std::string& keyhotee_id)
{
  return get_name_hash_for_skeleton(get_keyhotee_id_skeleton(keyhotee_id));
}

uint64_t name_hash(const std::string& keyhotee_id)
{
  return keyhotee_id_hash_generator::get_instance()->name_hash(keyhotee_id);
}

std::string get_keyhotee_id_skeleton(const std::string& keyhotee_id)
{
  return keyhotee_id_hash_generator::get_instance()->get_keyhotee_id_skeleton(keyhotee_id);
}

} } // end namespace bts::bitname
