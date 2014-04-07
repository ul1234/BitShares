#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_MODULE KhidTest
#include <boost/test/unit_test.hpp>
#include <bts/bitname/bitname_hash.hpp>
#include <fc/log/logger.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/sha512.hpp>
#include <fc/thread/thread.hpp>

#include <fc/reflect/variant.hpp>
#include <iostream>
#include <sstream>
#include <fstream>

#include <boost/assign.hpp>

#include <unicode/unistr.h>

using namespace boost::assign;

using namespace bts::bitname;

std::vector<std::string> group1 = 
  list_of("Officer Bob")               // plain ascii
         ("O\\uFB00icer B\\u00F3b")    // ff ligature, o acute
         ("O\\uFB03cer B\\u00F2b")     // ffi ligature, o grave
         ("\\uFF2F\\uFF46\\uFF46\\uFF49\\uFF43\\uFF45\\uFF52\\u3000\\uFF22\\uFF4F\\uFF42") // full width letters
         ("Officer \\uD835\\uDDA1ob"); // mathematical B
         
std::vector<std::string> group2 = 
  list_of("\\u30B4\\u30B8\\u30E9")                // full width katakana
         ("\\uFF7A\\uFF9E\\uFF7C\\uFF9E\\uFF97"); // half width katakana

std::vector<std::string> group3 = 
  list_of("\\u738B\\u83F2")               // cjk unified
         ("\\uD87E\\uDD29\\u83F2");       // cjk compatibility

std::vector<std::string> group4 = 
  list_of("aether")               // plain ascii
         ("\\u00E6ther");         // ae letter/ligature

std::vector<std::string> group5 = 
  list_of("Superstring")               // plain ascii
         ("Super\\uFB06ring");         // st ligature

std::vector<std::string> group6 = 
  list_of("Scoop")                                // plain ascii
         ("\\u0405\\u0441\\u043E\\u043E\\u0440"); // cyrillic	

std::vector<std::string> group7 = 
  list_of("Big\\u2014boy")                           // em-dash
         ("Big\\u30FCboy")                           // kana prolonged sound mark
         ("Big\\u4E00boy");                          // kanji numeral 1

std::string convertEscapedStringToUtf8(const std::string& escapedString)
{
  UnicodeString unicodeString = UnicodeString(escapedString.c_str()).unescape();
  std::string result;
  unicodeString.toUTF8String(result);
  return result;
}

void test_group(const std::vector<std::string> group_to_test)
{
  assert(group_to_test.size() > 1);
  std::string skeleton_for_this_group(get_keyhotee_id_skeleton(convertEscapedStringToUtf8(group_to_test[0])));
  for (unsigned i = 1; i < group_to_test.size(); ++i)
  {
    std::string skeleton_for_this_id(get_keyhotee_id_skeleton(convertEscapedStringToUtf8(group_to_test[i])));
    assert(skeleton_for_this_id == skeleton_for_this_group);
  }
}

void test_all_groups()
{
  test_group(group1);
  test_group(group2);
  test_group(group3);
  test_group(group4);
  test_group(group5);
  test_group(group6);
  test_group(group7);
}

int main(int argc, char** argv)
{

  if (argc <= 1)
  {
    test_all_groups();
  }
  else if (argc == 2)
  {
    typedef std::multimap<std::string, std::string> string_string_map;
    string_string_map skeletons;
    unsigned num_collisions = 0;
    unsigned num_ids = 0;

    std::ifstream csvFile(argv[1]);
    std::string line;
    while (std::getline(csvFile, line))
    {
      size_t commaPos = line.find(',');
      if (commaPos != std::string::npos)
      {
        std::string khid = line.substr(0, commaPos);
        std::string skeleton(get_keyhotee_id_skeleton(khid));
        skeletons.insert(string_string_map::value_type(skeleton, khid));
        ++num_ids;
      }
    }
    for (string_string_map::iterator iter = skeletons.begin();
         iter != skeletons.end();
         ++iter)
    {
      string_string_map::iterator next_iter = iter;
      ++next_iter;
      if (next_iter != skeletons.end() && next_iter->first == iter->first)
      {
        std::ostringstream collisions;
        collisions << "\"" << iter->second << "\"";
        ++num_collisions;
        while (next_iter != skeletons.end() && next_iter->first == iter->first)
        {
          collisions << ", \"" << next_iter->second << "\"";
          ++num_collisions;
          ++next_iter;
        }
        elog("Error: Keyhotee IDs ${collisions} all reduce to \"${skeleton}\"",
              ("collisions", collisions.str())("skeleton", iter->first));
        iter = next_iter;
      }
    }
    ilog("Processed all ${num_ids} IDs in ${file}, ${count} IDs involved in collisions",("num_ids", num_ids)("file", argv[1])("count",num_collisions));
  }
  return 0;
}
