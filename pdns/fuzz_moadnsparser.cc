/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "dnswriter.hh"
#include "statbag.hh"

StatBag S;

bool g_slogStructured{false};

static void init()
{
  reportAllTypes();
}

static void exerciseParsed(const MOADNSParser& parser)
{
  // Force the text-form serialisation of every parsed record. This exercises
  // the per-type getZoneRepresentation() / rcpgenerator paths, which the
  // wire-only parse path otherwise leaves untouched.
  for (const auto& record : parser.d_answers) {
    try {
      (void)record.toString();
    }
    catch (const std::exception&) {
    }
    catch (const PDNSException&) {
    }
  }

  // Re-serialise the parsed records to wire format to exercise
  // DNSPacketWriter and the per-type toPacket() implementations.
  try {
    std::vector<uint8_t> packet;
    DNSPacketWriter writer(packet, parser.d_qname, parser.d_qtype, parser.d_qclass);
    for (const auto& record : parser.d_answers) {
      if (!record.getContent()) {
        continue;
      }
      writer.startRecord(record.d_name, record.d_type, record.d_ttl, record.d_class, record.d_place);
      try {
        record.getContent()->toPacket(writer);
      }
      catch (const std::exception&) {
      }
      catch (const PDNSException&) {
      }
    }
    writer.commit();
  }
  catch (const std::exception&) {
  }
  catch (const PDNSException&) {
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  static bool initialized = false;

  if (!initialized) {
    init();
    initialized = true;
  }

  if (size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  try {
    MOADNSParser moaQuery(true, reinterpret_cast<const char*>(data), size);
    exerciseParsed(moaQuery);
  }
  catch (const std::exception& e) {
  }
  catch (const PDNSException& e) {
  }

  try {
    MOADNSParser moaAnswer(false, reinterpret_cast<const char*>(data), size);
    exerciseParsed(moaAnswer);
  }
  catch (const std::exception& e) {
  }
  catch (const PDNSException& e) {
  }

  return 0;
}
