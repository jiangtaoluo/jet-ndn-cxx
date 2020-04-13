/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "ndn-cxx/data.hpp"
#include "ndn-cxx/encoding/block-helpers.hpp"
#include "ndn-cxx/util/sha256.hpp"

#include "ndn-cxx/util/random.hpp"  // jet, jzq,: for fastPush
#include "ndn-cxx/util/time.hpp" // Jiangtao Luo. 12 Apr 2020
namespace ndn {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<Data>));
BOOST_CONCEPT_ASSERT((WireEncodable<Data>));
BOOST_CONCEPT_ASSERT((WireEncodableWithEncodingBuffer<Data>));
BOOST_CONCEPT_ASSERT((WireDecodable<Data>));
static_assert(std::is_base_of<tlv::Error, Data::Error>::value,
              "Data::Error must inherit from tlv::Error");

Data::Data(const Name& name)
  : m_name(name)
  , m_content(tlv::Content)
  , m_tsBorn(-1) // Jiangtao Luo. 13 Apr 2020
{
  
}

Data::Data(const Block& wire)
{
  wireDecode(wire);
}

template<encoding::Tag TAG>
size_t
Data::wireEncode(EncodingImpl<TAG>& encoder, bool wantUnsignedPortionOnly) const
{
  // Data ::= DATA-TLV TLV-LENGTH
  //            Name
  //            MetaInfo?
  //            Content?
  //            SignatureInfo
  //            SignatureValue
  ////////////////////////////////
  // Jiangtao. 10 Feb 2020
  //            EI
  //            Nonce
  ////////////////////////////////
  // Jiangtao Luo. 12 Apr 2020
  //            BornTime
  ////////////////////////////////

  size_t totalLength = 0;

  ////////////////////////////////
  // Jiangtao Luo. 12 Apr 2020

  // Born Time
  //time::system_clock::TimePoint now = time::system_clock::now();
  if (m_tsBorn >= 0) {
      totalLength += prependNonNegativeIntegerBlock(encoder,
                                                  tlv::BornTime,
                                                 getBornTime());
  }
  /////////////////////

  /**
   * Jiangtao Luo. 10 Feb 2020  
   * Jzq Mar.14 .2019
  */

  // Nonce
  if(hasNonce()){
    uint32_t nonce = getNonce(); // if nonce was unset, getNonce generates a random nonce
    totalLength += encoder.prependByteArrayBlock(tlv::Nonce, reinterpret_cast<uint8_t*>(&nonce), sizeof(nonce));
  }

  // EmergencyInd
  if(m_emergencyInd.size()>0){
     totalLength += prependStringBlock(encoder,tlv::EmergencyInd, getEmergencyInd());
  }
 
  ////////////////////////////////
  
  // SignatureValue
  if (!wantUnsignedPortionOnly) {
    if (!m_signature) {
      BOOST_THROW_EXCEPTION(Error("Requested wire format, but Data has not been signed"));
    }
    totalLength += encoder.prependBlock(m_signature.getValue());
  }

  // SignatureInfo
  totalLength += encoder.prependBlock(m_signature.getInfo());

  // Content
  totalLength += encoder.prependBlock(getContent());

  // MetaInfo
  totalLength += getMetaInfo().wireEncode(encoder);

  // Name
  totalLength += getName().wireEncode(encoder);

  if (!wantUnsignedPortionOnly) {
    totalLength += encoder.prependVarNumber(totalLength);
    totalLength += encoder.prependVarNumber(tlv::Data);
  }
  return totalLength;
}

template size_t
Data::wireEncode<encoding::EncoderTag>(EncodingBuffer&, bool) const;

template size_t
Data::wireEncode<encoding::EstimatorTag>(EncodingEstimator&, bool) const;

const Block&
Data::wireEncode(EncodingBuffer& encoder, const Block& signatureValue) const
{
  size_t totalLength = encoder.size();
  totalLength += encoder.appendBlock(signatureValue);

  encoder.prependVarNumber(totalLength);
  encoder.prependVarNumber(tlv::Data);

  const_cast<Data*>(this)->wireDecode(encoder.block());
  return m_wire;
}

const Block&
Data::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  const_cast<Data*>(this)->wireDecode(buffer.block());
  return m_wire;
}

void
Data::wireDecode(const Block& wire)
{
  // Data ::= DATA-TLV TLV-LENGTH
  //            Name
  //            MetaInfo?
  //            Content?
  //            SignatureInfo
  //            SignatureValue
  ////////////////////////////////
  // Jiangtao Luo. JZQ. 10 Feb 2020
  //            EI
  //            Nounce
  ////////////////////////////////
  ////////////////////////////////
  // Jiangtao Luo. 12 Apr
  //            BornTime
  ////////////////////////////////

  m_wire = wire;
  m_wire.parse();

  auto element = m_wire.elements_begin();
  if (element == m_wire.elements_end() || element->type() != tlv::Name) {
    BOOST_THROW_EXCEPTION(Error("Name element is missing or out of order"));
  }
  m_name.wireDecode(*element);
  int lastElement = 1; // last recognized element index, in spec order

  m_metaInfo = MetaInfo();
  m_content = Block(tlv::Content);
  m_signature = Signature();
  m_fullName.clear();

  for (++element; element != m_wire.elements_end(); ++element) {
    switch (element->type()) {
      case tlv::MetaInfo: {
        if (lastElement >= 2) {
          BOOST_THROW_EXCEPTION(Error("MetaInfo element is out of order"));
        }
        m_metaInfo.wireDecode(*element);
        lastElement = 2;
        break;
      }
      case tlv::Content: {
        if (lastElement >= 3) {
          BOOST_THROW_EXCEPTION(Error("Content element is out of order"));
        }
        m_content = *element;
        lastElement = 3;
        break;
      }
      case tlv::SignatureInfo: {
        if (lastElement >= 4) {
          BOOST_THROW_EXCEPTION(Error("SignatureInfo element is out of order"));
        }
        m_signature.setInfo(*element);
        lastElement = 4;
        break;
      }
      case tlv::SignatureValue: {
        if (lastElement >= 5) {
          BOOST_THROW_EXCEPTION(Error("SignatureValue element is out of order"));
        }
        m_signature.setValue(*element);
        lastElement = 5;
        break;
      }
      ////////////////////////////////
       /**
     * decode EmergencyInd Nonce
     * Jzq Mar.14. 2019
     * Jet. 10 Feb 2020
     */
      case tlv::EmergencyInd: {
        if (lastElement >= 6) {
            BOOST_THROW_EXCEPTION(Error("EmergencyInd element is out of order"));
        }
        m_emergencyInd = readString(*element);
        lastElement = 6;
        break;
        }
      case tlv::Nonce: {
        uint32_t nonce = 0;
        if (lastElement >= 7) {
            BOOST_THROW_EXCEPTION(Error("Nonce element is out of order"));
        }
        if (element->value_size() != sizeof(nonce)) {
            BOOST_THROW_EXCEPTION(Error("Nonce element is malformed"));
        }
        std::memcpy(&nonce, element->value(), sizeof(nonce));
        m_nonce = nonce;
        lastElement = 7;
        break;
      }

      ////////////////////////////////
      ////////////////////////////////
      // Jiangtao Luo. 12 Apr 2020
      case tlv::BornTime: {
        if (lastElement >= 8) {
          BOOST_THROW_EXCEPTION(Error("BornTime element is out of order"));
        }
         m_tsBorn = readNonNegativeInteger(*element);
        // uint64_t ts = 0;
        // std::memcpy(&ts, element->value(), sizeof(ts));
        // m_tsBorn = ts;
        lastElement = 8;
        break;
      }
      ////////////////////////////////
      default: {
        if (tlv::isCriticalType(element->type())) {
          BOOST_THROW_EXCEPTION(Error("unrecognized element of critical type " +
                                      to_string(element->type())));
        }
        break;
      }
    }
  }

  if (!m_signature) {
    BOOST_THROW_EXCEPTION(Error("SignatureInfo element is missing"));
  }
}

////////////////////////////////
/**
 * Jzq add Data field accesors EmergencyInd Nonce
 * @param ei EmergencyInd values,which come from enum class EI
 *
 */
Data&
Data::setEmergencyInd(const EI ei)
{
    m_emergencyInd = ei;
    m_wire.reset();
    return *this;
}
uint32_t
Data::getNonce() const
{
  if(!m_nonce){
    m_nonce = random::generateWord32();
  }
  return *m_nonce;
}
Data&
Data::setNonce(uint32_t nonce)
{
  m_nonce = nonce;
  m_wire.reset();
  return *this;
}
////////////////////////////////

const Name&
Data::getFullName() const
{
  if (m_fullName.empty()) {
    if (!m_wire.hasWire()) {
      BOOST_THROW_EXCEPTION(Error("Cannot compute full name because Data has no wire encoding (not signed)"));
    }
    m_fullName = m_name;
    m_fullName.appendImplicitSha256Digest(util::Sha256::computeDigest(m_wire.wire(), m_wire.size()));
  }

  return m_fullName;
}

void
Data::resetWire()
{
  m_wire.reset();
  m_fullName.clear();
}

Data&
Data::setName(const Name& name)
{
  resetWire();
  m_name = name;
  return *this;
}

Data&
Data::setMetaInfo(const MetaInfo& metaInfo)
{
  resetWire();
  m_metaInfo = metaInfo;
  return *this;
}

const Block&
Data::getContent() const
{
  if (!m_content.hasWire()) {
    const_cast<Block&>(m_content).encode();
  }
  return m_content;
}

Data&
Data::setContent(const Block& block)
{
  resetWire();

  if (block.type() == tlv::Content) {
    m_content = block;
  }
  else {
    m_content = Block(tlv::Content, block);
  }

  return *this;
}

Data&
Data::setContent(const uint8_t* value, size_t valueSize)
{
  resetWire();
  m_content = makeBinaryBlock(tlv::Content, value, valueSize);
  return *this;
}

Data&
Data::setContent(ConstBufferPtr value)
{
  resetWire();
  m_content = Block(tlv::Content, std::move(value));
  return *this;
}

Data&
Data::setSignature(const Signature& signature)
{
  resetWire();
  m_signature = signature;
  return *this;
}

Data&
Data::setSignatureValue(const Block& value)
{
  resetWire();
  m_signature.setValue(value);
  return *this;
}

Data&
Data::setContentType(uint32_t type)
{
  resetWire();
  m_metaInfo.setType(type);
  return *this;
}

Data&
Data::setFreshnessPeriod(time::milliseconds freshnessPeriod)
{
  resetWire();
  m_metaInfo.setFreshnessPeriod(freshnessPeriod);
  return *this;
}

Data&
Data::setFinalBlock(optional<name::Component> finalBlockId)
{
  resetWire();
  m_metaInfo.setFinalBlock(std::move(finalBlockId));
  return *this;
}

bool
operator==(const Data& lhs, const Data& rhs)
{
  return lhs.getName() == rhs.getName() &&
         lhs.getMetaInfo() == rhs.getMetaInfo() &&
         lhs.getContent() == rhs.getContent() &&
         lhs.getSignature() == rhs.getSignature();
}

std::ostream&
operator<<(std::ostream& os, const Data& data)
{
  os << "Name: " << data.getName() << "\n";
  os << "MetaInfo: " << data.getMetaInfo() << "\n";
  os << "Content: (size: " << data.getContent().value_size() << ")\n";
  os << "Signature: (type: " << data.getSignature().getType()
     << ", value_length: "<< data.getSignature().getValue().value_size() << ")";
  os << std::endl;

  return os;
}

////////////////////////////////
// Jiangtao Luo. 12 Apr 2020
Data&
Data::setBornTime(uint64_t ts)
{
  m_tsBorn = ts;
  m_wire.reset();
  return *this;
}

} // namespace ndn
