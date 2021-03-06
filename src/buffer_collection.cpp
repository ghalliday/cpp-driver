/*
  Copyright (c) 2014 DataStax

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "buffer_collection.hpp"

#include "types.hpp"


extern "C" {

CassCollection* cass_collection_new(CassCollectionType type, size_t element_count) {
  cass::BufferCollection* collection = new cass::BufferCollection(type == CASS_COLLECTION_TYPE_MAP,
                                                                 element_count);
  collection->inc_ref();
  return CassCollection::to(collection);
}

void cass_collection_free(CassCollection* collection) {
  collection->dec_ref();
}

CassError cass_collection_append_int32(CassCollection* collection,
                                       cass_int32_t value) {
  collection->append_int32(value);
  return CASS_OK;
}

CassError cass_collection_append_int64(CassCollection* collection,
                                       cass_int64_t value) {
  collection->append_int64(value);
  return CASS_OK;
}

CassError cass_collection_append_float(CassCollection* collection,
                                       cass_float_t value) {
  collection->append_float(value);
  return CASS_OK;
}

CassError cass_collection_append_double(CassCollection* collection,
                                        cass_double_t value) {
  collection->append_double(value);
  return CASS_OK;
}

CassError cass_collection_append_bool(CassCollection* collection,
                                      cass_bool_t value) {
  collection->append_byte(value == cass_true);
  return CASS_OK;
}

CassError cass_collection_append_string(CassCollection* collection,
                                        CassString value) {
  collection->append(value.data, value.length);
  return CASS_OK;
}

CassError cass_collection_append_bytes(CassCollection* collection,
                                       CassBytes value) {
  collection->append(value.data, value.size);
  return CASS_OK;
}

CassError cass_collection_append_uuid(CassCollection* collection,
                                      CassUuid value) {
  collection->append(value);
  return CASS_OK;
}

CassError cass_collection_append_inet(CassCollection* collection,
                                      CassInet value) {
  collection->append(value.address, value.address_length);
  return CASS_OK;
}

CassError cass_collection_append_decimal(CassCollection* collection,
                                         CassDecimal value) {
  collection->append(value.scale, value.varint.data, value.varint.size);
  return CASS_OK;
}

} // extern "C"

namespace cass {

int BufferCollection::encode(int version, BufferVec* bufs) const {
  if (version != 1 && version != 2) return -1;

  int value_size = sizeof(uint16_t);

  for (BufferVec::const_iterator it = bufs_.begin(),
      end = bufs_.end(); it != end; ++it) {
    value_size += sizeof(uint16_t);
    value_size += it->size();
  }

  int buf_size = sizeof(int32_t) + value_size;

  Buffer buf(buf_size);

  size_t pos = buf.encode_int32(0, value_size);

  pos = buf.encode_uint16(pos, is_map_ ? bufs_.size() / 2 : bufs_.size());
  for (BufferVec::const_iterator it = bufs_.begin(),
      end = bufs_.end(); it != end; ++it) {
    pos = buf.encode_uint16(pos, it->size());
    pos = buf.copy(pos, it->data(), it->size());
  }

  bufs->push_back(buf);

  return buf_size;
}

}
