// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

#include "src/common.h"

namespace {
// Invoke the actual linked SDK conversions, without duplicating their integer implementation.
NAN_METHOD(RoundTrip) {
  if (info.Length() != 1 || !info[0]->IsObject()) {
    return Nan::ThrowTypeError("The native offset fixture requires an object");
  }
  const int64_t value = NodeKafka::GetParameter<int64_t>(
      info[0].As<v8::Object>(), "offset", -99);
  rd_kafka_topic_partition_list_t* list = rd_kafka_topic_partition_list_new(1);
  rd_kafka_topic_partition_t* item = rd_kafka_topic_partition_list_add(
      list, "owned-native-boundary", 0);
  item->offset = value;
  v8::Local<v8::Array> result =
      NodeKafka::Conversion::TopicPartition::ToTopicPartitionV8Array(list, true);
  rd_kafka_topic_partition_list_destroy(list);
  info.GetReturnValue().Set(Nan::Get(result, 0).ToLocalChecked());
}
NAN_MODULE_INIT(Initialize) {
  Nan::SetMethod(target, "roundTrip", RoundTrip);
}
NODE_MODULE(owned_kafka_offset_fixture, Initialize)
}  // namespace
