/*
  Copyright 2014 DataStax

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

#ifndef __CASS_TESTING_HPP_INCLUDED__
#define __CASS_TESTING_HPP_INCLUDED__

#include "cassandra.h"

#include <string>

namespace cass {

std::string get_host_from_future(CassFuture* future);

unsigned get_connect_timeout_from_cluster(CassCluster* cluster);

int get_port_from_cluster(CassCluster* cluster);

std::string get_contact_points_from_cluster(CassCluster* cluster);


} // namespace cass

#endif
