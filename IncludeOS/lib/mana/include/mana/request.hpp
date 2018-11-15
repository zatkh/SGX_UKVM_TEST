// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015-2016 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MANA_REQUEST_HPP
#define MANA_REQUEST_HPP

#include <net/http/request.hpp>
#include <net/http/status_codes.hpp>
#include "attribute.hpp"
#include "params.hpp"

#include <map>

namespace mana {

class Request;
using Request_ptr = std::shared_ptr<Request>;

class Request_error : public std::runtime_error {
public:
  Request_error(http::status_t code, const char* err)
    : std::runtime_error{err}, code_{code}
  {}

  http::status_t code() const
  { return code_; }

private:
  http::status_t code_;
};

/**
 * @brief A wrapper around a HTTP Request.
 * @details Extends the basic HTTP Request by adding n attributes (Attribute)
 *
 */
class Request {
public:
  /**
   * @brief      Construct a Request with a given http::Request
   *
   * @param[in]  req   The HTTP request
   */
  explicit Request(http::Request_ptr req);

  /**
   * @brief      Construct a Request by internally creating a http::Request
   *
   * @param[in]  req  The HTTP request to be created
   */
  explicit Request(http::Request&& req);

  /**
   * @brief      Returns the underlying HTTP header
   *
   * @return     A HTTP header
   */
  auto& header()
  { return req_->header(); }

  const auto& header() const
  { return req_->header(); }

  /**
   * @brief      Returns the underlying HTTP method
   *
   * @return     The requests HTTP method
   */
  auto method() const
  { return req_->method(); }

  /**
   * @brief      Returns the Requests URI
   *
   * @return     The requests URI
   */
  const auto& uri() const
  { return req_->uri(); }

  /**
   * @brief      Returns the underlying HTTP Request object
   *
   * @return     The HTTP Request object
   */
  auto& source()
  { return *req_; }

  /**
   * @brief Check if the given attribute exists.
   * @details Iterates over map and check if the given
   *
   * @tparam A : The specific attribute
   * @return : If the Request has the specific attribute.
   */
  template<typename A>
  bool has_attribute() const;

  /**
   * @brief Retrieve a shared ptr to the specific attribute.
   * @details Try to retrieve the specific attribute by looking up the type
   * as key inside the attribute map.
   *
   * @tparam A : The specific attribute
   * @return : A shared ptr to the specific attribute. (Can be null if not exists.)
   */
  template<typename A>
  std::shared_ptr<A> get_attribute();

  /**
   * @brief Add/set a specific attribute.
   * @details Inserts a shared ptr of the specific attribute with type as key. (Will replace if already exists)
   *
   * @param  : A shared ptr to the specific attribute
   * @tparam A : The specific attribute
   */
  template<typename A>
  void set_attribute(std::shared_ptr<A>);

  std::string route_string() const
  { return "@" + std::string(http::method::str(req_->method())) + ":" + std::string(req_->uri().path()); }

  void set_params(const Params& params) { params_ = params; }

  const Params& params() const { return params_; }

private:
  http::Request_ptr req_;
  /**
   * @brief A map with pointers to attributes.
   * @details A map with a unique key to a specific attribute
   * and a pointer to the base class Attribute.
   * (Since we got more than one request, an Attribute can't be static)
   */
  std::map<AttrType, Attribute_ptr> attributes_;

  Params params_;

}; // < class Request

template<typename A>
bool Request::has_attribute() const {
  return attributes_.find(Attribute::type<A>()) != attributes_.end();
}

template<typename A>
std::shared_ptr<A> Request::get_attribute() {
  auto it = attributes_.find(Attribute::type<A>());
  if(it != attributes_.end())
    return std::static_pointer_cast<A>(it->second);
  return nullptr;
}

template<typename A>
void Request::set_attribute(std::shared_ptr<A> attr) {
  attributes_.insert({Attribute::type<A>(), attr});
}

}; // < namespace mana

#endif
