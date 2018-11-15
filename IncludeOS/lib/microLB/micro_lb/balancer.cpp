#include "balancer.hpp"
#include <net/tcp/stream.hpp>

#define READQ_PER_CLIENT        4096
#define MAX_READQ_PER_NODE      8192
#define READQ_FOR_NODES         8192
#define MAX_OUTGOING_ATTEMPTS    100
// checking if nodes are dead or not
#define ACTIVE_INITIAL_PERIOD     8s
#define ACTIVE_CHECK_PERIOD      30s
// connection attempt timeouts
#define CONNECT_TIMEOUT          10s
#define CONNECT_THROW_PERIOD     20s
#define INITIAL_SESSION_TIMEOUT   5s
#define ROLLING_SESSION_TIMEOUT  60s

#define LB_VERBOSE 0
#if LB_VERBOSE
#define LBOUT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define LBOUT(fmt, ...) /** **/
#endif

using namespace std::chrono;

namespace microLB
{
  Balancer::Balancer(
         netstack_t& incoming, uint16_t in_port,
         netstack_t& outgoing)
    : nodes(), netin(incoming), netout(outgoing), signal({this, &Balancer::handle_queue})
  {
    netin.tcp().listen(in_port,
    [this] (auto conn) {
      if (conn != nullptr) {
        this->incoming(std::make_unique<net::tcp::Stream> (conn));
      }
    });

    this->init_liveupdate();
  }
  int Balancer::wait_queue() const {
    return this->queue.size();
  }
  int Balancer::connect_throws() const {
    return this->throw_counter;
  }
  netstack_t& Balancer::get_client_network() noexcept
  {
    return this->netin;
  }
  netstack_t& Balancer::get_nodes_network() noexcept
  {
    return this->netout;
  }
  const pool_signal_t& Balancer::get_pool_signal() const
  {
    return this->signal;
  }
  void Balancer::incoming(net::Stream_ptr conn)
  {
      queue.emplace_back(std::move(conn));
      LBOUT("Queueing connection (q=%lu)\n", queue.size());
      // IMPORTANT: try to handle queue, in case its ready
      // don't directly call handle_connections() from here!
      this->handle_queue();
  }
  void Balancer::handle_queue()
  {
    // check waitq
    while (nodes.pool_size() > 0 && queue.empty() == false)
    {
      auto& client = queue.front();
      if (client.conn->is_connected()) {
        // NOTE: explicitly want to copy buffers
        net::Stream_ptr rval =
            nodes.assign(std::move(client.conn), client.readq);
        if (rval == nullptr) {
          // done with this queue item
          queue.pop_front();
        }
        else {
          // put connection back in queue item
          client.conn = std::move(rval);
        }
      }
      else {
        queue.pop_front();
      }
    } // waitq check
    // check if we need to create more connections
    this->handle_connections();
  }
  void Balancer::handle_connections()
  {
    // stop any rethrow timer since this is a de-facto retry
    if (this->throw_retry_timer != Timers::UNUSED_ID) {
        Timers::stop(this->throw_retry_timer);
        this->throw_retry_timer = Timers::UNUSED_ID;
    }
    // calculating number of connection attempts to create
    int np_connecting = nodes.pool_connecting();
    int estimate = queue.size() - (np_connecting + nodes.pool_size());
    estimate = std::min(estimate, MAX_OUTGOING_ATTEMPTS);
    estimate = std::max(0, estimate - np_connecting);
    // create more outgoing connections
    if (estimate > 0)
    {
      try {
        nodes.create_connections(estimate);
      }
      catch (std::exception& e)
      {
        this->throw_counter++;
        // assuming the failure is due to not enough eph. ports
        this->throw_retry_timer = Timers::oneshot(CONNECT_THROW_PERIOD,
        [this] (int) {
            this->throw_retry_timer = Timers::UNUSED_ID;
            this->handle_connections();
        });
      }
    } // estimate
  } // handle_connections()

  Waiting::Waiting(net::Stream_ptr incoming)
    : conn(std::move(incoming)), total(0)
  {
    // queue incoming data from clients not yet
    // assigned to a node
    conn->on_read(READQ_PER_CLIENT,
    [this] (auto buf) {
      // prevent buffer bloat attack
      this->total += buf->size();
      if (this->total > MAX_READQ_PER_NODE) {
        conn->close();
      }
      else {
        LBOUT("*** Queued %lu bytes\n", buf->size());
        readq.push_back(buf);
      }
    });
  }

  void Nodes::create_connections(int total)
  {
    // temporary iterator
    for (int i = 0; i < total; i++)
    {
      // look for next active node up to *size* times
      for (size_t i = 0; i < nodes.size(); i++)
      {
        int iter = conn_iterator;
        conn_iterator = (conn_iterator + 1) % nodes.size();
        // if the node is active, connect immediately
        bool is_active = nodes[iter].is_active();
        if (is_active) {
          nodes[iter].connect();
          break;
        }
      }
    }
  }
  net::Stream_ptr Nodes::assign(net::Stream_ptr conn, queue_vector_t& readq)
  {
    for (size_t i = 0; i < nodes.size(); i++)
    {
      auto outgoing = nodes[algo_iterator].get_connection();
      // algorithm here //
      algo_iterator = (algo_iterator + 1) % nodes.size();
      // check if connection was retrieved
      if (outgoing != nullptr)
      {
        assert(outgoing->is_connected());
        LBOUT("Assigning client to node %d (%s)\n",
              algo_iterator, outgoing->to_string().c_str());
        auto& session = this->create_session(
            not readq.empty(), std::move(conn), std::move(outgoing));
        // flush readq to session.outgoing
        for (auto buffer : readq) {
          LBOUT("*** Flushing %lu bytes\n", buffer->size());
          session.outgoing->write(buffer);
        }
        return nullptr;
      }
    }
    return conn;
  }
  size_t Nodes::size() const noexcept {
    return nodes.size();
  }
  Nodes::const_iterator Nodes::begin() const {
    return nodes.cbegin();
  }
  Nodes::const_iterator Nodes::end() const {
    return nodes.cend();
  }
  int Nodes::pool_connecting() const {
    int count = 0;
    for (auto& node : nodes) count += node.connection_attempts();
    return count;
  }
  int Nodes::pool_size() const {
    int count = 0;
    for (auto& node : nodes) count += node.pool_size();
    return count;
  }
  int32_t Nodes::open_sessions() const {
    return session_cnt;
  }
  int64_t Nodes::total_sessions() const {
    return session_total;
  }
  int32_t Nodes::timed_out_sessions() const {
    return session_timeouts;
  }
  Session& Nodes::create_session(bool talk, net::Stream_ptr client, net::Stream_ptr outgoing)
  {
    int idx = -1;
    if (free_sessions.empty()) {
      idx = sessions.size();
      sessions.emplace_back(*this, idx, talk, std::move(client), std::move(outgoing));
    } else {
      idx = free_sessions.back();
      new (&sessions[idx]) Session(*this, idx, talk, std::move(client), std::move(outgoing));
      free_sessions.pop_back();
    }
    session_total++;
    session_cnt++;
    LBOUT("New session %d  (current = %d, total = %ld)\n",
          idx, session_cnt, session_total);
    return sessions[idx];
  }
  Session& Nodes::get_session(int idx)
  {
    auto& session = sessions.at(idx);
    assert(session.is_alive());
    return session;
  }
  void Nodes::close_session(int idx, bool timeout)
  {
    auto& session = get_session(idx);
    // disable timeout timer
    if (session.timeout_timer != Timers::UNUSED_ID) {
      Timers::stop(session.timeout_timer);
      session.timeout_timer = Timers::UNUSED_ID;
    }
    // remove connections
    session.incoming->reset_callbacks();
    session.incoming = nullptr;
    session.outgoing->reset_callbacks();
    session.outgoing = nullptr;
    // free session
    if (timeout) this->session_timeouts++;
    free_sessions.push_back(session.self);
    session_cnt--;
    LBOUT("Session %d closed  (total = %d)\n", session.self, session_cnt);
  }

  Node::Node(netstack_t& stk, net::Socket a, const pool_signal_t& sig)
    : stack(stk), addr(a), pool_signal(sig)
  {
    // periodically connect to node and determine if active
    // however, perform first check immediately
    this->active_timer = Timers::periodic(0s, ACTIVE_CHECK_PERIOD,
    [this] (int) {
      this->perform_active_check();
    });
  }
  void Node::perform_active_check()
  {
    try {
      this->stack.tcp().connect(this->addr,
      [this] (auto conn) {
        this->active = (conn != nullptr);
        // if we are connected, its alive
        if (conn != nullptr)
        {
          // hopefully put this to good use
          pool.push_back(std::make_unique<net::tcp::Stream>(conn));
          // stop any active check
          this->stop_active_check();
          // signal change in pool
          this->pool_signal();
        }
        else {
          // if no periodic check is being done right now,
          // start doing it (after initial delay)
          this->restart_active_check();
        }
      });
    } catch (std::exception& e) {
      // do nothing, because might just be eph.ports used up
    }
  }
  void Node::restart_active_check()
  {
    // set as inactive
    this->active = false;
    // begin checking active again
    if (this->active_timer == Timers::UNUSED_ID)
    {
      this->active_timer = Timers::periodic(
        ACTIVE_INITIAL_PERIOD, ACTIVE_CHECK_PERIOD,
      [this] (int) {
        this->perform_active_check();
      });
    }
  }
  void Node::stop_active_check()
  {
    // set as active
    this->active = true;
    // stop active checking for now
    if (this->active_timer != Timers::UNUSED_ID) {
      Timers::stop(this->active_timer);
      this->active_timer = Timers::UNUSED_ID;
    }
  }
  void Node::connect()
  {
    auto outgoing = this->stack.tcp().connect(this->addr);
    // connecting to node atm.
    this->connecting++;
    // retry timer when connect takes too long
    int fail_timer = Timers::oneshot(CONNECT_TIMEOUT,
    [this, outgoing] (int)
    {
      // close connection
      outgoing->abort();
      // no longer connecting
      assert(this->connecting > 0);
      this->connecting --;
      // restart active check
      this->restart_active_check();
      // signal change in pool
      this->pool_signal();
    });
    // add connection to pool on success, otherwise.. retry
    outgoing->on_connect(
    [this, fail_timer] (auto conn)
    {
      // stop retry timer
      Timers::stop(fail_timer);
      // no longer connecting
      assert(this->connecting > 0);
      this->connecting --;
      // connection may be null, apparently
      if (conn != nullptr && conn->is_connected())
      {
        LBOUT("Connected to %s  (%ld total)\n",
                addr.to_string().c_str(), pool.size());
        this->pool.push_back(std::make_unique<net::tcp::Stream>(conn));
        // stop any active check
        this->stop_active_check();
      }
      else {
        this->restart_active_check();
      }
      // signal change in pool
      this->pool_signal();
    });
  }
  net::Stream_ptr Node::get_connection()
  {
    while (pool.empty() == false) {
        auto conn = std::move(pool.back());
        assert(conn != nullptr);
        pool.pop_back();
        if (conn->is_connected()) return conn;
        else conn->close();
    }
    return nullptr;
  }

  // use indexing to access Session because std::vector
  Session::Session(Nodes& n, int idx, bool talk,
                   net::Stream_ptr inc, net::Stream_ptr out)
      : parent(n), self(idx), incoming(std::move(inc)),
                              outgoing(std::move(out))
  {
    // if the client talked before it was assigned a session, use bigger timeout
    auto timeout = (talk) ? ROLLING_SESSION_TIMEOUT : INITIAL_SESSION_TIMEOUT;
    // session timeout timer
    this->timeout_timer = Timers::oneshot(timeout,
    [&nodes = n, this] (int) {
        this->timeout(nodes);
    });
    incoming->on_read(READQ_PER_CLIENT,
    [this] (auto buf) {
        assert(this->is_alive());
        this->handle_timeout();
        this->outgoing->write(buf);
    });
    incoming->on_close(
    [&nodes = n, idx] () {
        nodes.get_session(idx).outgoing->close();
        //nodes.get_session(idx).incoming->close();
    });
    outgoing->on_read(READQ_FOR_NODES,
    [this] (auto buf) {
        assert(this->is_alive());
        this->handle_timeout();
        this->incoming->write(buf);
    });
    outgoing->on_close(
    [&nodes = n, idx] () {
        //nodes.get_session(idx).outgoing->close();
        nodes.get_session(idx).incoming->close();
    });
  }
  bool Session::is_alive() const {
    return incoming != nullptr;
  }
  void Session::handle_timeout()
  {
    // stop old timer
    Timers::stop(this->timeout_timer);
    // create new timeout
    this->timeout_timer = Timers::oneshot(ROLLING_SESSION_TIMEOUT,
    [&nodes = parent, this] (int) {
        this->timeout(nodes);
    });
  }
  void Session::timeout(Nodes& nodes)
  {
    assert(this->is_alive());
    this->timeout_timer = Timers::UNUSED_ID;
    nodes.close_session(this->self, true);
  }
}
