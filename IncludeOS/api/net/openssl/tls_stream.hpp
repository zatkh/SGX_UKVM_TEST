#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <net/stream.hpp>

//#define VERBOSE_OPENSSL
#ifdef VERBOSE_OPENSSL
#define TLS_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define TLS_PRINT(fmt, ...) /* fmt */
#endif

namespace openssl
{
  struct TLS_stream : public net::Stream
  {
    using Stream_ptr = net::Stream_ptr;

    TLS_stream(SSL_CTX* ctx, Stream_ptr, bool outgoing = false);
    TLS_stream(Stream_ptr, SSL* ctx, BIO*, BIO*);
    virtual ~TLS_stream();

    void write(buffer_t buffer) override;
    void write(const std::string&) override;
    void write(const void* buf, size_t n) override;
    void close() override;
    void reset_callbacks() override;

    net::Socket local() const override {
      return m_transport->local();
    }
    net::Socket remote() const override {
      return m_transport->remote();
    }
    std::string to_string() const override {
      return m_transport->to_string();
    }

    void on_connect(ConnectCallback cb) override {
      m_on_connect = std::move(cb);
    }
    void on_read(size_t, ReadCallback cb) override {
      m_on_read = std::move(cb);
    }
    void on_close(CloseCallback cb) override {
      m_on_close = std::move(cb);
    }
    void on_write(WriteCallback cb) override {
      m_on_write = std::move(cb);
    }

    bool is_connected() const noexcept override {
      return handshake_completed() && m_transport->is_connected();
    }
    bool is_writable() const noexcept override {
      return is_connected() && m_transport->is_writable();
    }
    bool is_readable() const noexcept override {
      return m_transport->is_readable();
    }
    bool is_closing() const noexcept override {
      return m_transport->is_closing();
    }
    bool is_closed() const noexcept override {
      return m_transport->is_closed();
    }

    int get_cpuid() const noexcept override {
      return m_transport->get_cpuid();
    }

    Stream* transport() noexcept override {
      return m_transport.get();
    }

    size_t serialize_to(void*) const override;

  private:
    void tls_read(buffer_t);
    int  tls_perform_stream_write();
    int  tls_perform_handshake();
    bool handshake_completed() const noexcept;
    void close_callback_once();

    enum status_t {
      STATUS_OK,
      STATUS_WANT_IO,
      STATUS_FAIL
    };
    status_t status(int n) const noexcept;

    Stream_ptr m_transport = nullptr;
    SSL*  m_ssl    = nullptr;
    BIO*  m_bio_rd = nullptr;
    BIO*  m_bio_wr = nullptr;
    bool  m_busy = false;
    bool  m_deferred_close = false;
    ConnectCallback  m_on_connect = nullptr;
    ReadCallback     m_on_read    = nullptr;
    WriteCallback    m_on_write   = nullptr;
    CloseCallback    m_on_close   = nullptr;
  };

  inline TLS_stream::TLS_stream(SSL_CTX* ctx, Stream_ptr t, bool outgoing)
    : m_transport(std::move(t))
  {
    ERR_clear_error(); // prevent old errors from mucking things up
    this->m_bio_rd = BIO_new(BIO_s_mem());
    this->m_bio_wr = BIO_new(BIO_s_mem());
    assert(ERR_get_error() == 0 && "Initializing BIOs");
    this->m_ssl = SSL_new(ctx);
    assert(this->m_ssl != nullptr);
    assert(ERR_get_error() == 0 && "Initializing SSL");
    // TLS server-mode
    if (outgoing == false)
        SSL_set_accept_state(this->m_ssl);
    else
        SSL_set_connect_state(this->m_ssl);

    SSL_set_bio(this->m_ssl, this->m_bio_rd, this->m_bio_wr);
    // always-on callbacks
    m_transport->on_read(8192, {this, &TLS_stream::tls_read});
    m_transport->on_close({this, &TLS_stream::close_callback_once});

    // start TLS handshake process
    if (outgoing == true)
    {
      if (this->tls_perform_handshake() < 0) return;
    }
  }
  inline TLS_stream::TLS_stream(Stream_ptr t, SSL* ssl, BIO* rd, BIO* wr)
    : m_transport(std::move(t)), m_ssl(ssl), m_bio_rd(rd), m_bio_wr(wr)
  {
    // always-on callbacks
    m_transport->on_read(8192, {this, &TLS_stream::tls_read});
    m_transport->on_close({this, &TLS_stream::close_callback_once});
  }
  inline TLS_stream::~TLS_stream()
  {
    assert(m_busy == false && "Cannot delete stream while in its call stack");
    SSL_free(this->m_ssl);
  }

  inline void TLS_stream::write(buffer_t buffer)
  {
    if (UNLIKELY(this->is_connected() == false)) {
      TLS_PRINT("TLS_stream::write() called on closed stream\n");
      return;
    }

    int n = SSL_write(this->m_ssl, buffer->data(), buffer->size());
    auto status = this->status(n);
    if (status == STATUS_FAIL) {
      this->close();
      return;
    }

    do {
      n = tls_perform_stream_write();
    } while (n > 0);
  }
  inline void TLS_stream::write(const std::string& str)
  {
    write(net::Stream::construct_buffer(str.data(), str.data() + str.size()));
  }
  inline void TLS_stream::write(const void* data, const size_t len)
  {
    auto* buf = static_cast<const uint8_t*> (data);
    write(net::Stream::construct_buffer(buf, buf + len));
  }

  inline void TLS_stream::tls_read(buffer_t buffer)
  {
    ERR_clear_error();
    uint8_t* buf = buffer->data();
    int      len = buffer->size();

    while (len > 0)
    {
      int n = BIO_write(this->m_bio_rd, buf, len);
      if (UNLIKELY(n < 0)) {
        this->close();
        return;
      }
      buf += n;
      len -= n;

      // if we aren't finished initializing session
      if (UNLIKELY(!handshake_completed()))
      {
        int num = SSL_do_handshake(this->m_ssl);
        auto status = this->status(num);

        // OpenSSL wants to write
        if (status == STATUS_WANT_IO)
        {
          tls_perform_stream_write();
        }
        else if (status == STATUS_FAIL)
        {
          if (num < 0) {
            TLS_PRINT("TLS_stream::SSL_do_handshake() returned %d\n", num);
            #ifdef VERBOSE_OPENSSL
              ERR_print_errors_fp(stdout);
            #endif
          }
          this->close();
          return;
        }
        // nothing more to do if still not finished
        if (handshake_completed() == false) return;
        // handshake success
        if (m_on_connect) m_on_connect(*this);
      }

      // read decrypted data
      do {
        char temp[8192];
        n = SSL_read(this->m_ssl, temp, sizeof(temp));
        if (n > 0) {
          auto buf = net::Stream::construct_buffer(temp, temp + n);
          if (m_on_read) {
            this->m_busy = true;
            m_on_read(std::move(buf));
            this->m_busy = false;
          }
        }
      } while (n > 0);
      // this goes here?
      if (UNLIKELY(this->is_closing() || this->is_closed())) {
        TLS_PRINT("TLS_stream::SSL_read closed during read\n");
        return;
      }
      if (this->m_deferred_close) {
        this->close(); return;
      }

      auto status = this->status(n);
      // did peer request stream renegotiation?
      if (status == STATUS_WANT_IO)
      {
        do {
          n = tls_perform_stream_write();
        } while (n > 0);
      }
      else if (status == STATUS_FAIL)
      {
        this->close();
        return;
      }
      // check deferred closing
      if (this->m_deferred_close) {
        this->close(); return;
      }

    } // while it < end
  } // tls_read()

  inline int TLS_stream::tls_perform_stream_write()
  {
    ERR_clear_error();
    int pending = BIO_ctrl_pending(this->m_bio_wr);
    //printf("pending: %d\n", pending);
    if (pending > 0)
    {
      auto buffer = net::Stream::construct_buffer(pending);
      int n = BIO_read(this->m_bio_wr, buffer->data(), buffer->size());
      assert(n == pending);
      m_transport->write(buffer);
      if (m_on_write) {
        this->m_busy = true;
        m_on_write(n);
        this->m_busy = false;
      }
      return n;
    }
    else {
      BIO_read(this->m_bio_wr, nullptr, 0);
    }
    if (!BIO_should_retry(this->m_bio_wr))
    {
      this->close();
      return -1;
    }
    return 0;
  }
  inline int TLS_stream::tls_perform_handshake()
  {
    ERR_clear_error(); // prevent old errors from mucking things up
    // will return -1:SSL_ERROR_WANT_WRITE
    int ret = SSL_do_handshake(this->m_ssl);
    int n = this->status(ret);
    ERR_print_errors_fp(stderr);
    if (n == STATUS_WANT_IO)
    {
      do {
        n = tls_perform_stream_write();
        if (n < 0) {
          TLS_PRINT("TLS_stream::tls_perform_handshake() stream write failed\n");
        }
      } while (n > 0);
      return n;
    }
    else {
      TLS_PRINT("TLS_stream::tls_perform_handshake() returned %d\n", ret);
      this->close();
      return -1;
    }
  }

  inline void TLS_stream::close()
  {
    //ERR_clear_error();
    if (this->m_busy) {
      this->m_deferred_close = true; return;
    }
    CloseCallback func = std::move(this->m_on_close);
    this->reset_callbacks();
    if (m_transport->is_connected())
        m_transport->close();
    if (func) func();
  }
  inline void TLS_stream::close_callback_once()
  {
    if (this->m_busy) {
      this->m_deferred_close = true; return;
    }
    CloseCallback func = std::move(this->m_on_close);
    this->reset_callbacks();
    if (func) func();
  }
  inline void TLS_stream::reset_callbacks()
  {
    this->m_on_close = nullptr;
    this->m_on_connect = nullptr;
    this->m_on_read  = nullptr;
    this->m_on_write = nullptr;
  }

  inline bool TLS_stream::handshake_completed() const noexcept
  {
    return SSL_is_init_finished(this->m_ssl);
  }
  inline TLS_stream::status_t TLS_stream::status(int n) const noexcept
  {
    int error = SSL_get_error(this->m_ssl, n);
    switch (error)
    {
    case SSL_ERROR_NONE:
        return STATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return STATUS_WANT_IO;
    default:
        return STATUS_FAIL;
    }
  }
} // openssl
