#include <algorithm>
#include <cassert>
#include <ctime>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

#include <boost/asio.hpp>
#include <boost/endian.hpp>


static const size_t max_msg_size = 4096;
static const std::array<uint8_t, 2> valid_request_types = {0, 2}; 


uint8_t calculate_checksum(const std::string& input)
{
    uint8_t checksum = 0;
    for (char c : input) {
        checksum += static_cast<uint8_t>(c);
    }
    // checksum = ~checksum;
    return checksum;
}


uint32_t next_key(uint32_t key)
{
  return (key*1103515245 + 12345) % 0x7FFFFFFF;
}


class CipherKeyGenerator
{
public:
    CipherKeyGenerator(const std::string& username, const std::string& password, uint8_t sequence)
    {
        uint32_t initial_key = sequence << 16 | calculate_checksum(username) << 8 | calculate_checksum(password);
        key_ = next_key(initial_key);
    }

    uint16_t get_next()
    {
        uint8_t ret = key_ % 256;
        key_ = next_key(key_);
        return ret;
    }

private:
    uint32_t key_;
};


class Buffer
{
public:
    size_t get_size() const
    {
        return buffer_.size();
    }

    void resize(size_t size)
    {
        buffer_.resize(size);
    }

    uint8_t* get_ptr(size_t offset)
    {
        if (offset > buffer_.size()) {
            throw std::runtime_error("Invalid offset");
        }
        return &buffer_[offset];
    }

    const char* get_charz(size_t offset, size_t size) const
    {
        if (offset + size > buffer_.size()) {
            throw std::runtime_error("Invalid offset");
        }
        if (std::find(&buffer_[offset], &buffer_[offset + size], 0) == &buffer_[offset + size]) {
            throw std::runtime_error("Invalid string");
        }
        return reinterpret_cast<const char*>(&buffer_[offset]);
    }

    boost::asio::mutable_buffer as_asio_buffer(size_t offset = 0)
    {
        if (offset >= buffer_.size()) {
            throw std::runtime_error("Invalid offset");
        }
        return boost::asio::buffer(buffer_.data() + offset, buffer_.size() - offset);
    }

    template<typename T>
    void pack_numeric(size_t offset, const T& value)
    {
        if (offset + sizeof(T) > buffer_.size()) {
            throw std::runtime_error("Invalid offset");
        }
        *reinterpret_cast<T*>(&buffer_[offset]) = boost::endian::native_to_big<T>(value);
    }

    template<typename T>
    T unpack_numeric(size_t offset) const
    {
        if (offset + sizeof(T) > buffer_.size()) {
            throw std::runtime_error("Invalid offset");
        }
        T ret = *reinterpret_cast<const T*>(&buffer_[offset]);
        return boost::endian::big_to_native<T>(ret);
    }

private:
    std::vector<uint8_t> buffer_;
};


class MessageHeader
{
public:
    static const uint8_t size = 4;

    MessageHeader(Buffer& buffer) :
        buffer_(buffer)
    {}

    uint16_t get_msg_size() const
    {
        return buffer_.unpack_numeric<uint16_t>(0);
    }

    void set_msg_size(uint16_t size)
    {
        buffer_.pack_numeric<uint16_t>(0, size);
    }

    uint8_t get_msg_type() const
    {
        return buffer_.unpack_numeric<uint8_t>(2);
    }

    void set_msg_type(uint8_t type)
    {
        buffer_.pack_numeric<uint8_t>(2, type);
    }

    uint8_t get_msg_sequence() const
    {
        return buffer_.unpack_numeric<uint8_t>(3);
    }

    void set_msg_sequence(uint8_t sequence)
    {
        buffer_.pack_numeric<uint8_t>(3, sequence);
    }

private:
    Buffer& buffer_;
};


class Message
{
public:
    Message(Buffer& buffer) :
        header(buffer),
        buffer_(buffer)
    {}

    MessageHeader header;

protected:
    Buffer& buffer_;
};


class LoginRequest :
    public Message
{
public:
    static const uint8_t type = 0;

    LoginRequest(Buffer& buffer) :
        Message(buffer)
    {}

    const char* username() const
    {
        return buffer_.get_charz(4, 32);
    }

    const char* password() const
    {
        return buffer_.get_charz(36, 32);
    }
};


class LoginResponse :
    public Message
{
public:
    static const uint8_t type = 1;
    static const uint8_t size = MessageHeader::size + 2;

    LoginResponse(Buffer& buffer) :
        Message(buffer)
    {}

    void set_status_code(uint16_t status_code)
    {
        buffer_.pack_numeric<uint16_t>(4, status_code);
    }
};


class EchoRequest :
    public Message
{
public:
    static const uint8_t type = 2;

    EchoRequest(Buffer& buffer) :
        Message(buffer)
    {}

    uint16_t get_cipher_message_size() const
    {
        return buffer_.unpack_numeric<uint16_t>(4);
    }

    // void decrypt_message_inplace(const std::string& username, const std::string& password)
    // {
    //     uint8_t cipher_msg_offset = 6;
    //     uint16_t cipher_message_size = get_cipher_message_size();

    //     if (cipher_msg_offset + cipher_message_size != buffer_.get_size()) {
    //         throw std::runtime_error("Invalid cipher message size.");
    //     }

    //     CipherKeyGenerator key_gen(username, password, header.get_msg_sequence());
    //     uint8_t* begin = buffer_.get_ptr(cipher_msg_offset);
    //     uint8_t* end = buffer_.get_ptr(buffer_.get_size());
    //     std::transform(
    //         begin, end, begin, [&](uint8_t cipher){return cipher ^ key_gen.get_next();}
    //     );
    // }
};


class EchoResponse :
    public Message
{
public:
    static const uint8_t type = 3;

    EchoResponse(Buffer& buffer) :
        Message(buffer)
    {}
};



class tcp_connection :
    public std::enable_shared_from_this<tcp_connection>
{
public:
    typedef std::shared_ptr<tcp_connection> pointer;

    static pointer create(boost::asio::io_context &io_context)
    {
        return std::shared_ptr<tcp_connection>(new tcp_connection(io_context));
    }

    boost::asio::ip::tcp::socket & get_socket()
    {
        return socket_;
    }

    void start()
    {
        std::cout << "Reading header" << std::endl;
        buffer_.resize(MessageHeader::size);
        boost::asio::async_read(
            socket_, buffer_.as_asio_buffer(),
            std::bind(&tcp_connection::header_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        );
    }

private:
    tcp_connection(boost::asio::io_context &io_context) :
        socket_(io_context)
    {
    }

    bool logged_in() const
    {
        return !username_.empty() && !password_.empty();
    }

    void header_read(boost::system::error_code error, size_t bytes_transferred)
    {
        if (error) {
            if (error == boost::asio::error::misc_errors::eof) {
                std::cout << "Client disconnected" << std::endl;
            }
            else {
                std::cerr << 
                    "ERROR - Failed to read header. error: " << error.message() <<
                    ". bytes_transferred: " << bytes_transferred <<
                    std::endl;
            }
            return;
        }

        MessageHeader header(buffer_);
        if (header.get_msg_size() > max_msg_size || header.get_msg_size() <= MessageHeader::size) {
            std::cerr << "ERROR - Invalid message size: " << header.get_msg_size() << std::endl;
            return;
        }
        if (!std::any_of(
            valid_request_types.begin(), valid_request_types.end(), [&](uint8_t msg_type){return header.get_msg_type() == msg_type;}
        )) {
            std::cerr << "ERROR - Invalid message type: " << static_cast<uint16_t>(header.get_msg_type()) << std::endl;
            return;
        }

        std::cout << "Header ok. size: " << header.get_msg_size() <<
            " type: " << static_cast<uint16_t>(header.get_msg_type()) <<
            " sequence: " << static_cast<uint16_t>(header.get_msg_sequence()) <<
            std::endl;
        std::cout << "Reading the rest of the message" << std::endl;

        buffer_.resize(header.get_msg_size());
        boost::asio::async_read(
            socket_, buffer_.as_asio_buffer(MessageHeader::size),
            std::bind(&tcp_connection::body_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        );
    }

    void body_read(boost::system::error_code error, size_t bytes_transferred)
    {
        if (error) {
            std::cerr << 
                "ERROR - Failed to read body. error: " << error.message() <<
                ". bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
        }

        MessageHeader header(buffer_);
        switch (header.get_msg_type())
        {
        case LoginRequest::type:
            process_login_request();
            break;
        case EchoRequest::type:
            process_echo_request();
            break;
        default:
            std::cerr << "ERROR - Invalid message type: " << static_cast<uint16_t>(header.get_msg_type()) << std::endl;
        } 
    }

    void process_login_request()
    {
        std::cout << "Processing login request" << std::endl;

        if (logged_in()) {
            std::cerr << "ERROR - Already logged in" << std::endl;
            return;
        }

        try {
            LoginRequest request(buffer_);
            username_ = request.username();
            password_ = request.password();

            buffer_.resize(LoginResponse::size);
            LoginResponse response(buffer_);
            response.header.set_msg_size(LoginResponse::size);
            response.header.set_msg_type(LoginResponse::type);
            response.set_status_code(1);

            boost::asio::async_write(
                socket_, buffer_.as_asio_buffer(),
                std::bind(&tcp_connection::response_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
            );
        }
        catch (const std::exception& e) {
            std::cerr << "ERROR - Failed to process login request: " << e.what() << std::endl;
        }
    }

    void process_echo_request()
    {
        std::cout << "Processing echo request" << std::endl;

        if (!logged_in()) {
            std::cerr << "ERROR - Not logged in" << std::endl;
            return;
        }

        try {
            EchoRequest request(buffer_);
            // request.decrypt_message_inplace(username_, password_);

            EchoResponse response(buffer_);
            response.header.set_msg_type(EchoResponse::type);

            boost::asio::async_write(
                socket_, buffer_.as_asio_buffer(),
                std::bind(&tcp_connection::response_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
            );
        }
        catch (const std::exception& e) {
            std::cerr << "ERROR - Failed to process echo request: " << e.what() << std::endl;
        }
    }

    void response_write(boost::system::error_code error, size_t bytes_transferred)
    {
        if (error) {
            std::cerr << "ERROR - Failed to write response. error: " << error.message() <<
                " bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
        }

        // Back to reading a header.
        start();
    }

    boost::asio::ip::tcp::socket socket_;
    Buffer buffer_;
    std::string username_;
    std::string password_;
};


class tcp_server
{
public:
    tcp_server(boost::asio::io_context &io_context, boost::asio::ip::port_type port) :
        io_context_(io_context),
        acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
    {
        start_accept();
    }

private:
    void start_accept()
    {
        auto connection = tcp_connection::create(io_context_);
        acceptor_.async_accept(
            connection->get_socket(),
            std::bind(&tcp_server::handle_accept, this, connection, std::placeholders::_1)
        );
    }

    void handle_accept(tcp_connection::pointer connection, boost::system::error_code error)
    {
        if (!error) {
            std::cout << "New connection" << std::endl;
            connection->start();
        }
        else {
            std::cerr << "ERROR - Failed to accept connection: " << error.message() << std::endl;
        }

        // In any case keep accepting connections. 
        start_accept();
    }

    boost::asio::io_context &io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
};


int main()
{
    try {
        boost::asio::ip::port_type port = 12345;
        boost::asio::io_context io_context;
        tcp_server server(io_context, port);
        io_context.run();
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
