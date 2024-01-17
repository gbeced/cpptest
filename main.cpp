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


typedef std::vector<unsigned char> buffer_t;
static const size_t max_msg_size = 4096;
static const std::array<uint8_t, 2> valid_request_types = {0, 2}; 


template<typename T>
void pack_numeric(const T& value, buffer_t& buffer, size_t offset)
{
    if (offset + sizeof(T) > buffer.size()) {
        throw std::runtime_error("Invalid offset");
    }
    *reinterpret_cast<T*>(&buffer[offset]) = boost::endian::native_to_big<T>(value);
}


template<typename T>
T unpack_numeric(const buffer_t& buffer, size_t offset)
{
    if (offset + sizeof(T) > buffer.size()) {
        throw std::runtime_error("Invalid offset");
    }
    T ret = *reinterpret_cast<const T*>(&buffer[offset]);
    return boost::endian::big_to_native<T>(ret);
}


const char* unpack_charz(const buffer_t& buffer, size_t offset, size_t size)
{
    if (offset + size > buffer.size()) {
        throw std::runtime_error("Invalid offset");
    }
    if (std::find(&buffer[offset], &buffer[offset + size], 0) == &buffer[offset + size]) {
        throw std::runtime_error("Invalid string");
    }
    return reinterpret_cast<const char*>(&buffer[offset]);
}


class MessageHeader
{
public:
    static const u_int8_t size = 4;

    MessageHeader(buffer_t& buffer) :
        buffer_(buffer)
    {}

    u_int16_t get_msg_size() const
    {
        return unpack_numeric<u_int16_t>(buffer_, 0);
    }

    void set_msg_size(u_int16_t size)
    {
        pack_numeric<u_int16_t>(size, buffer_, 0);
    }

    u_int8_t get_msg_type() const
    {
        return unpack_numeric<u_int8_t>(buffer_, 2);
    }

    void set_msg_type(u_int8_t type)
    {
        pack_numeric<u_int8_t>(type, buffer_, 2);
    }

    u_int8_t get_msg_sequence() const
    {
        return unpack_numeric<u_int8_t>(buffer_, 3);
    }

    void set_msg_sequence(u_int8_t sequence)
    {
        pack_numeric<u_int8_t>(sequence, buffer_, 3);
    }

private:
    buffer_t& buffer_;
};


class Message
{
public:
    Message(buffer_t& buffer) :
        header(buffer),
        buffer_(buffer)
    {}

    MessageHeader header;

protected:
    buffer_t& buffer_;
};


class LoginRequest :
    public Message
{
public:
    static const u_int8_t type = 0;

    LoginRequest(buffer_t& buffer) :
        Message(buffer)
    {}

    const char* username() const
    {
        return unpack_charz(buffer_, 4, 32);
    }

    const char* password() const
    {
        return unpack_charz(buffer_, 36, 32);
    }
};


class LoginResponse :
    public Message
{
public:
    static const u_int8_t type = 1;
    static const u_int8_t size = MessageHeader::size + 2;

    LoginResponse(buffer_t& buffer) :
        Message(buffer)
    {}

    void set_status_code(u_int16_t status_code)
    {
        pack_numeric<u_int16_t>(status_code, buffer_, 4);
    }
};


class EchoRequest :
    public Message
{
public:
    static const u_int8_t type = 2;

    EchoRequest(buffer_t& buffer) :
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

    boost::asio::ip::tcp::socket &socket()
    {
        return socket_;
    }

    void start()
    {
        std::cout << "Reading header" << std::endl;
        buffer_.resize(MessageHeader::size);
        boost::asio::async_read(
            socket_,
            boost::asio::buffer(buffer_.data(), buffer_.size()),
            std::bind(&tcp_connection::header_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        );
    }

private:
    tcp_connection(boost::asio::io_context &io_context) :
        socket_(io_context),
        buffer_(MessageHeader::size)
    {
    }

    bool logged_in() const
    {
        return !username_.empty() && !password_.empty();
    }

    void header_read(boost::system::error_code error, size_t bytes_transferred)
    {
       if (error) {
            std::cerr << 
                "ERROR - Failed to read header. error: " << error.message() <<
                ". bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
       }

        MessageHeader header(buffer_);
        if (header.get_msg_size() > max_msg_size || header.get_msg_size() <= MessageHeader::size) {
            std::cerr << "ERROR - Invalid message size: " << header.get_msg_size() << std::endl;
            return;
        }
        if (!std::any_of(
            valid_request_types.begin(), valid_request_types.end(), [&](u_int8_t msg_type){return header.get_msg_type() == msg_type;}
        )) {
            std::cerr << "ERROR - Invalid message type: " << static_cast<u_int16_t>(header.get_msg_type()) << std::endl;
            return;
        }

        std::cout << "Header ok. size: " << header.get_msg_size() <<
            " type: " << static_cast<u_int16_t>(header.get_msg_type()) <<
            " sequence: " << static_cast<u_int16_t>(header.get_msg_sequence()) <<
            std::endl;
        std::cout << "Reading the rest of the message" << std::endl;

        buffer_.resize(header.get_msg_size());
        boost::asio::async_read(
            socket_,
            boost::asio::buffer(buffer_.data() + MessageHeader::size, buffer_.size() - MessageHeader::size),
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
            std::cerr << "ERROR - Invalid message type: " << static_cast<u_int16_t>(header.get_msg_type()) << std::endl;
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
                socket_,
                boost::asio::buffer(buffer_.data(), buffer_.size()),
                std::bind(&tcp_connection::response_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
            );
        }
        catch (const std::exception& e) {
            std::cerr << "ERROR - Failed to process login request: " << e.what() << std::endl;
        }
    }

    void process_echo_request()
    {
        if (!logged_in()) {
            std::cerr << "ERROR - Not logged in" << std::endl;
            return;
        }

        try {
            EchoRequest msg(buffer_);

            std::cout << "Processing echo request" << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "ERROR - Failed to process echo request: " << e.what() << std::endl;
        }
    }

    void response_write(boost::system::error_code error, size_t bytes_transferred)
    {
        if (error) {
            std::cerr << 
                "ERROR - Failed to write response. error: " << error.message() <<
                " bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
        }

        // Back to reading a header.
        start();
    }

    boost::asio::ip::tcp::socket socket_;
    buffer_t buffer_;
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
            connection->socket(),
            std::bind(&tcp_server::handle_accept, this, connection, std::placeholders::_1)
        );
    }

    void handle_accept(tcp_connection::pointer connection, boost::system::error_code error)
    {
        if (!error) {
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
