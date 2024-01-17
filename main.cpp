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


typedef std::vector<unsigned char> buffer_t;
static const size_t msg_header_size = 4;
static const size_t max_msg_size = 4096;
static const std::array<uint8_t, 2> valid_request_types = {0, 2}; 


template<typename T>
T parse_numeric(const buffer_t& buffer, size_t offset)
{
    if (offset + sizeof(T) > buffer.size()) {
        throw std::runtime_error("Invalid offset");
    }
    return *reinterpret_cast<const T*>(&buffer[offset]);
}


const char* parse_charz(const buffer_t& buffer, size_t offset, size_t size)
{
    if (offset + size > buffer.size()) {
        throw std::runtime_error("Invalid offset");
    }
    const char* ret = reinterpret_cast<const char*>(&buffer[offset]);
    return ret;
}


class MessageHeader
{
public:
    MessageHeader(const buffer_t& buffer) :
        buffer_(buffer)
    {}

    u_int16_t size() const
    {
        return parse_numeric<u_int16_t>(buffer_, 0);
    }

    u_int8_t type() const
    {
        return parse_numeric<u_int8_t>(buffer_, 2);
    }

    u_int8_t sequence() const
    {
        return parse_numeric<u_int8_t>(buffer_, 3);
    }

private:
    const buffer_t& buffer_;
};


class Message
{
public:
    Message(const buffer_t& buffer) :
        header(buffer),
        buffer_(buffer)
    {}

    MessageHeader header;

private:
    const buffer_t& buffer_;
};


class LoginRequest :
    public Message
{
public:
    static const u_int8_t type = 0;
};


class EchoRequest :
    public Message
{
public:
    static const u_int8_t type = 2;
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
        buffer_.resize(msg_header_size);
        boost::asio::async_read(
            socket_,
            boost::asio::buffer(buffer_.data(), msg_header_size),
            std::bind(&tcp_connection::header_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        );
    }

private:
    tcp_connection(boost::asio::io_context &io_context) :
        socket_(io_context),
        buffer_(msg_header_size)
    {
    }

    void header_read(boost::system::error_code error, size_t bytes_transferred)
    {
       if (error) {
            std::cout << 
                "Failed to read header. error: " << error <<
                " bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
       }

        MessageHeader header(buffer_);
        if (header.size() > max_msg_size || header.size() <= msg_header_size) {
            std::cout << 
                "Invalid message size. size: " << header.size() <<
                std::endl;
            return;
        }
        if (!std::any_of(
            valid_request_types.begin(), valid_request_types.end(), [&](u_int8_t msg_type){return header.type() == msg_type;}
        )) {
            std::cout << 
                "Invalid message type. type: " << static_cast<u_int16_t>(header.type()) <<
                std::endl;
            return;
        }

        std::cout << "Header read. size: " << header.size() <<
            " type: " << static_cast<u_int16_t>(header.type()) <<
            " sequence: " << static_cast<u_int16_t>(header.sequence()) <<
            std::endl;
        std::cout << "Reading the rest of the message" << std::endl;
        buffer_.resize(header.size());
        boost::asio::async_read(
            socket_,
            boost::asio::buffer(buffer_.data() + msg_header_size, header.size() - msg_header_size),
            std::bind(&tcp_connection::body_read, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        );
    }

    void body_read(boost::system::error_code error, size_t bytes_transferred)
    {
       if (error) {
            std::cout << 
                "Failed to read body. error: " << error <<
                " bytes_transferred: " << bytes_transferred <<
                std::endl;
            return;
       }

        std::cout << 
            "body_read. error: " << error <<
            " bytes_transferred: " << bytes_transferred <<
            std::endl;


        // auto msg = make_daytime_string();
        // boost::asio::async_write(
        //     socket_,
        //     boost::asio::buffer(msg),
        //     std::bind(&tcp_connection::response_write, shared_from_this(), std::placeholders::_1, std::placeholders::_2)
        // );
    }

    void response_write(boost::system::error_code error, size_t bytes_transferred)
    {
    }

    boost::asio::ip::tcp::socket socket_;
    buffer_t buffer_;
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
        std::cout << "Accepted new connection. error: " << error << std::endl;

        if (!error) {
            connection->start();
        }

        start_accept();
    }


    boost::asio::io_context &io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
};


int main()
{
    try {
        boost::asio::io_context io_context;
        tcp_server server(io_context, 12345);
        io_context.run();
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
