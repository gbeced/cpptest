#include <ctime>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;


std::string make_daytime_string()
{
    using namespace std; // For time_t, time and ctime;
    time_t now = time(0);
    return ctime(&now);
}


class tcp_connection :
    public std::enable_shared_from_this<tcp_connection>
{
public:
    typedef std::shared_ptr<tcp_connection> pointer;

    static pointer create(boost::asio::io_context &io_context)
    {
        return std::shared_ptr<tcp_connection>(new tcp_connection(io_context));
    }

    tcp::socket &socket()
    {
        return socket_;
    }

    void start()
    {
        std::cout << "tcp_connection::start" << std::endl;

        auto msg = make_daytime_string();
        boost::asio::async_write(
            socket_,
            boost::asio::buffer(msg),
            std::bind(&tcp_connection::handle_write, this, std::placeholders::_1, std::placeholders::_2)
        );

        // boost::asio::async_write(
        //     socket_,
        //     boost::asio::buffer(message_),
        //     std::bind(
        //         &tcp_connection::handle_write, shared_from_this(),
        //         boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred
        //     )
        // );
    }

private:
    tcp_connection(boost::asio::io_context &io_context) :
        socket_(io_context)
    {
    }

    void handle_write(boost::system::error_code error, size_t bytes_transferred)
    {
        std::cout << 
            "tcp_connection::handle_write. error: " << error <<
            " bytes_transferred: " << bytes_transferred <<
            std::endl;
    }
    tcp::socket socket_;
};


class tcp_server
{
public:
    tcp_server(boost::asio::io_context &io_context, boost::asio::ip::port_type port) :
        io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
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
        std::cout << "tcp_server::handle_accept. error: " << error << std::endl;

        if (!error)
        {
            connection->start();
        }

        start_accept();
    }


    boost::asio::io_context &io_context_;
    tcp::acceptor acceptor_;
};


int main()
{
    try
    {
        boost::asio::io_context io_context;
        tcp_server server(io_context, 12345);
        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}