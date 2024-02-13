#include "AnalyzeResultWriter.h"

#include <iostream>
#include <stdexcept>


namespace itmn
{

    namespace
    {

        constexpr std::string_view length_64 = "<=64";
        constexpr std::string_view length_65_255 = "65-255";
        constexpr std::string_view length_256_511 = "256-511";
        constexpr std::string_view length_512_1023 = "512-1023";
        constexpr std::string_view length_1024_1518 = "1024-1518";
        constexpr std::string_view length_1518 = ">1518";

        constexpr std::string_view ip_v4 = "IPv4";
        constexpr std::string_view non_ip_v4 = "non-IPv4";
        constexpr std::string_view tcp = "TCP";
        constexpr std::string_view udp = "UDP";
        constexpr std::string_view icmp = "ICMP";
        constexpr std::string_view other_l4 = "other L4";

        constexpr std::string_view syn = "SYN";
        constexpr std::string_view syn_ack = "SYN + ACK";
        constexpr std::string_view ack = "ACK";
        constexpr std::string_view fin_ack = "FIN + ACK";
        constexpr std::string_view rst = "RST";
        constexpr std::string_view rst_ack = "RST + ACK";
        constexpr std::string_view other = "other";

        std::string_view GetLengthRangeStr(const LengthRange range)
        {
            static const std::map<LengthRange, std::string_view> enum_to_str = {
                {LengthRange::length_64, length_64},
                {LengthRange::length_65_255, length_65_255},
                {LengthRange::length_256_511, length_256_511},
                {LengthRange::length_512_1023, length_512_1023},
                {LengthRange::length_1024_1518, length_1024_1518},
                {LengthRange::length_1518, length_1518}};

            if (const auto found = enum_to_str.find(range); found != std::cend(enum_to_str))
            {
                return found->second;
            }

            throw std::runtime_error(std::string{"Can't get str for range " + std::to_string(static_cast<int>(range))});
        }

        std::string_view GetProtocolStr(const Protocols protocol)
        {
            static const std::map<Protocols, std::string_view> enum_to_str = {
                {Protocols::ip_v4, ip_v4}, {Protocols::non_ip_v4, non_ip_v4}, {Protocols::tcp, tcp},
                {Protocols::udp, udp},     {Protocols::icmp, icmp},           {Protocols::other_l4, other_l4}};

            if (const auto found = enum_to_str.find(protocol); found != std::cend(enum_to_str))
            {
                return found->second;
            }

            throw std::runtime_error(
                std::string{"Can't get str for range " + std::to_string(static_cast<int>(protocol))});
        }

        std::string_view GetTcpFlagStr(const TcpFlags flag)
        {
            static const std::map<TcpFlags, std::string_view> enum_to_str = {
                {TcpFlags::syn, syn},         {TcpFlags::syn_ack, syn_ack}, {TcpFlags::ack, ack},
                {TcpFlags::fin_ack, fin_ack}, {TcpFlags::rst, rst},         {TcpFlags::rst_ack, rst_ack},
                {TcpFlags::other, other}};

            if (const auto found = enum_to_str.find(flag); found != std::cend(enum_to_str))
            {
                return found->second;
            }

            throw std::runtime_error(std::string{"Can't get str for range " + std::to_string(static_cast<int>(flag))});
        }


    } // namespace

    void AnalyzeResultWriter::operator()(const IAnalyzeResultPtr &result)
    {
        if (!result)
        {
            throw std::runtime_error(std::string{"result is nullptr "});
        }

        std::cout << "Total packets: " << result->PackageCount() << std::endl;
        std::cout << "Total length: " << result->TotalLength() << std::endl;
        std::cout << "Distribution of packet lengths in bytes: " << std::endl;
        for (auto &[lenght_str, count] : result->LengthDistribution())
        {
            std::cout << GetLengthRangeStr(lenght_str) << ": " << count << std::endl;
        }
        std::cout << std::endl;

        std::cout << "Distribution by protocol: " << std::endl;
        for (const auto &[protocol, count] : result->ProtocolDistribution())
        {
            std::cout << GetProtocolStr(protocol) << ": " << count << std::endl;
        }
        std::cout << std::endl;

        std::cout << "Number of unique values by field: " << std::endl;
        std::cout << "src_mac " << result->UniqueSrcMacCount() << std::endl;
        std::cout << "dst_mac " << result->UniqueDstMacCount() << std::endl;
        std::cout << "src_ip " << result->UniqueSrcIpCount() << std::endl;
        std::cout << "dst_ip " << result->UniqueDstIpCount() << std::endl;
        std::cout << "src_port " << result->UniqueSrcPortCount() << std::endl;
        std::cout << "dst_port " << result->UniqueDstPortCount() << std::endl;
        std::cout << std::endl;
        std::cout << "Distribution by flags SYN, ACK, FIN, RST: " << std::endl;
        for (const auto &[flag, count] : result->TcpFlagsDistribution())
        {
            std::cout << GetTcpFlagStr(flag) << ": " << count << std::endl;
        }
        std::cout << std::endl;

        std::cout << "Number of packets with correct checksum of L3 headers: " << result->ValidL3ChecksumCount()
                  << std::endl;
        std::cout << "Number of packets with incorrect checksum of L3 headers: " << result->InvalidL3ChecksumCount()
                  << std::endl;
        std::cout << "Number of packets with correct checksum of L4 headers: " << result->ValidL4ChecksumCount()
                  << std::endl;
        std::cout << "Number of packets with incorrect checksum of L4 headers: " << result->InvalidL4ChecksumCount()
                  << std::endl;
    }

    IAnalyzeResultWriterPtr MakeAnalyzeResultWriter() { return std::make_unique<AnalyzeResultWriter>(); }

} // namespace itmn
