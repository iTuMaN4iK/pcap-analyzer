#include "AnalyzeResult.h"

#include "Utils.h"

#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include <iostream>


namespace itmn
{

    namespace
    {
        constexpr std::pair<LengthRange, int> length_distribution_default[] = {
            {LengthRange::length_64, 0},       {LengthRange::length_65_255, 0},    {LengthRange::length_256_511, 0},
            {LengthRange::length_512_1023, 0}, {LengthRange::length_1024_1518, 0}, {LengthRange::length_1518, 0}};


        constexpr std::pair<Protocols, int> protocol_distribution_default[] = {
            {Protocols::ip_v4, 0}, {Protocols::non_ip_v4, 0}, {Protocols::tcp, 0},
            {Protocols::udp, 0},   {Protocols::icmp, 0},      {Protocols::other_l4, 0}};


        constexpr std::pair<TcpFlags, int> flags_distribution_default[] = {
            {TcpFlags::syn, 0}, {TcpFlags::syn_ack, 0}, {TcpFlags::ack, 0},  {TcpFlags::fin_ack, 0},
            {TcpFlags::rst, 0}, {TcpFlags::rst_ack, 0}, {TcpFlags::other, 0}};

        LengthRange get_length_range(const uint32_t length)
        {
            if (length <= 64)
            {
                return LengthRange::length_64;
            }
            if (length <= 255)
            {
                return LengthRange::length_65_255;
            }
            if (length <= 511)
            {
                return LengthRange::length_256_511;
            }
            if (length <= 1023)
            {
                return LengthRange::length_512_1023;
            }
            if (length <= 1518)
            {
                return LengthRange::length_1024_1518;
            }

            return LengthRange::length_1518;
        }

        std::string GetMacAddr(const void *host)
        {
            ether_addr addr{};
            memcpy(addr.ether_addr_octet, host, 6);
            return ether_ntoa(&addr);
        }

    } // namespace

    AnalyzeResult::AnalyzeResult() :
        package_count_{0}, total_length_{0}, valid_l3_checksum_count_{0}, invalid_l3_checksum_count_{0},
        valid_l4_checksum_count_{0}, invalid_l4_checksum_count_{0},
        length_distribution_{std::cbegin(length_distribution_default), std::cend(length_distribution_default)},
        protocol_distribution_{std::cbegin(protocol_distribution_default), std::cend(protocol_distribution_default)},
        tcp_flags_distribution_{std::cbegin(flags_distribution_default), std::cend(flags_distribution_default)}
    {
    }

    void AnalyzeResult::AddPackage(const pcap_pkthdr *header, const u_char *packet)
    {
        ++package_count_;
        AddLength(header->len);

        const auto *eth_header = reinterpret_cast<struct ether_header *>(const_cast<u_char *>(packet));
        unique_src_mac_.insert(GetMacAddr(&eth_header->ether_shost));
        unique_dst_mac_.insert(GetMacAddr(&eth_header->ether_dhost));

        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        {
            ++protocol_distribution_[Protocols::non_ip_v4];
            return;
        }

        ++protocol_distribution_[Protocols::ip_v4];

        auto *ip_header = reinterpret_cast<iphdr *>(const_cast<u_char *>(packet) + sizeof(ethhdr));
        unique_src_ip_.insert(ntohl(ip_header->saddr));
        unique_dst_ip_.insert(ntohl(ip_header->daddr));
        IpCheckSum(ip_header);

        switch (ip_header->protocol)
        {
        case IPPROTO_TCP:
            ++protocol_distribution_[Protocols::tcp];
            {
                auto *tcp_header =
                    reinterpret_cast<tcphdr *>(const_cast<u_char *>(packet) + sizeof(ethhdr) + ip_header->ihl * 4);
                AddTcpFlags(tcp_header->th_flags);
                unique_src_port_.insert(ntohs(tcp_header->source));
                unique_dst_port_.insert(ntohs(tcp_header->dest));
                TcpCheckSum(ip_header, tcp_header);
            }
            break;
        case IPPROTO_UDP:
            ++protocol_distribution_[Protocols::udp];
            {
                auto *udp_header =
                    reinterpret_cast<udphdr *>(const_cast<u_char *>(packet) + sizeof(ethhdr) + (ip_header->ihl * 4));
                unique_src_port_.insert(ntohs(udp_header->source));
                unique_dst_port_.insert(ntohs(udp_header->dest));
                UdpCheckSum(ip_header, udp_header);
            }
            break;
        case IPPROTO_ICMP:
            {
                ++protocol_distribution_[Protocols::icmp];
            }
            break;
        default:
            ++protocol_distribution_[Protocols::other_l4];
            break;
        }
    }

    void AnalyzeResult::AddLength(const uint32_t length)
    {
        total_length_ += length;
        ++length_distribution_[get_length_range(length)];
    }

    void AnalyzeResult::IpCheckSum(iphdr *ip_header)
    {
        const auto original = ip_header->check;
        const auto calculated = CalcChecksumIp(ip_header);
        if (original == calculated)
        {
            ++valid_l3_checksum_count_;
        }
        else
        {
            ++invalid_l3_checksum_count_;
        }
    }

    void AnalyzeResult::TcpCheckSum(const iphdr *ip_header, tcphdr *tcp_header)
    {
        const auto original_checksum = tcp_header->check;
        const auto calculated = CalcChecksumTcp(ip_header, tcp_header);
        if (original_checksum == calculated)
        {
            ++valid_l4_checksum_count_;
        }
        else
        {
            ++invalid_l4_checksum_count_;
        }
    }

    void AnalyzeResult::UdpCheckSum(const iphdr *ip_header, udphdr *udp_header)
    {
        const auto original_checksum = udp_header->check;
        const auto calculated = CalcChecksumUdp(ip_header, udp_header);
        if (original_checksum == calculated)
        {
            ++valid_l4_checksum_count_;
        }
        else
        {
            ++invalid_l4_checksum_count_;
        }
    }

    void AnalyzeResult::AddTcpFlags(const uint8_t flags)
    {
        static const std::map<uint8_t, TcpFlags> flags_map = {{0x02, TcpFlags::syn}, {0x12, TcpFlags::syn_ack},
                                                              {0x10, TcpFlags::ack}, {0x11, TcpFlags::fin_ack},
                                                              {0x04, TcpFlags::rst}, {0x14, TcpFlags::rst_ack}};

        if (const auto found = flags_map.find(flags); found != std::cend(flags_map))
        {
            ++tcp_flags_distribution_[found->second];
            return;
        }

        ++tcp_flags_distribution_[TcpFlags::other];
    }

    size_t AnalyzeResult::PackageCount() const { return package_count_; }

    size_t AnalyzeResult::TotalLength() const { return total_length_; }

    LengthCountMap AnalyzeResult::LengthDistribution() const { return length_distribution_; }

    ProtocolsCountMap AnalyzeResult::ProtocolDistribution() const { return protocol_distribution_; }

    TcpFlagsCountMap AnalyzeResult::TcpFlagsDistribution() const { return tcp_flags_distribution_; }

    size_t AnalyzeResult::UniqueSrcMacCount() const { return unique_src_mac_.size(); }

    size_t AnalyzeResult::UniqueDstMacCount() const { return unique_dst_mac_.size(); }

    size_t AnalyzeResult::UniqueSrcIpCount() const { return unique_src_ip_.size(); }

    size_t AnalyzeResult::UniqueDstIpCount() const { return unique_dst_ip_.size(); }

    size_t AnalyzeResult::UniqueSrcPortCount() const { return unique_src_port_.size(); }

    size_t AnalyzeResult::UniqueDstPortCount() const { return unique_dst_port_.size(); }

    size_t AnalyzeResult::InvalidL3ChecksumCount() const { return invalid_l3_checksum_count_; }

    size_t AnalyzeResult::ValidL3ChecksumCount() const { return valid_l3_checksum_count_; }

    size_t AnalyzeResult::InvalidL4ChecksumCount() const { return invalid_l4_checksum_count_; }

    size_t AnalyzeResult::ValidL4ChecksumCount() const { return valid_l4_checksum_count_; }

} // namespace itmn
