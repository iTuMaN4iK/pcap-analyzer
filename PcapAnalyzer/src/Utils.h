#pragma once

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstdint>


namespace itmn
{

    struct PseudoHead
    {
        uint8_t zero;
        uint8_t type;
        uint16_t len;
        uint32_t src_ip;
        uint32_t dst_ip;
    };

    [[nodiscard]] inline uint32_t CalcSum(const uint8_t *addr, int count)
    {
        uint32_t sum = 0;
        while (count > 1)
        {
            sum += (*addr << 8) + *(addr + 1);
            addr += 2;
            count -= 2;
        }
        if (count > 0)
        {
            sum += *addr << 8;
        }

        return sum;
    }

    [[nodiscard]] static uint32_t CalcPseudoheadSum(const iphdr *ip_header, const uint8_t type)
    {
        PseudoHead head{};
        head.zero = 0;
        head.type = type;
        head.len = htons(static_cast<uint16_t>(ntohs(ip_header->tot_len) - ip_header->ihl * 4));
        head.src_ip = ip_header->saddr;
        head.dst_ip = ip_header->daddr;
        return CalcSum(reinterpret_cast<uint8_t *>(&head), sizeof(PseudoHead));
    }

    [[nodiscard]] inline uint16_t FinishChecksum(uint32_t sum)
    {
        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;
        return htons(static_cast<uint16_t>(~sum));
    }

    [[nodiscard]] inline uint16_t CalcChecksumIp(iphdr *ip_header)
    {
        ip_header->check = 0;
        const auto sum = CalcSum(reinterpret_cast<uint8_t *>(ip_header), ip_header->ihl * 4);
        return FinishChecksum(sum);
    }

    [[nodiscard]] inline uint16_t CalcChecksumTcp(const iphdr *ip_header, tcphdr *tcp_header)
    {
        tcp_header->check = 0;
        auto sum = CalcPseudoheadSum(ip_header, IPPROTO_TCP);
        sum += CalcSum(reinterpret_cast<uint8_t *>(tcp_header), ntohs(ip_header->tot_len) - ip_header->ihl * 4);
        return FinishChecksum(sum);
    }

    [[nodiscard]] inline uint16_t CalcChecksumUdp(const iphdr *ip_header, udphdr *udp_header)
    {
        udp_header->check = 0;
        uint32_t sum = CalcPseudoheadSum(ip_header, IPPROTO_UDP);
        sum += CalcSum(reinterpret_cast<uint8_t *>(udp_header), ntohs(udp_header->len));
        sum = FinishChecksum(sum);
        return sum == 0x000 ? 0xFFFF : sum;
    }

} // namespace itmn
