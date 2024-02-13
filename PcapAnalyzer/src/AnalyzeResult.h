#pragma once

#include "pcap_analyzer/IAnalyzeResult.h"

#include <map>
#include <string>
#include <unordered_set>


struct udphdr;
struct iphdr;
struct pcap_pkthdr;
struct ip;
struct tcphdr;
struct ether_header;

namespace itmn
{

    /**
     * \brief Класс результата анализа
     */
    class AnalyzeResult final : public IAnalyzeResult
    {
    public:
        /**
         * \brief Конструктор.
         */
        explicit AnalyzeResult();

        [[nodiscard]] size_t PackageCount() const override;
        [[nodiscard]] size_t TotalLength() const override;
        [[nodiscard]] LengthCountMap LengthDistribution() const override;
        [[nodiscard]] ProtocolsCountMap ProtocolDistribution() const override;
        [[nodiscard]] TcpFlagsCountMap TcpFlagsDistribution() const override;
        [[nodiscard]] size_t UniqueSrcMacCount() const override;
        [[nodiscard]] size_t UniqueDstMacCount() const override;
        [[nodiscard]] size_t UniqueSrcIpCount() const override;
        [[nodiscard]] size_t UniqueDstIpCount() const override;
        [[nodiscard]] size_t UniqueSrcPortCount() const override;
        [[nodiscard]] size_t UniqueDstPortCount() const override;
        [[nodiscard]] size_t InvalidL3ChecksumCount() const override;
        [[nodiscard]] size_t ValidL3ChecksumCount() const override;
        [[nodiscard]] size_t InvalidL4ChecksumCount() const override;
        [[nodiscard]] size_t ValidL4ChecksumCount() const override;

        /**
         * \brief Добавить пакет в результат.
         *
         * \param header Указатель на заголовок.
         * \param packet Указатель на данные.
         */
        void AddPackage(const pcap_pkthdr *header, const u_char *packet);


    private:
        /**
         * \brief Добавление длины пакета в общую статистику.
         *
         * \param length Длина пакета
         */
        void AddLength(uint32_t length);

        /**
         * \brief Проверка контрольной суммы IP.
         *
         * \param ip_header Указатель на IP-заголовок
         */
        void IpCheckSum(iphdr *ip_header);

        /**
         * \brief Проверка контрольной суммы TCP.
         *
         * \param ip_header Указатель на IP-заголовок
         * \param tcp_header Указатель на TCP-заголовок
         */
        void TcpCheckSum(const iphdr *ip_header, tcphdr *tcp_header);

        /**
         * \brief Проверка контрольной суммы UDP.
         *
         * \param ip_header Указатель на IP-заголовок
         * \param udp_header Указатель на UDP-заголовок
         */
        void UdpCheckSum(const iphdr *ip_header, udphdr *udp_header);

        /**
         * \brief Добавление флагов TCP в статистику.
         *
         * \param flags Флаги TCP
         */
        void AddTcpFlags(uint8_t flags);

    private:
        //! Общее количество пакетов.
        size_t package_count_;
        //! Общая длина пакетов.
        size_t total_length_;
        //! Количество пакетов с корректной контрольной суммой на уровне L3.
        size_t valid_l3_checksum_count_;
        //! Количество пакетов с некорректной контрольной суммой на уровне L3.
        size_t invalid_l3_checksum_count_;
        //! Количество пакетов с корректной контрольной суммой на уровне L4.
        size_t valid_l4_checksum_count_;
        //! Количество пакетов с некорректной контрольной суммой на уровне L4.
        size_t invalid_l4_checksum_count_;
        //! Распределение пакетов по длине.
        LengthCountMap length_distribution_;
        //! Распределение пакетов по протоколам.
        ProtocolsCountMap protocol_distribution_;
        //! Распределение пакетов по флагам TCP.
        TcpFlagsCountMap tcp_flags_distribution_;
        //! Уникальные источники MAC-адресов.
        std::unordered_set<std::string> unique_src_mac_;
        //! Уникальные назначения MAC-адресов.
        std::unordered_set<std::string> unique_dst_mac_;
        //! Уникальные источники IP-адресов.
        std::unordered_set<uint32_t> unique_src_ip_;
        //! Уникальные назначения IP-адресов.
        std::unordered_set<uint32_t> unique_dst_ip_;
        //! Уникальные источники портов.
        std::unordered_set<uint16_t> unique_src_port_;
        //! Уникальные назначения портов.
        std::unordered_set<uint16_t> unique_dst_port_;
    };


} // namespace itmn
