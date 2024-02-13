#pragma once

#include <map>
#include <memory>


namespace itmn
{

    /**
     * \brief Возможные диапазоны длин IP.
     */
    enum class LengthRange
    {
        length_64 = 0, ///< Длина IP меньше или равна 64 байтам
        length_65_255, ///< Длина IP от 65 до 255 байт
        length_256_511, ///< Длина IP от 256 до 511 байт
        length_512_1023, ///< Длина IP от 512 до 1023 байт
        length_1024_1518, ///< Длина IP от 1024 до 1518 байт
        length_1518, ///< Длина IP больше 1518 байт
    };

    using LengthCountMap = std::map<LengthRange, int>;

    /**
     * \brief Возможные протоколы.
     */
    enum class Protocols
    {
        ip_v4 = 0,
        non_ip_v4,
        tcp,
        udp,
        icmp,
        other_l4,
    };

    using ProtocolsCountMap = std::map<Protocols, int>;

    /**
     * \brief Возможные флаги TCP.
     */
    enum class TcpFlags
    {
        syn = 0,
        syn_ack,
        ack,
        fin_ack,
        rst,
        rst_ack,
        other,
    };

    using TcpFlagsCountMap = std::map<TcpFlags, int>;

    /**
     * \brief Класс результата анализа
     */
    class IAnalyzeResult
    {
    public:
        [[nodiscard]] virtual size_t PackageCount() const = 0;
        [[nodiscard]] virtual size_t TotalLength() const = 0;
        [[nodiscard]] virtual LengthCountMap LengthDistribution() const = 0;
        [[nodiscard]] virtual ProtocolsCountMap ProtocolDistribution() const = 0;
        [[nodiscard]] virtual TcpFlagsCountMap TcpFlagsDistribution() const = 0;
        [[nodiscard]] virtual size_t UniqueSrcMacCount() const = 0;
        [[nodiscard]] virtual size_t UniqueDstMacCount() const = 0;
        [[nodiscard]] virtual size_t UniqueSrcIpCount() const = 0;
        [[nodiscard]] virtual size_t UniqueDstIpCount() const = 0;
        [[nodiscard]] virtual size_t UniqueSrcPortCount() const = 0;
        [[nodiscard]] virtual size_t UniqueDstPortCount() const = 0;
        [[nodiscard]] virtual size_t InvalidL3ChecksumCount() const = 0;
        [[nodiscard]] virtual size_t ValidL3ChecksumCount() const = 0;
        [[nodiscard]] virtual size_t InvalidL4ChecksumCount() const = 0;
        [[nodiscard]] virtual size_t ValidL4ChecksumCount() const = 0;

        virtual ~IAnalyzeResult() = default;
    };

    using IAnalyzeResultPtr = std::unique_ptr<IAnalyzeResult>;

} // namespace itmn
