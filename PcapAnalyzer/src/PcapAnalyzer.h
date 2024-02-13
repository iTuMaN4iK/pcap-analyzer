#pragma once

#include "pcap_analyzer/IPcapAnalyzer.h"

#include <memory>
#include <pcap/pcap.h>
#include <string>

namespace itmn
{

    /**
     * \brief Класс-анализатор PCAP файлов. Отвечает за проведение анализа и предоставление результатов.
     */
    class PcapAnalyzer final : public IPcapAnalyzer
    {
    public:
        /**
         * \brief Конструктор.
         *
         * \param file_name Имя файла, который необходимо проанализировать.
         */
        explicit PcapAnalyzer(const std::string &file_name);

        /**
         * \brief Запускает анализ pcap файла.
         *
         * \return Возвращает результат анализа.
         */
        IAnalyzeResultPtr Analyze() override;

        ~PcapAnalyzer() override = default;

    private:
        // Имя файла PCAP для анализа
        std::string fname_;
        // Ручка PCAP для файла PCAP
        std::unique_ptr<pcap_t, void (*)(pcap_t *)> handle_;
    };

} // namespace itmn
