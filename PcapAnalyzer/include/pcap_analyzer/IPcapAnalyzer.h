#pragma once

#include "IAnalyzeResult.h"

#include <string>


namespace itmn
{

    /**
     * \brief Класс-анализатор PCAP файлов. Отвечает за проведение анализа и предоставление результатов.
     */
    class IPcapAnalyzer
    {
    public:
        /**
         * \brief Запускает анализ pcap файла.
         *
         * \return Возвращает результат анализа.
         */
        [[nodiscard]] virtual IAnalyzeResultPtr Analyze() = 0;

        virtual ~IPcapAnalyzer() = default;
    };

    using IPcapAnalyzerPtr = std::unique_ptr<IPcapAnalyzer>;

    IPcapAnalyzerPtr MakePcapAnalyzer(const std::string &file_name);

} // namespace itmn
