#pragma once

#include "pcap_analyzer/IAnalyzeResultWriter.h"


namespace itmn
{

    /**
     * \brief Этот класс предназначен для записи результатов анализа.
     */
    class AnalyzeResultWriter final : public IAnalyzeResultWriter
    {
    public:
        /**
         * \brief Записывает результат анализа.
         *
         * \param result Результат анализа.
         */
        void operator()(const IAnalyzeResultPtr &result) override;
    };

} // namespace itmn
