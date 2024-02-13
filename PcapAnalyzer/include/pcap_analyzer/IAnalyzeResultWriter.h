#pragma once

#include "IAnalyzeResult.h"


namespace itmn
{

    /**
     * \brief Этот класс предназначен для записи результатов анализа.
     */
    class IAnalyzeResultWriter
    {
    public:
        /**
         * \brief Записывает результат анализа.
         *
         * \param result Результат анализа.
         */
        virtual void operator()(const IAnalyzeResultPtr &result) = 0;

        virtual ~IAnalyzeResultWriter() = default;
    };

    using IAnalyzeResultWriterPtr = std::unique_ptr<IAnalyzeResultWriter>;

    IAnalyzeResultWriterPtr MakeAnalyzeResultWriter();

} // namespace itmn
