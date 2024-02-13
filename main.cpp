#include <CLI/CLI.hpp>

#include "pcap_analyzer/IAnalyzeResultWriter.h"
#include "pcap_analyzer/IPcapAnalyzer.h"


int main(const int argc, char **argv)
{
    CLI::App app("pcap analyzer");
    std::string input_file;
    app.add_option("-p, --path", input_file, "Path to input file")->required();

    try
    {
        CLI11_PARSE(app, argc, argv);

        const auto analyzer = itmn::MakePcapAnalyzer(input_file);
        const auto result = analyzer->Analyze();
        const auto writer = itmn::MakeAnalyzeResultWriter();
        (*writer)(result);
    }
    catch (const CLI::ParseError &e)
    {
        return app.exit(e);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
