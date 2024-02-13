#include "PcapAnalyzer.h"

#include "AnalyzeResult.h"

#include <netinet/ether.h>
#include <netinet/if_ether.h>

#include <stdexcept>


namespace itmn
{
    PcapAnalyzer::PcapAnalyzer(const std::string &file_name) : handle_(nullptr, pcap_close)
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        auto *handle = pcap_open_offline(file_name.c_str(), errbuf);

        if (handle == nullptr)
        {
            throw std::runtime_error(std::string{"Couldn't open pcap file "} + file_name + ": " + errbuf);
        }

        handle_.reset(handle);
    }

    IAnalyzeResultPtr PcapAnalyzer::Analyze()
    {
        auto result = std::make_unique<AnalyzeResult>();
        pcap_pkthdr *header;
        const u_char *packet;

        while (pcap_next_ex(handle_.get(), &header, &packet) >= 1)
        {
            result->AddPackage(header, packet);
        }

        return result;
    }

    IPcapAnalyzerPtr MakePcapAnalyzer(const std::string &file_name)
    {
        return std::make_unique<PcapAnalyzer>(file_name);
    }


} // namespace itmn
