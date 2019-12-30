#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <arpa/inet.h>
#include <netflow9.h>
#include <netinet/in.h>
#include <tins/tins.h>
#include <ctime>
#include <functional>
#include <stdexcept>
#include <string>
#include <variant>

struct PCAPPacket
{
    const uint8_t *data;
    size_t len;
    sockaddr addr;
};

// Get packets from file.
std::vector<PCAPPacket> get_packets(const char *pcap_path);

// Convert a sockaddr to sockaddr_in.
sockaddr_in ip4_addr(const sockaddr &addr);

struct NetflowHeader
{
    uint16_t version;
    uint16_t count;
    uint32_t uptime;
    uint32_t timestamp;
    uint32_t sequence;
    uint32_t source_id;
};

// Objects of this class can build Netflow9 packets for unit tests.
class NetflowPacketBuilder
{
public:
    NetflowPacketBuilder() : timestamp_(time(nullptr))
    {
    }

    // Set the Netflow version in header (default 9).
    NetflowPacketBuilder &setNetflowVersion(uint16_t version)
    {
        version_ = version;
        return *this;
    }

    // Set the system uptime in header (default 0).
    NetflowPacketBuilder &setSystemUptime(uint32_t uptime)
    {
        uptime_ = uptime;
        return *this;
    }

    // Set the unix timestamp in header (default now).
    NetflowPacketBuilder &setUnixTimestamp(uint32_t timestamp)
    {
        timestamp_ = timestamp;
        return *this;
    }

    // Set the sequence number in header (default 0).
    NetflowPacketBuilder &setSequenceNumber(uint32_t sequence)
    {
        sequence_ = sequence;
        return *this;
    }

    // Set the sourceID in header (default 0).
    NetflowPacketBuilder &setSourceID(uint32_t sourceId)
    {
        sourceId_ = sourceId;
        return *this;
    }

    // Begin a new template flowset with given id.
    NetflowPacketBuilder &addDataTemplateFlowset(uint16_t flowsetId)
    {
        if (flowsetId > 255)
            throw std::invalid_argument("flowsetId must be <= 255");
        records_.push_back(DataTemplateFlowset{flowsetId, {}});
        return *this;
    }

    // Begin a new data template in last flowset.  Fails if
    // ``addDataTemplateFlowset`` was not yet called.
    NetflowPacketBuilder &addDataTemplate(uint16_t templateId)
    {
        if (templateId <= 255)
            throw std::invalid_argument("templateId must be > 255");
        if (records_.empty())
            throw std::runtime_error("no flowsets");

        DataTemplateFlowset &flowset = lastDataTemplateFlowset();
        flowset.templates.push_back(DataTemplate{templateId, {}});
        return *this;
    }

    // Add a field to the latest data template.  Fails if
    // ``addDataTemplate`` was not yet called.
    NetflowPacketBuilder &addDataTemplateField(uint16_t type, uint16_t length)
    {
        if (records_.empty())
            throw std::runtime_error("no flowsets");
        if (lastDataTemplateFlowset().templates.empty())
            throw std::runtime_error("no templates in last flowset");

        DataTemplate &tmpl = lastDataTemplateFlowset().templates.back();
        tmpl.fields.push_back({type, length});
        return *this;
    }

    // Begin a new data flowset with given id.
    NetflowPacketBuilder &addDataFlowset(uint16_t flowsetId)
    {
        records_.push_back(DataFlowset{flowsetId, {}});
        return *this;
    }

    // Add a field to latest data flowset.  Fails if
    // ``addDataFlowset`` was not yet called.
    template <typename T>
    NetflowPacketBuilder &addDataField(T value)
    {
        if (records_.empty())
            throw std::runtime_error("no flowsets");

        Bytes bytes = toBytes(value);
        lastDataFlowset().values.emplace_back(bytes);
        return *this;
    }

    // Begin a new option template with given id.
    NetflowPacketBuilder &addOptionTemplate(uint16_t templateId)
    {
        if (templateId <= 255)
            throw std::invalid_argument("templateId must be > 255");

        records_.push_back(OptionTemplate{templateId, {}, {}});
        return *this;
    }

    // Add a scope field to the latest option template.  Fails if
    // ``addOptionTemplate`` was not yet called.
    NetflowPacketBuilder &addOptionScopeField(uint16_t type, uint16_t length)
    {
        if (type == 0 || type > 5)
            throw std::invalid_argument(
                "scope field type must be > 0 and <= 5");

        OptionTemplate &tmpl = lastOptionTemplate();
        tmpl.scopeFields.push_back({type, length});
        return *this;
    }

    // Add a field to the latest data template.  Fails if
    // ``addDataTemplate`` was not yet called.
    NetflowPacketBuilder &addOptionField(uint16_t type, uint16_t length)
    {
        OptionTemplate &tmpl = lastOptionTemplate();
        tmpl.fields.push_back({type, length});
        return *this;
    }

    // Build the entire packet.
    std::vector<uint8_t> build() const
    {
        Bytes header = buildHeader();
        Bytes records = buildRecords();
        auto packet = header + records;
        return {packet.begin(), packet.end()};
    }

private:
    using Bytes = std::basic_string<uint8_t>;
    using FieldDef = std::pair<uint16_t, uint16_t>;  // Field type, field length

    struct DataTemplate
    {
        uint16_t templateId;
        std::vector<FieldDef> fields;
    };

    struct OptionTemplate
    {
        uint16_t templateId;
        std::vector<FieldDef> scopeFields;
        std::vector<FieldDef> fields;
    };

    struct DataTemplateFlowset
    {
        uint16_t flowsetId;
        std::vector<DataTemplate> templates;
    };

    struct DataFlowset
    {
        uint16_t flowsetId;  // = templateId
        std::vector<Bytes> values;
    };

    using Record =
        std::variant<DataTemplateFlowset, DataFlowset, OptionTemplate>;

    Bytes buildHeader() const
    {
        NetflowHeader hd;
        hd.version = htons(version_);
        hd.count = htons(records_.size());
        hd.uptime = htonl(uptime_);
        hd.timestamp = htonl(timestamp_);
        hd.sequence = htonl(sequence_);
        hd.source_id = htonl(sourceId_);
        return Bytes(reinterpret_cast<const uint8_t *>(&hd),
                     reinterpret_cast<const uint8_t *>(&hd) + sizeof(hd));
    }

    Bytes buildRecords() const
    {
        Bytes ret;
        for (const Record &record : records_) {
            if (record.index() == 0)
                ret += buildDataTemplateFlowset(
                    std::get<DataTemplateFlowset>(record));
            else if (record.index() == 1)
                ret += buildDataFlowset(std::get<DataFlowset>(record));
            else if (record.index() == 2)
                ret += buildOptionTemplate(std::get<OptionTemplate>(record));
        }

        return ret;
    }

    Bytes buildDataTemplateFlowset(const DataTemplateFlowset &tf) const
    {
        Bytes templateBytes;
        for (const DataTemplate &t : tf.templates)
            templateBytes += buildDataTemplate(t);

        return toBytes(htons(tf.flowsetId)) +  // FlowsetID
               toBytes(htons(
                   sizeof(uint16_t) * 2 +
                   templateBytes.size())) +  // Flowset length in
                                             // bytes (including two 2-byte
                                             // fields at beginning)
               templateBytes;
    }

    Bytes buildDataFlowset(const DataFlowset &df) const
    {
        Bytes bytes;
        for (const Bytes &value : df.values)
            bytes += value;

        Bytes paddingBytes = padding(2 * sizeof(uint16_t) + bytes.size());

        return toBytes(htons(df.flowsetId)) +
               toBytes(htons(sizeof(uint16_t) * 2 + bytes.size() +
                             paddingBytes.size())) +
               bytes + paddingBytes;
    }

    Bytes buildDataTemplate(const DataTemplate &t) const
    {
        Bytes ret;
        ret += toBytes(htons(t.templateId));
        ret += toBytes(htons(t.fields.size()));
        for (const auto &fieldDef : t.fields) {
            ret += toBytes(htons(fieldDef.first));
            ret += toBytes(htons(fieldDef.second));
        }

        return ret;
    }

    Bytes buildOptionTemplate(const OptionTemplate &t) const
    {
        Bytes scope;
        Bytes option;

        for (const FieldDef &fd : t.scopeFields) {
            scope += toBytes(htons(fd.first));
            scope += toBytes(htons(fd.second));
        }
        for (const FieldDef &fd : t.fields) {
            option += toBytes(htons(fd.first));
            option += toBytes(htons(fd.second));
        }

        Bytes paddingBytes =
            padding(5 * sizeof(uint16_t) + scope.size() + option.size());

        return toBytes(htons(1))  // FlowsetID = 1 for all option templates
               + toBytes(htons(5 * sizeof(uint16_t) + scope.size() +
                               option.size() + paddingBytes.size())) +
               toBytes(htons(t.templateId)) + toBytes(htons(scope.size())) +
               toBytes(htons(option.size())) + scope + option + paddingBytes;
    }

    // Convert any integer value to bytes.
    template <typename T>
    static Bytes toBytes(T t)
    {
        union {
            T value;
            uint8_t bytes[sizeof(T)];
        } u;
        u.value = t;
        return Bytes(u.bytes, u.bytes + sizeof(T));
    }

    static Bytes padding(size_t record_size)
    {
        size_t padding = sizeof(uint32_t) - (record_size % sizeof(uint32_t));
        return Bytes(padding, 0x0);
    }

    DataTemplateFlowset &lastDataTemplateFlowset()
    {
        return std::get<DataTemplateFlowset>(records_.back());
    }

    DataFlowset &lastDataFlowset()
    {
        return std::get<DataFlowset>(records_.back());
    }

    OptionTemplate &lastOptionTemplate()
    {
        return std::get<OptionTemplate>(records_.back());
    }

    uint16_t version_ = 9;
    uint32_t uptime_ = 0;
    uint32_t timestamp_;
    uint32_t sequence_ = 0;
    uint32_t sourceId_ = 0;
    std::vector<Record> records_;
};

#endif
