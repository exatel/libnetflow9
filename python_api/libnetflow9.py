import numpy as np
import ctypes
from enum import IntEnum
from nf9_ctypes import *


class NF9Error(Exception):
    """
    Basic LibNetflow9 exception
    """


class NF9InvalidArgumentError(NF9Error):
    """
    Exception raised after passing invalid argument
    """


class NF9NotFoundError(NF9Error):
    """
    Exception raised when field cannot be found
    """


class NF9OutOfMemoryError(NF9Error):
    """
    Exception raised after reaching the limit of used memory
    """


class NF9MalformedError(NF9Error):
    """
    Exception raised when processed packet is malformed
    """


class NF9OutdatedError(NF9Error):
    """
    Exception raised after receiving a template that is older than previous one
    """


class NF9Opt(IntEnum):
    """
    Flags describing options of a NetFlow decoder
    """
    NF9_OPT_MAX_MEM_USAGE = 0
    NF9_OPT_TEMPLATE_EXPIRE_TIME = 1
    NF9_OPT_OPTION_EXPIRE_TIME = 2


class NF9FlowsetType(IntEnum):
    """
    Class describing possible types of NetFlow flowset
    """
    NF9_FLOWSET_TEMPLATE = 0
    NF9_FLOWSET_OPTIONS = 1
    NF9_FLOWSET_DATA = 2


def strerror(error_code):
    """
    Get an error message for an error code.
    """
    error_name = c_nf9_strerror(error_code)
    return error_name.decode("utf-8")


def error_code_to_exception(error_code):
    """
    Return exception that matches given error code
    """
    if error_code == 1:
        return NF9InvalidArgumentError(strerror(error_code))
    if error_code == 2:
        return NF9NotFoundError(strerror(error_code))
    if error_code == 3:
        return NF9OutOfMemoryError(strerror(error_code))
    if error_code == 4:
        return NF9MalformedError(strerror(error_code))
    if error_code == 5:
        return NF9OutdatedError(strerror(error_code))

    return NF9Error("unknown error")


class NF9Packet:
    """
    Class that represents NetFlow9 packet
    """

    def __init__(self, c_nf9_pkt):
        self.c_nf9_pkt = c_nf9_pkt

    def __del__(self):
        c_nf9_free_packet(self.c_nf9_pkt)

    def get_num_flowsets(self):
        """
        Get the number of flowsets in a NetFlow packet.
        """
        return c_nf9_get_num_flowsets(self.c_nf9_pkt)

    def get_timestamp(self):
        """
        Get the UNIX timestamp from a NetFlow packet.
        """
        return c_nf9_get_timestamp(self.c_nf9_pkt)

    def get_uptime(self):
        """
        Get the system uptime in milliseconds from a NetFlow packet.
        """
        return c_nf9_get_uptime(self.c_nf9_pkt)

    def get_flowset_type(self, flowset):
        """
        Get the type of flowset in a NetFlow packet.
        """
        return NF9FlowsetType(c_nf9_get_flowset_type(self.c_nf9_pkt, flowset))

    def get_num_flows(self, flowset):
        """
        Get the number of flows in a specific flowset in a NetFlow packet.
        """
        return c_nf9_get_num_flows(self.c_nf9_pkt, flowset)

    def get_field(self, flowset, flow, field, bytes_limit=1000):
        """
        Get the value of a field from a NetFlow data record.
        """
        arr = np.empty(bytes_limit, np.uint8)
        length = ctypes.c_size_t(arr.size)
        err = c_nf9_get_field(self.c_nf9_pkt, flowset, flow, field,
                              arr.ctypes.data_as(ctypes.c_void_p), length)
        if err:
            raise error_code_to_exception(err)

        return bytes(arr[:length.value])

    def get_all_fields(self, flowset, flow, fields_nb_limit=300):
        """
        Get the values of all fields from a NetFlow data record.
        """
        size = ctypes.c_size_t(fields_nb_limit)
        arr = (ctypes.POINTER(nf9_fieldval) * size.value)()
        arr = ctypes.cast(arr, ctypes.POINTER(nf9_fieldval))

        err = c_nf9_get_all_fields(self.c_nf9_pkt, flowset, flow,
                                   arr, size)
        if err:
            raise error_code_to_exception(err)

        result = []
        i = 0
        for fieldval in arr:
            if i >= size.value:
                break
            i += 1
            result.append((fieldval.field, fieldval.value))

        return result

    def get_option(self, field, bytes_limit=1000):
        """
        Get the value of an option from a NetFlow packet.
        """
        arr = np.empty(bytes_limit, np.uint8)
        length = ctypes.c_size_t(arr.size)
        err = c_nf9_get_option(self.c_nf9_pkt, field, arr.ctypes.data_as(ctypes.c_void_p),
                               length)
        if err:
            error_code_to_exception(err)

        return bytes(arr[:length.value])

    def get_sampling_rate(self, flowset, flownum):
        """
        Get the sampling rate used for a flow within a NetFlow packet.
        """
        sampling = ctypes.c_uint32()
        err = c_nf9_get_sampling_rate(self.c_nf9_pkt, flowset, flownum, sampling)
        if err:
            raise error_code_to_exception(err)

        return sampling


class LibNetflow9:
    """
    A class that gives access to libnetflow9 - a library for decoding packets conforming
    to the NetFlow9 format in order to extract meta information about the traffic.
    """

    def __init__(self, flags=0):
        """
        Create a NetFlow9 decoder (state) object.
        """
        self.state = c_nf9_init(flags)

    def __del__(self):
        """
        Free the state and object.
        """
        c_nf9_free(self.state)

    def decode(self, pkt):
        """
        Decode a NetFlow9 packet.
        """
        c_nf9_pkt = ctypes.POINTER(nf9_packet)()
        addr = nf9_addr()
        pkt_ptr = ctypes.c_char_p(pkt)
        size = ctypes.c_size_t(len(pkt))

        err = c_nf9_decode(self.state, ctypes.byref(c_nf9_pkt), pkt_ptr, size,
                           ctypes.byref(addr))
        if err:
            raise error_code_to_exception(err)
        return NF9Packet(c_nf9_pkt)

    def get_stats(self):
        """
        Get all statistics.
        """
        stats = c_nf9_get_stats(self.state)

        result = {
            "processed": c_nf9_get_stat(stats, 0),
            "malformed": c_nf9_get_stat(stats, 1),
            "records": c_nf9_get_stat(stats, 2),
            "templates": c_nf9_get_stat(stats, 3),
            "option_templates": c_nf9_get_stat(stats, 4),
            "missing_templates": c_nf9_get_stat(stats, 5),
            "expired_objects": c_nf9_get_stat(stats, 6),
            "memory_usage": c_nf9_get_stat(stats, 7)
        }

        c_nf9_free_stats(stats)
        return result

    def ctl(self, opt, value):
        """
        Set NetFlow9 decoder options.
        """
        err = c_nf9_ctl(self.state, opt, value)
        if err:
            raise error_code_to_exception(err)
