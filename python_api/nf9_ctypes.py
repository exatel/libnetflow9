import ctypes
from pathlib import Path
import os


class nf9_state(ctypes.Structure):
    _fields_ = []


class nf9_addr(ctypes.Union):
    _fields_ = []


class nf9_stats(ctypes.Structure):
    _fields_ = []


class nf9_packet(ctypes.Structure):
    _fields_ = []


class nf9_fieldval(ctypes.Structure):
    _fields_ = [
        ("field", ctypes.c_uint32),
        ("size", ctypes.c_size_t),
        ("value", ctypes.c_char_p)
    ]


lib_path = os.environ.get("LD_LIBRARY_PATH")
if lib_path:
    lib_path = os.path.join(lib_path, "libnetflow9.so")
else:
    ROOT = Path(__file__).parent.parent
    lib_path = os.path.join(ROOT, "build", "libnetflow9.so")

lib = ctypes.CDLL(lib_path)

c_nf9_init = lib.nf9_init
c_nf9_init.argtypes = [ctypes.c_int]
c_nf9_init.restype = ctypes.POINTER(nf9_state)

c_nf9_free = lib.nf9_free
c_nf9_free.argtypes = [ctypes.POINTER(nf9_state)]
c_nf9_free.restype = None

c_nf9_decode = lib.nf9_decode
c_nf9_decode.argtypes = [ctypes.POINTER(nf9_state), ctypes.POINTER(ctypes.POINTER(nf9_packet)),
                         ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(nf9_addr)]
c_nf9_decode.restype = ctypes.c_int

c_nf9_strerror = lib.nf9_strerror
c_nf9_strerror.argtypes = [ctypes.c_int]
c_nf9_strerror.restype = ctypes.c_char_p

c_nf9_free_packet = lib.nf9_free_packet
c_nf9_free_packet.argtypes = [ctypes.POINTER(nf9_packet)]
c_nf9_free_packet.restype = None

c_nf9_get_num_flowsets = lib.nf9_get_num_flowsets
c_nf9_get_num_flowsets.argtypes = [ctypes.POINTER(nf9_packet)]
c_nf9_get_num_flowsets.restype = ctypes.c_size_t

c_nf9_get_timestamp = lib.nf9_get_timestamp
c_nf9_get_timestamp.argtypes = [ctypes.POINTER(nf9_packet)]
c_nf9_get_timestamp.restype = ctypes.c_uint32

c_nf9_get_uptime = lib.nf9_get_uptime
c_nf9_get_uptime.argtypes = [ctypes.POINTER(nf9_packet)]
c_nf9_get_uptime.restype = ctypes.c_uint32

c_nf9_get_flowset_type = lib.nf9_get_flowset_type
c_nf9_get_flowset_type.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint]
c_nf9_get_flowset_type.restype = ctypes.c_int

c_nf9_get_num_flows = lib.nf9_get_num_flows
c_nf9_get_num_flows.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint]
c_nf9_get_num_flows.restype = ctypes.c_size_t

c_nf9_get_field = lib.nf9_get_field
c_nf9_get_field.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint, ctypes.c_uint,
                            ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
c_nf9_get_field.restype = ctypes.c_int

c_nf9_get_all_fields = lib.nf9_get_all_fields
c_nf9_get_all_fields.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint, ctypes.c_uint,
                                 ctypes.POINTER(nf9_fieldval), ctypes.POINTER(ctypes.c_size_t)]
c_nf9_get_all_fields.restype = ctypes.c_int

c_nf9_get_option = lib.nf9_get_option
c_nf9_get_option.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint32, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_size_t)]
c_nf9_get_option.restype = ctypes.c_int

c_nf9_get_sampling_rate = lib.nf9_get_sampling_rate
c_nf9_get_sampling_rate.argtypes = [ctypes.POINTER(nf9_packet), ctypes.c_uint, ctypes.c_uint,
                                    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int)]
c_nf9_get_sampling_rate.restype = ctypes.c_int

c_nf9_get_stats = lib.nf9_get_stats
c_nf9_get_stats.argtypes = [ctypes.POINTER(nf9_state)]
c_nf9_get_stats.restype = ctypes.POINTER(nf9_stats)

c_nf9_get_stat = lib.nf9_get_stat
c_nf9_get_stat.argtypes = [ctypes.POINTER(nf9_stats), ctypes.c_int]
c_nf9_get_stat.restype = ctypes.c_uint64

c_nf9_free_stats = lib.nf9_free_stats
c_nf9_free_stats.argtypes = [ctypes.POINTER(nf9_stats)]
c_nf9_free_stats.restype = None

c_nf9_ctl = lib.nf9_ctl
c_nf9_ctl.argtypes = [ctypes.POINTER(nf9_state), ctypes.c_int, ctypes.c_long]
c_nf9_ctl.restype = ctypes.c_int
