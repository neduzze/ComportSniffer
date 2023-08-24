from dataclasses import dataclass
from enum import Enum, auto
import serial
import time
import argparse


@dataclass
class ComConfig:    
    com_pc: int
    com_dev: int
    baudrate_pc = 9600
    baudrate_dev = 9600
    max_delay: float = 5e-3  # seconds

class Direction(Enum):
    Rx = auto()
    Tx = auto()

@dataclass
class ArgParser:
    com_config: ComConfig

    def get_args(self) -> ComConfig:
        parser = argparse.ArgumentParser(
            description="ComPort Sniffing Tool to intercept traffic in the comport",
            prog="Serial Port Sniffer",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )

        parser.add_argument(
            "-p",
            "--pc-com",
            metavar="<int>",
            dest="com_pc",
            type=int,
            default=self.com_config.com_pc,
            help="PC Comport",
        )

        parser.add_argument(
            "-d",
            "--device-com",
            metavar="<int>",
            dest="com_dev",
            type=int,
            default=self.com_config.com_dev,
            help="Device Comport",
        )

        parser.add_argument(
            "-s",
            "--pc-baudrate",
            metavar="<int>",
            dest="baudrate_pc",
            type=int,
            default=self.com_config.baudrate_pc,
            help="PC Baudrate Value",
        )

        parser.add_argument(
            "-t",
            "--dev-baudrate",
            metavar="<int>",
            dest="baudrate_dev",
            type=int,
            default=self.com_config.baudrate_dev,
            help="Device Baudrate Value",
        )

        parser.add_argument(
            "-m",
            "--max-delay",
            metavar="<float>",
            dest="max_delay",
            type=float,
            default=self.com_config.max_delay,
            help="Delay in seconds. Maximum allowed time between packets",
        )

        args = parser.parse_args()

        self.com_config.com_pc = args.com_pc
        self.com_config.com_dev = args.com_dev
        self.com_config.baudrate_pc = args.baudrate_pc
        self.com_config.baudrate_dev = args.baudrate_dev
        self.com_config.max_delay = args.max_delay

        return self.com_config



def print_cmd(cmd: list[int]) -> str:
    out_str = ""
    max_len = 16
    for c, v in enumerate(cmd):
        if 0 == c % max_len and 0 < c:
            out_str += f"\n"
        out_str += f"{v:02X} "
    return out_str


def print_data(data: bytearray, direction: Direction):
    arr = list(data)
    if Direction.Rx == direction:
        print(f"{' 🟢 RESPONSE 🟢 ':<^78} ")
        print(print_cmd(arr))
        print("#"*80)
    elif Direction.Tx == direction:
        
        print(f"\n{' PACKET ':#^80}")
        print(f"{' 🔴 REQUEST 🔴 ':>^78} ")
        print(print_cmd(arr))

    else:
        raise Exception("Wrong Direction Data Received!")
@dataclass
class Sniffer:
    com_config:ComConfig
    last_rx_time: float = 0
    last_tx_time: float = 0

    def __post_init__(self):
        arg_parser = ArgParser(self.com_config)
        self.com_configv = arg_parser.get_args()
        self.max_delay = self.com_config.max_delay 
        self.pc_port = serial.Serial(f"COM{self.com_config.com_pc}", self.com_config.baudrate_pc)
        self.dev_port = serial.Serial(f"COM{self.com_config.com_dev}", self.com_config.baudrate_dev)
        self.rx_data = bytearray()
        self.tx_data = bytearray()
        self.new_rx = False
        self.new_tx = False

    def start_tx_time(self):
        self.last_tx_time = time.perf_counter()

    def start_rx_time(self):
        self.last_rx_time = time.perf_counter()

    def check_tx_time(self) -> bool:
        curr_time = time.perf_counter() - self.last_tx_time
        return curr_time > self.max_delay

    def check_rx_time(self) -> bool:
        curr_time = time.perf_counter() - self.last_rx_time
        return curr_time > self.max_delay

    def sniff_port(self):
        From_PC_To_Device = True
        rx_counter = 0
        tx_counter = 0
        try:
            while 1:
                while self.pc_port.in_waiting and From_PC_To_Device:
                    self.start_rx_time()
                    self.new_rx = True
                    serial_out = self.pc_port.read(size=1)

                    self.rx_data.extend(serial_out)
                    self.dev_port.write(serial_out)
                    rx_counter = 0
                else:
                    if self.new_rx:
                        rx_counter += 1
                    if self.new_rx and self.check_rx_time():
                        print_data(self.rx_data, Direction.Rx)
                        self.new_rx = False
                        self.rx_data.clear()
                        rx_counter = 0

                    From_PC_To_Device = False

                while self.dev_port.in_waiting and not From_PC_To_Device:
                    self.start_tx_time()
                    self.new_tx = True
                    serial_out = self.dev_port.read(size=1)
                    self.tx_data.extend(serial_out)
                    # print(serial_out.decode(), end="") #or write it to a file
                    self.pc_port.write(serial_out)
                    # print(tx_data)

                else:
                    if self.new_tx:
                        tx_counter += 1
                    if self.new_tx and self.check_tx_time():
                        print_data(self.tx_data, Direction.Tx)
                        self.new_tx = False
                        self.tx_data.clear()
                        tx_counter = 0

                    From_PC_To_Device = True

        finally:
            self.pc_port.close()
            self.dev_port.close()


if __name__ == "__main__":
    com_config=ComConfig(12,25)
    sniffer = Sniffer(com_config)
    sniffer.sniff_port()
    # TODO: Dump Data to some kind of database
