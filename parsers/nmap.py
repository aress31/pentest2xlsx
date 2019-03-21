#!/usr/bin/env python3
#    Copyright (C) 2019 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

# TODO:
# * add a "Service vs Hosts" worksheet
# * improve the logic - replace dict with list

from .parser import Parser
from libnmap.parser import NmapParser
from pathlib import Path

import logging
import xlsxwriter


class Nmap(Parser):
    def __init__(self, input_files, output_file):
        super(Nmap, self).__init__(input_files, output_file)

    def print_vars(self):
        logging.info("input file(s): {}".format(
            sorted([x.name for x in self._input_files])))
        logging.info("output file: {}".format(self._output_file))

    def parse(self):
        logging.info("generating worksheet 'Host vs Service'...")
        self.parse_host_service()
        logging.info("generating worksheet 'Host vs OS'...")
        self.parse_host_os()
        logging.info("generating worksheet 'OS vs Hosts'...")
        self.parse_os_hosts()

        try:
            self._workbook.close()
        except Exception as e:
            logging.exception("{}".format(e))

    def parse_host_service(self):
        table_data = []
        table_headers = [
            {"header": "File"},
            {"header": "Host IP"},
            {"header": "Port"},
            {"header": "Protocol"},
            {"header": "Service"},
            {"header": "State"},
            {"header": "Banner"},
            {"header": "Reason"}
        ]

        for input_file in self._input_files:
            host_services = get_host_services(input_file)

            for values in host_services:
                for service in values["services"]:
                    table_data.append(
                        [
                            values["filepath"],
                            values["host_ip"],
                            service["port"],
                            service["protocol"],
                            service["service"],
                            service["state"],
                            service["banner"],
                            service["reason"]
                        ]
                    )

        worksheet = self._workbook.add_worksheet("Host vs Service")
        self.draw_table(worksheet, table_headers, table_data)

    def parse_host_os(self):
        table_data = []
        table_headers = [
            {"header": "File"},
            {"header": "Host IP"},
            {"header": "Operating System"},
            {"header": "Accuracy"}
        ]

        for input_file in self._input_files:
            host_os = get_host_os(input_file)

            for values in host_os:
                table_data.append(
                    [
                        values["filepath"],
                        values["host_ip"],
                        values["os"],
                        values["accuracy"]
                    ]
                )

        worksheet = self._workbook.add_worksheet("Host vs OS")
        self.draw_table(worksheet, table_headers, table_data)

    def parse_os_hosts(self):
        table_data = []
        table_headers = [
            {"header": "File"},
            {"header": "Operating System"},
            {"header": "Host IP Count"},
            {"header": "Host IP"}
        ]

        for input_file in self._input_files:
            host_os = get_os_hosts(input_file)

            for os, values in host_os.items():
                table_data.append(
                    [
                        values["filepath"],
                        os,
                        len(set(values["host_ip"])),
                        ";".join(sorted(
                            set(values["host_ip"]),
                            key=lambda x: tuple(map(int, x.split('.')))
                        ))
                    ]
                )

        worksheet = self._workbook.add_worksheet("OS vs Hosts")
        self.draw_table(worksheet, table_headers, table_data)


def get_host_services(file):
    results = []

    nmap = NmapParser.parse_fromfile(file.name)

    for host in nmap.hosts:
        if host.is_up() and host.get_ports():
            services = []

            for port in host.get_ports():
                service = host.get_service(port[0], port[1])
                services.append(
                    {
                        "port": service.port,
                        "protocol": service.protocol,
                        "service": service.service,
                        "state": service.state,
                        "banner": service.banner,
                        "reason": service.reason
                    }
                )

            results.append(
                {
                    "filepath": Path(file.name).resolve().as_posix(),
                    "host_ip": host.address,
                    "services": services
                }
            )

    return results


def get_host_os(file):
    results = []

    nmap = NmapParser.parse_fromfile(file.name)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            os_match_probabilities = host.os_match_probabilities()

            # first match has the highest accuracy -
            # rework this to make sure to get highest prob
            if os_match_probabilities:
                results.append(
                    {
                        "filepath": Path(file.name).resolve().as_posix(),
                        "host_ip": host.address,
                        "os": os_match_probabilities[0].name,
                        "accuracy": os_match_probabilities[0].accuracy
                    }
                )
        elif not host.os_fingerprinted:
            logging.debug(
                "OS fingerprinting has not been performed for {}".
                format(host.address)
            )

    return results


def get_os_hosts(file):
    results = {}

    nmap = NmapParser.parse_fromfile(file.name)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            os_match_probabilities = host.os_match_probabilities()

            if os_match_probabilities:
                # first match has the highest accuracy
                if os_match_probabilities[0].name in list(results.keys()):
                    results[os_match_probabilities[0].name]["host_ip"].append(
                        host.address
                    )
                else:
                    results[os_match_probabilities[0].name] = {
                        "filepath": Path(file.name).resolve().as_posix(),
                        "host_ip": [host.address]
                    }
        elif not host.os_fingerprinted:
            logging.debug(
                "OS fingerprinting has not been performed for {}".
                format(host.address)
            )

    return results
