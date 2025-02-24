# DNS Server System

## Overview

The DNS Server System is an implementation of a hierarchical Domain Name System (DNS) architecture consisting of:

A DNS Resolver

A Root Server

A Top-Level Domain (TLD) Server

An Authoritative Server

This project follows the iterative DNS query resolution process and adheres to RFC 1034, RFC 1035, and RFC 2181 standards. It is implemented using Python and communicates via the User Datagram Protocol (UDP).

## Features

Iterative Query Resolution: The resolver queries the hierarchy (Root, TLD, and Authoritative servers) to resolve domain names.

Supports Various DNS Records: Handles A, AAAA, MX, CNAME, TXT, SOA, and SRV record types.

Error Handling: Implements proper response codes (e.g., NXDOMAIN, SERVFAIL, NOTIMP).

Multi-threaded Design: Each server operates concurrently for efficient request handling.

Logging and Debugging: Tracks query processing and errors for easy debugging.

## System Architecture

Client Query → Sent to DNS Resolver

Resolver to Root Server → Root Server provides TLD server info

Resolver to TLD Server → TLD Server provides authoritative server info

Resolver to Authoritative Server → Retrieves final answer

Response sent back to client

## Installation & Setup

### Prerequisites:

Python (Ensure Python 3.x is installed)

Required modules: socket, threading, logging, ipaddress

### Installation Steps:

Clone this repository:

git clone https://github.com/your-repo/dns-server-system.git
cd dns-server-system

Run each server in a separate terminal:

python resolver.py
python root_server.py
python tld_server.py
python authoritative_server.py

## Configuration

The servers are set to run on localhost (127.0.0.1) by default.

To allow communication across a network, update the server binding IPs:

Use 0.0.0.0 (all interfaces) or a specific LAN IP (e.g., 192.168.x.x).

Modify database entries in each server file to add/remove domain records.

## Usage

Sending DNS Queries

You can use nslookup or dig to test queries:

### Using nslookup:

nslookup example.com 127.0.0.1

### Using dig:

dig example.com @127.0.0.1

### Example Queries

A Record:

nslookup -type=A example.com 127.0.0.1

CNAME Record:

nslookup -type=CNAME google.com 127.0.0.1

MX Record:

nslookup -type=MX example.org 127.0.0.1

## Testing

The system has been tested for:

Valid domain resolution (example.com, example.org)

Non-existent domains returning NXDOMAIN

Unsupported query types returning NOTIMP

Large query loads handled via threading

## References

RFC 1034 - DNS Concepts and Facilities

RFC 1035 - DNS Implementation and Specification

GeeksforGeeks - DNS Basics
