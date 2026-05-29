// name: network_interfaces_ioctl
// title: Enumerate network interfaces with IOCTLs
// description: Lists Linux network interfaces from /proc/net/dev and queries ifreq fields with SIOCGIF* ioctls.
// tags: network, ioctl, ifreq

function encodeNameHex(name, length) {
  let hex = "";
  for (let i = 0; i < length; i++) {
    const value = i < name.length ? name.charCodeAt(i) : 0;
    hex += value.toString(16).padStart(2, "0");
  }
  return hex;
}

function readByte(hex, offset) {
  return parseInt(hex.substr(offset * 2, 2), 16);
}

function readU16LE(hex, offset) {
  return readByte(hex, offset) | (readByte(hex, offset + 1) << 8);
}

function readU32LE(hex, offset) {
  return readByte(hex, offset) +
    (readByte(hex, offset + 1) << 8) +
    (readByte(hex, offset + 2) << 16) +
    (readByte(hex, offset + 3) * 0x1000000);
}

const SIOCGIFFLAGS = 0x8913;
const SIOCGIFADDR = 0x8915;
const SIOCGIFNETMASK = 0x891b;
const SIOCGIFHWADDR = 0x8927;
const SIOCGIFMTU = 0x8921;
const SIOCGIFINDEX = 0x8933;

const IFF = {
  UP: 0x1,
  BROADCAST: 0x2,
  LOOPBACK: 0x8,
  POINTOPOINT: 0x10,
  RUNNING: 0x40,
  PROMISC: 0x100,
  MULTICAST: 0x1000,
};

const socket = sys.socket({domain: "AF_INET", type: "SOCK_DGRAM", protocol: 0, handle: "netprobe"});
if (!socket.ok) {
  return {error: "socket failed", detail: socket};
}

let procNetDevOpen = false;
let ifreqAllocated = false;

try {
  const procNetDev = sys.open({path: "/proc/net/dev", flags: "O_RDONLY|O_CLOEXEC", handle: "procnetdev"});
  if (!procNetDev.ok) {
    return {error: "open /proc/net/dev failed", detail: procNetDev};
  }
  procNetDevOpen = true;

  const content = sys.read({handle: "procnetdev", length: 65536, encoding: "utf8"});
  if (!content.ok) {
    return {error: "read /proc/net/dev failed", detail: content};
  }

  const interfaces = content.data_utf8.split("\n").slice(2)
    .map(line => line.trim().split(":")[0].trim())
    .filter(Boolean);

  const alloc = sys.bufferAlloc({name: "ifreq", size: 40, replace_existing: true});
  if (!alloc.ok) {
    return {error: "buffer allocation failed", detail: alloc};
  }
  ifreqAllocated = true;

  function ioctlIfreq(name, request) {
    const ifreqHex = encodeNameHex(name, 16) + "00".repeat(24);
    sys.bufferWrite({name: "ifreq", data_hex: ifreqHex});
    const ioctl = sys.ioctl({handle: "netprobe", request, buffer: "ifreq", buffer_length: 40});
    if (!ioctl.ok) {
      return null;
    }
    return sys.bufferRead({name: "ifreq", length: 40, encoding: "hex"}).data_hex;
  }

  const results = [];
  for (const name of interfaces) {
    const entry = {name};

    let data = ioctlIfreq(name, SIOCGIFINDEX);
    if (data) {
      entry.index = readU32LE(data, 16);
    }

    data = ioctlIfreq(name, SIOCGIFFLAGS);
    if (data) {
      const flags = readU16LE(data, 16);
      entry.flags = Object.entries(IFF).filter(([, value]) => flags & value).map(([key]) => key);
      entry.raw_flags = "0x" + flags.toString(16);
    }

    data = ioctlIfreq(name, SIOCGIFADDR);
    if (data && readU16LE(data, 16) === 2) {
      entry.ipv4 = [20, 21, 22, 23].map(offset => readByte(data, offset)).join(".");
    }

    data = ioctlIfreq(name, SIOCGIFNETMASK);
    if (data && readU16LE(data, 16) === 2) {
      entry.netmask = [20, 21, 22, 23].map(offset => readByte(data, offset)).join(".");
    }

    data = ioctlIfreq(name, SIOCGIFHWADDR);
    if (data) {
      entry.mac = [0, 1, 2, 3, 4, 5].map(offset => data.substr((18 + offset) * 2, 2)).join(":");
    }

    data = ioctlIfreq(name, SIOCGIFMTU);
    if (data) {
      entry.mtu = readU32LE(data, 16);
    }

    results.push(entry);
  }

  return results;
} finally {
  if (procNetDevOpen) {
    sys.close({handle: "procnetdev"});
  }
  if (ifreqAllocated) {
    sys.bufferFree({name: "ifreq"});
  }
  sys.close({handle: "netprobe"});
}