/* source: xio-tun.c */
/* Copyright Gerhard Rieger and contributors (see file CHANGES) */
/* Published under the GNU General Public License V.2, see file COPYING */

/* this file contains the source for opening addresses of tun/tap type */

#include "xiosysincludes.h"
#if WITH_TUN
#include "xioopen.h"

#include "xio-named.h"
#include "xio-socket.h"
#include "xio-ip.h"

#include "xio-tun.h"


static int xioopen_tun(int argc, const char *argv[], struct opt *opts, int xioflags, xiofile_t *fd, unsigned groups, int dummy1, int dummy2, int dummy3);

/****** TUN addresses ******/
const struct optdesc opt_tun_device    = { "tun-device",     NULL,      OPT_TUN_DEVICE,      GROUP_TUN,       PH_OPEN, TYPE_FILENAME, OFUNC_SPEC };
const struct optdesc opt_tun_name      = { "tun-name",       NULL,      OPT_TUN_NAME,        GROUP_INTERFACE, PH_FD,   TYPE_STRING,   OFUNC_SPEC };
const struct optdesc opt_tun_type      = { "tun-type",       NULL,      OPT_TUN_TYPE,        GROUP_INTERFACE, PH_FD,   TYPE_STRING,   OFUNC_SPEC };
const struct optdesc opt_iff_no_pi     = { "iff-no-pi",       "no-pi",       OPT_IFF_NO_PI,         GROUP_TUN,       PH_FD,   TYPE_BOOL,   OFUNC_SPEC };
const struct optdesc opt_iff_slip      = { "iff-slip",        "slip",        OPT_IFF_SLIP,          GROUP_TUN,       PH_FD,   TYPE_BOOL,   OFUNC_SPEC };
/*0 const struct optdesc opt_interface_addr    = { "interface-addr",    "address", OPT_INTERFACE_ADDR,    GROUP_INTERFACE, PH_FD, TYPE_STRING,   OFUNC_SPEC };*/
/*0 const struct optdesc opt_interface_netmask = { "interface-netmask", "netmask", OPT_INTERFACE_NETMASK, GROUP_INTERFACE, PH_FD, TYPE_STRING,   OFUNC_SPEC };*/
const struct optdesc opt_iff_up          = { "iff-up",          "up",          OPT_IFF_UP,          GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_UP };
const struct optdesc opt_iff_broadcast   = { "iff-broadcast",   NULL,          OPT_IFF_BROADCAST,   GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_BROADCAST };
const struct optdesc opt_iff_debug       = { "iff-debug"    ,   NULL,          OPT_IFF_DEBUG,       GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_DEBUG };
const struct optdesc opt_iff_loopback    = { "iff-loopback" ,   "loopback",    OPT_IFF_LOOPBACK,    GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_LOOPBACK };
const struct optdesc opt_iff_pointopoint = { "iff-pointopoint", "pointopoint",OPT_IFF_POINTOPOINT, GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_POINTOPOINT };
const struct optdesc opt_iff_notrailers  = { "iff-notrailers",  "notrailers",  OPT_IFF_NOTRAILERS,  GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_NOTRAILERS };
const struct optdesc opt_iff_running     = { "iff-running",     "running",     OPT_IFF_RUNNING,     GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_RUNNING };
const struct optdesc opt_iff_noarp       = { "iff-noarp",       "noarp",       OPT_IFF_NOARP,       GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_NOARP };
const struct optdesc opt_iff_promisc     = { "iff-promisc",     "promisc",     OPT_IFF_PROMISC,     GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_PROMISC };
const struct optdesc opt_iff_allmulti    = { "iff-allmulti",    "allmulti",    OPT_IFF_ALLMULTI,    GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_ALLMULTI };
const struct optdesc opt_iff_master      = { "iff-master",      "master",      OPT_IFF_MASTER,      GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_MASTER };
const struct optdesc opt_iff_slave       = { "iff-slave",       "slave",       OPT_IFF_SLAVE,       GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_SLAVE };
const struct optdesc opt_iff_multicast   = { "iff-multicast",   NULL,          OPT_IFF_MULTICAST,   GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_MULTICAST };
const struct optdesc opt_iff_portsel     = { "iff-portsel",     "portsel",     OPT_IFF_PORTSEL,     GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_PORTSEL };
const struct optdesc opt_iff_automedia   = { "iff-automedia",   "automedia",   OPT_IFF_AUTOMEDIA,   GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(para.tun.iff_opts), IFF_AUTOMEDIA };
/*const struct optdesc opt_iff_dynamic   = { "iff-dynamic",     "dynamic",     OPT_IFF_DYNAMIC,     GROUP_INTERFACE, PH_FD,   TYPE_BOOL,     OFUNC_OFFSET_MASKS, XIO_OFFSETOF(para.tun.iff_opts), XIO_SIZEOF(short), IFF_DYNAMIC };*/
#if LATER
const struct optdesc opt_route           = { "route",           NULL,          OPT_ROUTE,           GROUP_INTERFACE, PH_INIT, TYPE_STRING,   OFUNC_SPEC };
#endif

const struct addrdesc xioaddr_tun    = { "tun",    3, xioopen_tun, GROUP_FD|GROUP_CHR|GROUP_NAMED|GROUP_OPEN|GROUP_TUN, 0, 0, 0 HELP("[:<ip-addr>/<bits>]") };
/* "if-name"=tun3
// "route"=address/netmask
// "ip6-route"=address/netmask
// "iff-broadcast"
// "iff-debug"
// "iff-promisc"
// see .../linux/if.h
*/


#if LATER
/* sub options for route option */
#define IFOPT_ROUTE 1
static const struct optdesc opt_route_tos = { "route", NULL, IFOPT_ROUTE, };
static const struct optname xio_route_options[] = {
   {"tos", &xio_route_tos }
} ;
#endif

static int xioopen_tun(int argc, const char *argv[], struct opt *opts, int xioflags, xiofile_t *xfd, unsigned groups, int dummy1, int dummy2, int dummy3) {
   char *tundevice = NULL;
   char *tunname = NULL, *tuntype = NULL;
   int pf = /*! PF_UNSPEC*/ PF_INET;
   struct xiorange network;
   bool no_pi = false;
   bool slip = false;
   const char *namedargv[] = { "tun", NULL, NULL };
   int rw = (xioflags & XIO_ACCMODE);
   bool exists;
   struct ifreq ifr;
   int sockfd;
   char *ifaddr;
   int result;

   if (argc > 2 || argc < 0) {
      Error2("%s: wrong number of parameters (%d instead of 0 or 1)",
	     argv[0], argc-1);
   }

   if (retropt_string(opts, OPT_TUN_DEVICE, &tundevice) != 0) {
      tundevice = strdup("/dev/net/tun");
   }

   /*! socket option here? */
   retropt_socket_pf(opts, &pf);

   namedargv[1] = tundevice;
   /* open the tun cloning device */
   if ((result = _xioopen_named_early(2, namedargv, xfd, groups, &exists, opts)) < 0) {
      return result;
   }

   /*========================= the tunnel interface =========================*/
   Notice("creating tunnel network interface");
   if ((result = _xioopen_open(tundevice, rw, opts)) < 0)
      return result;
   xfd->stream.fd = result;
   xfd->stream.dtype = XIODATA_TUN;

   /* prepare configuration of the new network interface */
   memset(&ifr, 0,sizeof(ifr));

   if (retropt_string(opts, OPT_TUN_NAME, &tunname) == 0) {
      strncpy(ifr.ifr_name, tunname, IFNAMSIZ);	/* ok */
      free(tunname);
   } else {
      ifr.ifr_name[0] = '\0';
   }

   ifr.ifr_flags = IFF_TUN;
   xfd->stream.para.tun.tuntype = XIOTUNTYPE_TUN;
   if (retropt_string(opts, OPT_TUN_TYPE, &tuntype) == 0) {
      if (!strcmp(tuntype, "tap")) {
	 ifr.ifr_flags = IFF_TAP;
         xfd->stream.para.tun.tuntype = XIOTUNTYPE_TAP;
      } else if (strcmp(tuntype, "tun")) {
	 Error1("unknown tun-type \"%s\"", tuntype);
      }
   }

   if (retropt_bool(opts, OPT_IFF_NO_PI, &no_pi) == 0) {
      xfd->stream.para.tun.no_pi = no_pi;
      if (no_pi) {
	 ifr.ifr_flags |= IFF_NO_PI;
#if 0 /* not neccessary for now */
      } else {
	 ifr.ifr_flags &= ~IFF_NO_PI;
#endif
      }
   }

   if (retropt_bool(opts, OPT_IFF_SLIP, &slip) == 0) {
      xfd->stream.para.tun.slip = slip;
   }

   if (Ioctl(xfd->stream.fd, TUNSETIFF, &ifr) < 0) {
      Error3("ioctl(%d, TUNSETIFF, {\"%s\"}: %s",
	     xfd->stream.fd, ifr.ifr_name, strerror(errno));
      Close(xfd->stream.fd);
   }

   /*===================== setting interface properties =====================*/

   /* we seem to need a socket for manipulating the interface */
   if ((sockfd = Socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      Error1("socket(PF_INET, SOCK_DGRAM, 0): %s", strerror(errno));
      sockfd = xfd->stream.fd;	/* desparate fallback attempt */
   }

   /*--------------------- setting interface address and netmask ------------*/
   if (argc == 2) {
       if ((ifaddr = strdup(argv[1])) == NULL) {
          Error1("strdup(\"%s\"): out of memory", argv[1]);
          return STAT_RETRYLATER;
       }
       if ((result = xioparsenetwork(ifaddr, pf, &network)) != STAT_OK) {
          /*! recover */
          return result;
       }
       socket_init(pf, (union sockaddr_union *)&ifr.ifr_addr);
       ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr =
          network.netaddr.ip4.sin_addr;
       if (Ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
          Error4("ioctl(%d, SIOCSIFADDR, {\"%s\", \"%s\"}: %s",
             sockfd, ifr.ifr_name, ifaddr, strerror(errno));
       }
       ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr =
          network.netmask.ip4.sin_addr;
       if (Ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
          Error4("ioctl(%d, SIOCSIFNETMASK, {\"0x%08u\", \"%s\"}, %s",
             sockfd, ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr,
             ifaddr, strerror(errno));
       }
       free(ifaddr);
   }
   /*--------------------- setting interface flags --------------------------*/
   applyopts_single(&xfd->stream, opts, PH_FD);

   if (Ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
      Error3("ioctl(%d, SIOCGIFFLAGS, {\"%s\"}: %s",
	     sockfd, ifr.ifr_name, strerror(errno));
   }
   Debug2("\"%s\": system set flags: 0x%hx", ifr.ifr_name, ifr.ifr_flags);
   ifr.ifr_flags |= xfd->stream.para.tun.iff_opts[0];
   ifr.ifr_flags &= ~xfd->stream.para.tun.iff_opts[1];
   Debug2("\"%s\": xio merged flags: 0x%hx", ifr.ifr_name, ifr.ifr_flags);
   if (Ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
      Error4("ioctl(%d, SIOCSIFFLAGS, {\"%s\", %hd}: %s",
	     sockfd, ifr.ifr_name, ifr.ifr_flags, strerror(errno));
   }
   ifr.ifr_flags = 0;
   if (Ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
      Error3("ioctl(%d, SIOCGIFFLAGS, {\"%s\"}: %s",
	     sockfd, ifr.ifr_name, strerror(errno));
   }
   Debug2("\"%s\": resulting flags: 0x%hx", ifr.ifr_name, ifr.ifr_flags);


#if LATER
   applyopts_named(tundevice, opts, PH_FD);
#endif
   applyopts(xfd->stream.fd, opts, PH_FD);
   applyopts_cloexec(xfd->stream.fd, opts);

   applyopts_fchown(xfd->stream.fd, opts);

   if ((result = _xio_openlate(&xfd->stream, opts)) < 0)
      return result;

   return 0;
}

ssize_t _packet_len_from_ip_header(const uint8_t *buff, size_t bufsiz) {
   if (bufsiz < 4)
      return 0;

   if ((buff[0] >> 4) != 4)
       return -1; // not ipv4

   return (((size_t)buff[2]) << 8) | buff[3];
}

ssize_t _packet_len_from_ip6_header(const uint8_t *buff, size_t bufsiz) {
   if (bufsiz < 6)
      return 0;

   if ((buff[0] >> 4) != 6)
       return -1; // not ipv6

   // 40 - ipv6 header length
   return 40 + ((((size_t)buff[4]) << 8) | buff[5]);
}

ssize_t _packet_len_from_arp_header(const uint8_t *buff, size_t bufsiz) {
    if (bufsiz < 2)
        return 0;
    if (!(buff[0] == 0 && buff[1] == 1)) // hardware type == ethernet
        return -1; // not arp
    return 28;  // it's fixed
}

ssize_t _len_to_write_from_l3(uint16_t proto, const uint8_t *buff, size_t bufsiz) {
   switch(proto) {
      case 0x0800: // ip 4 ETH_P_IP
         return _packet_len_from_ip_header(buff, bufsiz);
      case 0x86DD: // ip 6 ETH_P_IPV6
         return _packet_len_from_ip6_header(buff, bufsiz);
      case 0x0806:
         return _packet_len_from_arp_header(buff, bufsiz);
      default:
         // unknown. Let's hope it is fully in buffer. Tun will break otherwise
         return bufsiz;
   }
}

size_t _packet_len_from_l3_header(struct single *pipe, const uint8_t *buff, size_t bufsiz) {
   if (pipe->para.tun.no_pi) {
      if (pipe->para.tun.tuntype == XIOTUNTYPE_TUN) {
         // todo is it always ip4?
         return _packet_len_from_ip_header(buff, bufsiz);
      } else {
         if (bufsiz < XIO_TUN_ETHERNET_LENGTH)
            return 0; // wait until ethernet header is filled

         uint16_t proto = (((uint16_t)buff[12]) << 8) | buff[13];

         ssize_t to_write = _len_to_write_from_l3(proto, buff + XIO_TUN_ETHERNET_LENGTH, bufsiz - XIO_TUN_ETHERNET_LENGTH);
         if (to_write < 0) {
            // l3 header mismatches ethertype. this situation is very unlikely
            // anyway, we can't determine packet length, so pass it as is
            return bufsiz;
         }
         if (to_write > 0)
            return XIO_TUN_ETHERNET_LENGTH + to_write;
         return 0; // not known yet
      }
   } else {
      if (bufsiz < XIO_TUN_PI_LENGTH)
         return 0; // return to wait until the buffer is full enough
      uint16_t proto = (((uint16_t)buff[2]) << 8) | buff[3];
      Debug1("Proto %x", proto);
      size_t l3_offset = XIO_TUN_PI_LENGTH;
      ssize_t to_write = 0;
      if (pipe->para.tun.tuntype == XIOTUNTYPE_TUN) {
         to_write = _len_to_write_from_l3(proto, buff + l3_offset, bufsiz - l3_offset);
         if (to_write < 0) {
            // what follows is another PI. Pass the current one to
            // the interface first
            return XIO_TUN_PI_LENGTH;
         }
         if (to_write > 0)
            return XIO_TUN_PI_LENGTH + to_write;
      } else { // tap
         if (bufsiz < XIO_TUN_PI_LENGTH + XIO_TUN_ETHERNET_LENGTH)
            return 0; // wait until PI + ethernet parts are in buffer
         uint16_t proto_eth = (((uint16_t)buff[12+XIO_TUN_PI_LENGTH]) << 8) | buff[13+XIO_TUN_PI_LENGTH];
         if (proto_eth != proto) {
            // what follows is (probably) another PI. Pass the current one to
            // the interface first
            Debug2("etherType in PI and ethernet header mismatch. Treating as extra PI. PI: %x. ETH: %x", proto, proto_eth);
            return XIO_TUN_PI_LENGTH;
         }
         l3_offset += XIO_TUN_ETHERNET_LENGTH;
         to_write = _len_to_write_from_l3(proto, buff + l3_offset, bufsiz - l3_offset);
         if (to_write > 0)
            return XIO_TUN_PI_LENGTH + XIO_TUN_ETHERNET_LENGTH + to_write;
      }
      return 0;
   }
}

void _slip_transform_if_full_frame(uint8_t *buff, size_t bufsiz, ssize_t * packet_len, ssize_t * raw_packet_len) {
   // find packet end mark. if found, transform the packet (strip escapes).
   // SLIP protocol reference: https://tools.ietf.org/html/rfc1055
   ssize_t slip_end_pos = -1;

   // find packet boundary first
   ssize_t i;
   for (i = 0; i < bufsiz; i++) {
      if (buff[i] == SLIP_END) {
         slip_end_pos = i;
         break;
      }
   }
   if (slip_end_pos == -1) {  // not a full frame yet
      Debug1("SLIP: not full frame. %d", bufsiz);
      *packet_len = 0;
      *raw_packet_len = 0;
      return;
   }

   // now as we've got a full packet, lets transform it
   ssize_t pos = 0; // transformed
   ssize_t pos_raw;
   for (pos_raw = 0; pos_raw < slip_end_pos;) {
      assert(buff[pos_raw] != SLIP_END);
      switch (buff[pos_raw]) {
         case SLIP_ESC:
            switch (buff[pos_raw + 1]) {
               case SLIP_ESC_END:
                  buff[pos] = SLIP_END;
                  break;
               case SLIP_ESC_ESC:
                  buff[pos] = SLIP_ESC;
                  break;
               default: // not valid SLIP actually. write some junk
                  Warn1("Invalid data after SLIP_ESC: %x. Skipping ESC byte.", buff[pos_raw + 1]);
                  buff[pos] = buff[pos_raw + 1];
            }
            pos++;
            pos_raw += 2;
            break;
         default:
            buff[pos] = buff[pos_raw];
            pos++;
            pos_raw++;
            break;
      }
   }
   *packet_len = pos;
   *raw_packet_len = slip_end_pos + 1;
}

/* on result < 0: errno reflects the value from write() */
ssize_t xiowrite_tun(struct single *pipe, void *buff, size_t bufsiz) {
   // SLIP transformation never grows a packet.
   ssize_t writt_total = 0;  // bytes already drained from the buff (before SLIP transformation)
   ssize_t packet_len;  // length of complete L2/L3 frame to write to the tun (after SLIP transformation)
   ssize_t raw_packet_len;  // length of raw L2/L3 packet (before SLIP)

   while (writt_total < bufsiz) {
      void *buff_packet = buff + writt_total;  // pointer to the current L2/L3 frame in buffer
      size_t bufsiz_packet = bufsiz - writt_total;  // length of buffer tail
      if (pipe->para.tun.slip) {
         _slip_transform_if_full_frame(buff_packet, bufsiz_packet, &packet_len, &raw_packet_len);
         // if packet_len is not 0, then buf definitely contains the whole frame (already transformed)
         // if packet_len == 0 , raw_packet_len might be > 0 - that means an END without a frame before it
      } else {
         packet_len = _packet_len_from_l3_header(pipe, buff_packet, bufsiz_packet);
         raw_packet_len = packet_len;  // we don't make any transformations here
      }
      assert(packet_len <= raw_packet_len);

      if (packet_len == 0 && raw_packet_len > 0 && raw_packet_len <= bufsiz_packet) {
         // skip junky frame
         writt_total += raw_packet_len;
         continue;
      }

      if (packet_len == 0 || packet_len > bufsiz_packet) {
         Debug1("Skipping buf len %d", bufsiz_packet);
         if (writt_total == 0) {
            // don't write anything yet, wait until buffer contains full
            // IP packet
            errno = EAGAIN;
            return -1;
         }
         break;
      }

      if (packet_len != bufsiz_packet) {
         Debug2("Partial packetwrite. %d out of %d", packet_len, bufsiz_packet);
      }

      ssize_t writt = writefull(pipe->fd, buff_packet, packet_len);
      if (writt < 0) {
         int _errno = errno;
         switch (_errno) {
            case EPIPE:
            case ECONNRESET:
               if (pipe->cool_write) {
                  Notice4("write(%d, %p, "F_Zu"): %s",
                        pipe->fd, buff_packet, packet_len, strerror(_errno));
                  break;
               }
               /*PASSTHROUGH*/
            default:
               Error4("write(%d, %p, "F_Zu"): %s",
                     pipe->fd, buff_packet, packet_len, strerror(_errno));
         }
         errno = _errno;
         return -1;
      }
      // tun accepts the whole frame in a single write syscall.
      // thus we can rely on an assumption:
      assert(writt == packet_len);
      writt_total += raw_packet_len;  // skip buf space equal to raw packet length
   }
   return writt_total;
}


ssize_t xioread_tun(struct single *pipe, uint8_t *buff, size_t bufsiz) {
   ssize_t bytes;
   do {
      bytes = Read(pipe->fd, buff, bufsiz);
   } while (bytes < 0 && errno == EINTR);

   if (bytes < 0) {
      int _errno = errno;
      switch (_errno) {
         case EPIPE: case ECONNRESET:
            Warn4("read(%d, %p, "F_Zu"): %s",
            pipe->fd, buff, bufsiz, strerror(_errno));
            break;

         default:
            Error4("read(%d, %p, "F_Zu"): %s", pipe->fd, buff, bufsiz, strerror(_errno));
      }
      errno = _errno;
      return -1;
   }

   // a full frame is guaranteed to be returned by a single read syscall
   // so we've got a full frame in the buffer now.

   if (!pipe->para.tun.slip)
      return bytes; // no transformations required

   // apply SLIP transformations

   // they never shrink the frame: they only grow it.
   // here's a hack: move the frame to the tail of buffer
   // so we can grow the packet when escaping END/ESC bytes.
   memmove(buff + bufsiz - bytes, buff, bytes);
   ssize_t pos_transformed = 0;
   ssize_t pos;
   for (pos = bufsiz - bytes; pos < bufsiz; pos++) {
      if (pos_transformed + 2 >= pos) { // looks like the buffer is too small for that packet.
         Warn2("Packets overlap on applying SLIP transformations to a packet "
               "read from tun. This packet is skipped. Consider increasing "
               "buffer length. (%d, %d)", bytes, bufsiz);
         errno = EAGAIN;
         return -1;  // drop packet
      }
      switch (buff[pos]) {
         case SLIP_END:
            buff[pos_transformed] = SLIP_ESC;
            buff[pos_transformed + 1] = SLIP_ESC_END;
            pos_transformed += 2;
            break;
         case SLIP_ESC:
            buff[pos_transformed] = SLIP_ESC;
            buff[pos_transformed + 1] = SLIP_ESC_ESC;
            pos_transformed += 2;
            break;
         default:
            buff[pos_transformed] = buff[pos];
            pos_transformed++;
      }
   }
   buff[pos_transformed] = SLIP_END;
   return pos_transformed + 1;
}


#endif /* WITH_TUN */
