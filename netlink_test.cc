#include "ace/Event_Handler.h"
#include "ace/Reactor.h"
#include "ace/Log_Msg.h"
#include "ace/Netlink_Addr.h"
#include "ace/SOCK_Netlink.h"
#include "ace/SOCK_Dgram.h"

#include <net/if.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string>
#include <bitset>
#include <linux/if_tun.h>


class NetlinkTest : public ACE_Event_Handler {

  public:
    struct Netlink_Request {
      struct nlmsghdr nhdr_; // message header
      struct ifaddrmsg ifa_; // interface
      char buf_[256];
    };

    virtual ~NetlinkTest();
    NetlinkTest(std::string intf_name, std::string ip, std::string mask)
    {
      m_intf_name = intf_name;
      m_ip = ip;
      m_mask = mask;
      seq_ = 0;
      address_.set(ACE_OS::getpid (), 0);

      if(socket_.open(address_, ACE_PROTOCOL_FAMILY_NETLINK, NETLINK_ROUTE) < 0) {
        ACE_ERROR((LM_ERROR,
                   ACE_TEXT("(%P|%t) NetlinkTest::open: - failed\n")
                   ACE_TEXT("to initialize netlink socket open ().\n")));
      }
      else {
        do {
          struct ifreq ifr;
          m_tunFd = open("/dev/net/tun", O_RDWR);
          if(m_tunFd < 0) {
            ACE_ERROR((LM_ERROR,
                       ACE_TEXT("(%P|%t) open for /dev/net/tun - failed\n")
                       ACE_TEXT("to initialize netlink socket open ().\n")));
            break;
          }

          memset((void *)&ifr, 0, sizeof(struct ifreq));

          ifr.ifr_flags = IFF_TUN       |
                          IFF_NO_PI     |
                          IFF_MULTICAST |
                          IFF_BROADCAST |
                          IFF_PROMISC   |
                          IFF_ONE_QUEUE;

          if(ACE_OS::ioctl(m_tunFd, TUNSETIFF, (void *) &ifr) < 0) {
            ACE_ERROR((LM_ERROR,
                       ACE_TEXT("(%P|%t) ioctl for /dev/net/tun - failed\n")
                       ACE_TEXT("to initialize netlink socket open ().\n")));
            break;
          }

          std::string tun_dev(ifr.ifr_name, IFNAMSIZ);
          m_tun_intf_name = tun_dev;

          ACE_DEBUG((LM_DEBUG, ACE_TEXT("(%P) the dev name is %s\n"), m_tun_intf_name.c_str()));
          ACE_Reactor::instance()->register_handler(this, ACE_Event_Handler::READ_MASK);
          ACE_Reactor::instance()->register_handler(m_tunFd, this, ACE_Event_Handler::READ_MASK);
        }while(0);
      }
    }

    ACE_HANDLE get_handle() const override;
    int handle_input(ACE_HANDLE ) override;
    int handle_close(ACE_HANDLE, ACE_Reactor_Mask) override;

    void mask(std::string mask_)
    {
      m_mask = mask_;
    }

    void ip(std::string ip_)
    {
      m_ip = ip_;
    }

    void intf(std::string intf_)
    {
      m_intf_name = intf_;
    }

    int bit_count(std::string mask_)
    {
      struct in_addr MASK;
      inet_aton(mask_.c_str(), &MASK);
      std::bitset<32>  subnetMask(MASK.s_addr);
      return(subnetMask.count());
    }

    int add_ip();
    int delete_ip();

    int install_tunIP(std::string srcIP_, std::string destIP_, std::string mack_);
  private:
    std::string m_intf_name;
    std::string m_ip;
    std::string m_mask;
    std::string m_tun_intf_name;
    ACE_HANDLE m_tunFd;
    // The socket.
    ACE_SOCK_Netlink socket_ ;
    // The address of the socket.
    ACE_Netlink_Addr  address_ ;
    // Message sequence number.
    ACE_UINT32 seq_ ;
    // The request structure passed to kernel.
    Netlink_Request netlink_request_;
};

NetlinkTest::~NetlinkTest()
{
  ACE_Reactor::instance()->remove_handler(this, ACE_Event_Handler::READ_MASK | ACE_Event_Handler::DONT_CALL);
  socket_.close();
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT("(%P) %s -  entered\n"), __PRETTY_FUNCTION__));
}

ACE_HANDLE NetlinkTest::get_handle() const
{
  ACE_DEBUG((LM_INFO, ACE_TEXT("%s\n"), __PRETTY_FUNCTION__));
  return(socket_.get_handle());
}

int NetlinkTest::install_tunIP(std::string srcIP_, std::string destIP_, std::string mask_)
{
  int32_t fd;
  struct ifreq ifr;
  ACE_SOCK_Dgram udpSock;
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  //fd = udpSock.get_handle();

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  strncpy(ifr.ifr_name, (const char *)m_tun_intf_name.c_str(), IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;
  struct in_addr IP;

  std::string newName("fwd0");
  strncpy(ifr.ifr_newname, newName.c_str(), IFNAMSIZ);

  if(ioctl(fd, SIOCSIFNAME, (void *) &ifr) < 0) {
   fprintf(stderr, "\n%s:%d renaming of tunnel intf failed\n", __FILE__, __LINE__);
   perror("\n renaming of tunnel intf :");
   return(-1);
  }

  strncpy(ifr.ifr_name, (const char *)newName.c_str(), IFNAMSIZ);
  if(srcIP_.length()) {
    inet_aton(srcIP_.c_str(), &IP);
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = IP.s_addr;

    if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface address failed\n");
     return(-1);
    }
  }

  if(destIP_.length()) {
    inet_aton(destIP_.c_str(), &IP);
    ((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr.s_addr = IP.s_addr;

    if(ioctl(fd, SIOCSIFDSTADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface DESTINATION IP FAILED failed\n");
     return(-1);
    }
  }

  if(mask_.length()) {
    inet_aton(mask_.c_str(), &IP);
    ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = IP.s_addr;

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
     fprintf(stderr, "\n%s:%dSetting of interface NETMASK failed\n", __FILE__, __LINE__);
     perror("\nSetting of netmask failed:");
     return(-1);
    }
  }



  ifr.ifr_flags = IFF_UP | IFF_RUNNING;
  if(ioctl(fd, SIOCSIFFLAGS, &ifr)) {
    perror("Setting of Flags Failed");
    return(-1);
  }

  close(fd);
  return(0);
}

int NetlinkTest::handle_input(ACE_HANDLE fd)
{
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT("(%P) %s -  entered\n"), __PRETTY_FUNCTION__));


  struct nlmsghdr *hdr = nullptr;
  struct iovec iov;
  char recv_buff_[1024];
  iov.iov_base = recv_buff_;
  iov.iov_len = sizeof (recv_buff_);

  int rval_bytes = -1;
  ACE_Netlink_Addr raddr;
  raddr.set (0, 0);

  rval_bytes = socket_.recv (&iov, 1, raddr);
  ACE_DEBUG((LM_INFO, ACE_TEXT("Response has come rval_bytes %d\n"), rval_bytes));

  hdr =  reinterpret_cast <nlmsghdr*> (recv_buff_);

  if(static_cast <int> (hdr->nlmsg_pid) != this->address_.get_pid ()) {
    ACE_ERROR_RETURN((LM_ERROR,
                      ACE_TEXT("(%P) Secondary_Ipaddr_Handler::handle_input - ")
                      ACE_TEXT("process id %d or message sequence is %d different\n"), address_.get_pid(), seq_),
                      -1);
  }
  /*
   https://tools.ietf.org/html/rfc3549
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Netlink message header                  |
   |                       type = NLMSG_ERROR                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Error code                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       OLD Netlink message header              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  if(hdr->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = static_cast <struct nlmsgerr*> (NLMSG_DATA(hdr));

    ACE_DEBUG ((LM_DEBUG,
                ACE_TEXT("(%P) err->error %d\n"), err->error));

    if(!err->error) {
      ACE_DEBUG ((LM_DEBUG,
                  ACE_TEXT("(%P) %s -  command success\n"), __PRETTY_FUNCTION__));
      ACE_DEBUG((LM_INFO, ACE_TEXT("err->msg.nlmsg_len %d err->msg.nlmsg_flags %d err->msg.nlmsg_type %d  err->msg.nlmsg_seq %d err->msg.nlmsg_pid %d\n"),
                          err->msg.nlmsg_len, err->msg.nlmsg_flags, err->msg.nlmsg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid));
      return 0;
    }

    errno = -err->error;
    perror("Installing of IP Address Failed: ");
    ACE_DEBUG((LM_INFO, ACE_TEXT("err->msg.nlmsg_len %d err->msg.nlmsg_flags %d err->msg.nlmsg_type %d  err->msg.nlmsg_seq %d err->msg.nlmsg_pid %d\n"),
                        err->msg.nlmsg_len, err->msg.nlmsg_flags, err->msg.nlmsg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid));
    return(0);
  }

  return(-1);
}

int NetlinkTest::handle_close(ACE_HANDLE fd, ACE_Reactor_Mask mask)
{
  ACE_DEBUG ((LM_DEBUG,
              ACE_TEXT("(%P) %s -  entered\n"), __PRETTY_FUNCTION__));
  ACE_Reactor::instance()->remove_handler(this, ACE_Event_Handler::READ_MASK | ACE_Event_Handler::DONT_CALL);
  socket_.close();
  return(0);
}

int NetlinkTest::add_ip()
{
  struct in_addr IP;
  inet_aton(m_ip.c_str(), &IP);
  ACE_OS::memset (&netlink_request_, 0, sizeof(netlink_request_));

  // fill the request header
  netlink_request_.nhdr_.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  netlink_request_.nhdr_.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
  netlink_request_.nhdr_.nlmsg_type = RTM_NEWADDR;
  netlink_request_.nhdr_.nlmsg_pid = address_.get_pid();
  netlink_request_.nhdr_.nlmsg_seq = ++seq_;

  netlink_request_.ifa_.ifa_prefixlen = bit_count(m_mask);
  netlink_request_.ifa_.ifa_flags = IFA_F_SECONDARY;
  netlink_request_.ifa_.ifa_scope = RT_SCOPE_HOST;
  netlink_request_.ifa_.ifa_family = AF_INET;
  //netlink_request_.ifa_.ifa_index = if_nametoindex(m_tun_intf_name.c_str());
  netlink_request_.ifa_.ifa_index = if_nametoindex(m_intf_name.c_str());

  struct rtattr *rta = reinterpret_cast <struct rtattr*> (((reinterpret_cast <char*>(&netlink_request_.nhdr_)) + NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len)));

  std::string label("enp0s9:1");
  rta->rta_type = IFA_LABEL;
  rta->rta_len = RTA_LENGTH (label.length());
  ACE_OS::memcpy (RTA_DATA(rta), (const void *)label.c_str(), label.length());

  netlink_request_.nhdr_.nlmsg_len = NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len) + RTA_LENGTH (label.length());

  rta = reinterpret_cast <struct rtattr*> (((reinterpret_cast <char*>(&netlink_request_.nhdr_)) + NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len)));

  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH (4);
  ACE_OS::memcpy (RTA_DATA(rta), (const void *)&IP.s_addr, 4);
  netlink_request_.nhdr_.nlmsg_len = NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len) + RTA_LENGTH (4);

  iovec iov_send = { static_cast <void*> (&netlink_request_.nhdr_), netlink_request_.nhdr_.nlmsg_len };

  ACE_Netlink_Addr  addr_send;
  addr_send.set (0, 0);

  if(socket_.send(&iov_send,
                  1,
                  addr_send) < 0) {
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT("%s - ")
                       ACE_TEXT("send of request failed with errno %d.\n"),
                       __PRETTY_FUNCTION__,
                       errno),
                       -1);
  }

  return(0);
}

int NetlinkTest::delete_ip()
{
  struct in_addr IP;
  inet_aton(m_ip.c_str(), &IP);
  ACE_OS::memset (&netlink_request_, 0, sizeof(netlink_request_));

  // fill the request header
  netlink_request_.nhdr_.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  netlink_request_.nhdr_.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  netlink_request_.nhdr_.nlmsg_type = RTM_DELADDR;
  netlink_request_.nhdr_.nlmsg_pid = address_.get_pid();
  netlink_request_.nhdr_.nlmsg_seq = ++seq_;

  struct rtattr *rta = reinterpret_cast <struct rtattr*> (((reinterpret_cast <char*>(&netlink_request_.nhdr_)) + NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len)));

  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH (4);
  ACE_OS::memcpy (RTA_DATA(rta), (const void *)&IP.s_addr, 4);

  netlink_request_.nhdr_.nlmsg_len = NLMSG_ALIGN (netlink_request_.nhdr_.nlmsg_len) + RTA_LENGTH (4);

  netlink_request_.ifa_.ifa_prefixlen = bit_count(m_mask);
  netlink_request_.ifa_.ifa_scope = 0;
  netlink_request_.ifa_.ifa_family = AF_INET;
  netlink_request_.ifa_.ifa_index = if_nametoindex(m_intf_name.c_str());


  iovec iov_send =
  {
    static_cast <void*> (&netlink_request_.nhdr_),
    netlink_request_.nhdr_.nlmsg_len
  };

  ACE_Netlink_Addr  addr_send;
  addr_send.set (0, 0);

  if(socket_.send (&iov_send,
                   1,
                   addr_send) < 0) {
    ACE_ERROR_RETURN ((LM_ERROR,
                       ACE_TEXT("%s - ")
                       ACE_TEXT("send of request failed with errno %d.\n"),
                       __PRETTY_FUNCTION__,
                       errno),
                       -1);
  }

  return(0);
}



int main()
{
  std::string intf("enp0s9");
  std::string ip("10.10.10.1");
  //std::string ip("10.11.10.20");
  std::string mask("255.255.255.0");

  NetlinkTest nTest(intf, ip, mask);
  nTest.add_ip();

  nTest.install_tunIP("10.10.10.2", "10.10.10.2", "255.255.255.0");
#if 0
  nTest.intf("enp0s9:1");
  nTest.ip("10.11.10.2");
  nTest.mask("255.255.255.0");
  nTest.add_ip();

  nTest.intf("enp0s9:3");
  nTest.ip("10.11.10.2");
  nTest.mask("255.255.255.0");
  nTest.add_ip();
#endif

  while(1) {
    ACE_Reactor::instance()->handle_events();
  }
}
