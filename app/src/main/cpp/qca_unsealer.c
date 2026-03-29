#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <errno.h>

// nl80211 魔数和常量定义
#define GENL_ID_CTRL 16
#define CTRL_CMD_GETFAMILY 3
#define CTRL_ATTR_FAMILY_NAME 1
#define CTRL_ATTR_FAMILY_ID 2
#define NL80211_CMD_VENDOR 103
#define NL80211_ATTR_IFINDEX 3
#define NL80211_ATTR_VENDOR_ID 195
#define NL80211_ATTR_VENDOR_SUBCMD 196
#define NL80211_ATTR_VENDOR_DATA 197

#define OUI_QCA 0x001374
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION 74
#define QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER 83
#define QCA_WLAN_VENDOR_ATTR_CONFIG_ARP_NS_OFFLOAD 81

// 辅助结构体用于构造 Generic Netlink 消息
struct genlmsghdr {
    uint8_t cmd;
    uint8_t version;
    uint16_t reserved;
};

// 辅助函数：计算 NLA 对齐大小
#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))

// 辅助函数：添加 NLA 属性
void add_nla(struct nlmsghdr *nlh, uint16_t type, const void *data, uint16_t data_len) {
    struct nlattr *nla = (struct nlattr *)((char *)nlh + NLA_ALIGN(nlh->nlmsg_len));
    nla->nla_len = data_len + sizeof(struct nlattr);
    nla->nla_type = type;
    if (data_len > 0 && data != NULL) {
        memcpy((char *)nla + sizeof(struct nlattr), data, data_len);
    }
    nlh->nlmsg_len = NLA_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len);
}

// 辅助函数：添加嵌套 NLA 属性起始
struct nlattr *add_nla_nest_start(struct nlmsghdr *nlh, uint16_t type) {
    struct nlattr *nest = (struct nlattr *)((char *)nlh + NLA_ALIGN(nlh->nlmsg_len));
    nest->nla_type = type | 0x8000; // NLA_F_NESTED
    // 暂存长度头部，稍后更新
    nlh->nlmsg_len = NLA_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(sizeof(struct nlattr));
    return nest;
}

// 辅助函数：结束嵌套 NLA 属性
void add_nla_nest_end(struct nlmsghdr *nlh, struct nlattr *nest) {
    nest->nla_len = (char *)nlh + NLA_ALIGN(nlh->nlmsg_len) - (char *)nest;
}

// 获取 nl80211 的 Family ID
int get_nl80211_family_id(int nl_sock) {
    char buf[8192];
    struct sockaddr_nl nladdr;
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct genlmsghdr *genl = (struct genlmsghdr *)(nlh + 1);

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;

    genl->cmd = CTRL_CMD_GETFAMILY;
    genl->version = 1;

    if (sendto(nl_sock, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        perror("sendto CTRL_CMD_GETFAMILY");
        return -1;
    }

    int nl80211_id = -1;
    while (1) {
        int len = recv(nl_sock, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv CTRL_CMD_GETFAMILY");
            return -1;
        }
        if (len == 0) break;

        for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                return nl80211_id;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
                if (err->error == 0) continue; // ACK
                fprintf(stderr, "[-] Netlink error in GETFAMILY: %d\n", err->error);
                return -1;
            }

            genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
            struct nlattr *nla = (struct nlattr *)((char *)genl + NLA_ALIGN(sizeof(struct genlmsghdr)));
            int nla_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct genlmsghdr));
            
            int cur_id = -1;
            char cur_name[64] = {0};

            while (nla_len >= (int)sizeof(struct nlattr)) {
                int attr_len = nla->nla_len;
                if (attr_len < (int)sizeof(struct nlattr) || attr_len > nla_len) {
                    break;
                }
                
                if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
                    cur_id = *(uint16_t *)((char *)nla + NLA_HDRLEN);
                } else if (nla->nla_type == CTRL_ATTR_FAMILY_NAME) {
                    int name_len = attr_len - NLA_HDRLEN;
                    if (name_len > 0 && name_len < sizeof(cur_name)) {
                        memcpy(cur_name, (char *)nla + NLA_HDRLEN, name_len);
                        cur_name[name_len] = '\0';
                    }
                }
                nla = (struct nlattr *)((char *)nla + NLA_ALIGN(attr_len));
                nla_len -= NLA_ALIGN(attr_len);
            }
            
            if (cur_id != -1 && cur_name[0] != '\0') {
                printf("[*] Found family: %s (ID: %d)\n", cur_name, cur_id);
                if (strcmp(cur_name, "nl80211") == 0) {
                    nl80211_id = cur_id;
                }
            }
        }
    }

    return nl80211_id;
}

// 发送 Vendor Command 解封环境
int unseal_qca_wifi(int nl80211_id, int nl_sock, int ifindex) {
    char buf[4096];
    struct sockaddr_nl nladdr;
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    // ==========================================
    // 载荷 1：关闭 ARP / NS Offload
    // ==========================================
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    nlh->nlmsg_type = nl80211_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 2;

    struct genlmsghdr *genl = (struct genlmsghdr *)(nlh + 1);
    genl->cmd = NL80211_CMD_VENDOR;
    genl->version = 1;

    add_nla(nlh, NL80211_ATTR_IFINDEX, &ifindex, sizeof(uint32_t));
    uint32_t vendor_id = OUI_QCA;
    add_nla(nlh, NL80211_ATTR_VENDOR_ID, &vendor_id, sizeof(uint32_t));
    uint32_t subcmd_config = QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION;
    add_nla(nlh, NL80211_ATTR_VENDOR_SUBCMD, &subcmd_config, sizeof(uint32_t));

    struct nlattr *nest_config = add_nla_nest_start(nlh, NL80211_ATTR_VENDOR_DATA);
    uint8_t offload_val = 0; // 0 = Disable
    add_nla(nlh, QCA_WLAN_VENDOR_ATTR_CONFIG_ARP_NS_OFFLOAD, &offload_val, sizeof(uint8_t));
    add_nla_nest_end(nlh, nest_config);

    if (sendto(nl_sock, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        perror("sendto ARP_NS_OFFLOAD payload");
        return -1;
    }
    printf("[+] Successfully sent QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION (ARP/NS Offload = 0)\n");

    // 读取响应，清空 socket 缓冲区
    recv(nl_sock, buf, sizeof(buf), 0);

    // ==========================================
    // 载荷 2：清空 APF (Packet Filter) 规则
    // ==========================================
    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    nlh->nlmsg_type = nl80211_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 3;

    genl = (struct genlmsghdr *)(nlh + 1);
    genl->cmd = NL80211_CMD_VENDOR;
    genl->version = 1;

    add_nla(nlh, NL80211_ATTR_IFINDEX, &ifindex, sizeof(uint32_t));
    add_nla(nlh, NL80211_ATTR_VENDOR_ID, &vendor_id, sizeof(uint32_t));
    uint32_t subcmd_apf = QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER;
    add_nla(nlh, NL80211_ATTR_VENDOR_SUBCMD, &subcmd_apf, sizeof(uint32_t));

    struct nlattr *nest_apf = add_nla_nest_start(nlh, NL80211_ATTR_VENDOR_DATA);
    // Attribute 2 通常是 QCA_WLAN_VENDOR_ATTR_PACKET_FILTER_PROGRAM
    // 传空的数据表示清除现有的 Filter
    add_nla(nlh, 2, NULL, 0); 
    add_nla_nest_end(nlh, nest_apf);

    if (sendto(nl_sock, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        perror("sendto PACKET_FILTER payload");
        return -1;
    }
    printf("[+] Successfully sent QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER (Empty Program to wipe APF)\n");
    
    // 读取响应，清空 socket 缓冲区
    recv(nl_sock, buf, sizeof(buf), 0);

    return 0;
}

int main(int argc, char **argv) {
    const char *iface = "wlan0";
    if (argc > 1) {
        iface = argv[1];
    }

    if (getuid() != 0) {
        fprintf(stderr, "[-] Error: This program must be run as root to send Netlink Vendor Commands.\n");
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "[-] Error: Cannot find interface %s\n", iface);
        return 1;
    }

    int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_sock < 0) {
        perror("socket AF_NETLINK");
        return 1;
    }

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    if (bind(nl_sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind AF_NETLINK");
        close(nl_sock);
        return 1;
    }

    printf("[*] Resolving nl80211 Netlink Family ID...\n");
    int nl80211_id = get_nl80211_family_id(nl_sock);
    if (nl80211_id < 0) {
        fprintf(stderr, "[-] Error: Could not resolve nl80211 family ID. Is the driver loaded?\n");
        close(nl_sock);
        return 1;
    }
    printf("[+] nl80211 Family ID: %d\n", nl80211_id);

    printf("[*] Unsealing QCA WiFi Offloads on %s (ifindex: %d)...\n", iface, ifindex);
    int ret = unseal_qca_wifi(nl80211_id, nl_sock, ifindex);
    if (ret == 0) {
        printf("[+] Unseal operation completed. The environment should now be vulnerable to MITM.\n");
    }

    close(nl_sock);
    return ret;
}