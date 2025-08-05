#include "rules.h" 


static struct proc_dir_entry *firewall_dir;
static struct proc_dir_entry *rules_file;
static LIST_HEAD(rules_list);
static DEFINE_SPINLOCK(rules_lock);
static int rule_count = 0;

/* Rule format: <ip_address> <protocol> <action> */
/* e.g. "192.168.1.1 6 1" to block TCP traffic from 192.168.1.1 */

/* Convert string action to enum */
static rule_action_t str_to_action(const char *action_str)
{
    if (action_str[0] == '0')
        return ACTION_ALLOW;
    return ACTION_DENY;
}

/* Convert protocol string to number */
static __u8 str_to_protocol(const char *proto_str)
{
    long protocol;
    int res = kstrtol(proto_str, 10, &protocol);
    if (res != 0)
        return 0; 
    return (__u8)protocol;
}

/* Parse rule from user input */
static int parse_rule(const char *buffer, __be32 *ip, __u8 *protocol, rule_action_t *action)
{
    char ip_str[16] = {0}; /* xxx.xxx.xxx.xxx\0 */
    char proto_str[4] = {0};
    char action_str[2] = {0};
    int fields;
    
    fields = sscanf(buffer, "%15s %3s %1s", ip_str, proto_str, action_str);
    if (fields != 3) {
        printk(KERN_ERR "Firewall: Invalid rule format. Expected: <ip> <protocol> <action>\n");
        return -EINVAL;
    }

    /* Convert IP string to binary */
    if (in4_pton(ip_str, -1, (u8 *)ip, -1, NULL) != 1) {
        printk(KERN_ERR "Firewall: Invalid IP address format\n");
        return -EINVAL;
    }

    *protocol = str_to_protocol(proto_str);
    *action = str_to_action(action_str);

    return 0;
}

/* Proc file operations */
static int rules_show(struct seq_file *m, void *v)
{
    firewall_rule_t *rule;
    unsigned char ip_bytes[4];
    
    seq_puts(m, "IP Address\tProtocol\tAction\n");
    seq_puts(m, "-----------------------------------\n");
    
    spin_lock(&rules_lock);
    list_for_each_entry(rule, &rules_list, list) {
        memcpy(ip_bytes, &rule->ip, 4);
        seq_printf(m, "%d.%d.%d.%d\t%u\t%s\n",
                  ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                  rule->protocol,
                  rule->action == ACTION_ALLOW ? "allow" : "deny");
    }
    spin_unlock(&rules_lock);
    
    return 0;
}

static int rules_open(struct inode *inode, struct file *file)
{
    return single_open(file, rules_show, NULL);
}

static ssize_t rules_write(struct file *file, const char __user *user_buffer,
                          size_t count, loff_t *ppos)
{
    char *buffer;
    __be32 ip;
    __u8 protocol;
    rule_action_t action;
    int ret;

    if (count > MAX_RULE_LENGTH)
        return -EINVAL;

    buffer = kmalloc(count + 1, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    if (copy_from_user(buffer, user_buffer, count)) {
        kfree(buffer);
        return -EFAULT;
    }
    buffer[count] = '\0';

    /* Remove trailing newlines */
    if (count > 0 && buffer[count-1] == '\n')
        buffer[count-1] = '\0';

    /* Parse the rule */
    ret = parse_rule(buffer, &ip, &protocol, &action);
    if (ret == 0) {
        ret = add_rule(ip, protocol, action);
        if (ret == 0) {
            printk(KERN_INFO "Firewall: Added rule for IP %pI4, protocol %u, action %d\n", 
                   &ip, protocol, action);
        } else {
            printk(KERN_ERR "Firewall: Failed to add rule, err=%d\n", ret);
        }
    }

    kfree(buffer);
    return count;
}

static const struct proc_ops rules_proc_ops = {
    .proc_open = rules_open,
    .proc_read = seq_read,
    .proc_write = rules_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Rule management functions */
int add_rule(__be32 ip, __u8 protocol, rule_action_t action)
{
    firewall_rule_t *rule, *tmp_rule;
    int found = 0;

    if (rule_count >= MAX_RULES)
        return -ENOSPC;

    /* Check if rule already exists */
    spin_lock(&rules_lock);
    list_for_each_entry(tmp_rule, &rules_list, list) {
        if (tmp_rule->ip == ip && tmp_rule->protocol == protocol) {
            tmp_rule->action = action;
            found = 1;
            break;
        }
    }
    spin_unlock(&rules_lock);

    if (found)
        return 0;

    /* Add new rule */
    rule = kmalloc(sizeof(firewall_rule_t), GFP_KERNEL);
    if (!rule)
        return -ENOMEM;

    rule->ip = ip;
    rule->protocol = protocol;
    rule->action = action;

    spin_lock(&rules_lock);
    list_add_tail(&rule->list, &rules_list);
    rule_count++;
    spin_unlock(&rules_lock);

    return 0;
}

int delete_rule(__be32 ip, __u8 protocol)
{
    firewall_rule_t *rule, *tmp;
    int found = 0;

    spin_lock(&rules_lock);
    list_for_each_entry_safe(rule, tmp, &rules_list, list) {
        if (rule->ip == ip && rule->protocol == protocol) {
            list_del(&rule->list);
            kfree(rule);
            rule_count--;
            found = 1;
            break;
        }
    }
    spin_unlock(&rules_lock);

    return found ? 0 : -ENOENT;
}

/* 修改后的check_rules函数，使用nf_hook_state参数 */
unsigned int check_rules(struct sk_buff *skb, 
                        const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    firewall_rule_t *rule;
    unsigned int ret = NF_ACCEPT;
    
    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    spin_lock(&rules_lock);
    list_for_each_entry(rule, &rules_list, list) {
        if (rule->ip == ip_header->saddr && 
            (rule->protocol == 0 || rule->protocol == ip_header->protocol)) {
            ret = (rule->action == ACTION_ALLOW) ? NF_ACCEPT : NF_DROP;
            break;
        }
    }
    spin_unlock(&rules_lock);

    return ret;
}

int init_rule_manager(void)
{
    /* Create /proc/firewall directory */
    firewall_dir = proc_mkdir("firewall", NULL);
    if (!firewall_dir) {
        printk(KERN_ERR "Firewall: Failed to create /proc/firewall directory\n");
        return -ENOMEM;
    }

    /* Create /proc/firewall/rules file */
    rules_file = proc_create("rules", 0644, firewall_dir, &rules_proc_ops);
    if (!rules_file) {
        printk(KERN_ERR "Firewall: Failed to create /proc/firewall/rules file\n");
        proc_remove(firewall_dir);
        return -ENOMEM;
    }

    printk(KERN_INFO "Firewall: Rule manager initialized\n");
    return 0;
}

void cleanup_rule_manager(void)
{
    firewall_rule_t *rule, *tmp;

    /* Remove proc entries */
    if (rules_file)
        proc_remove(rules_file);
    if (firewall_dir)
        proc_remove(firewall_dir);

    /* Free rules list */
    spin_lock(&rules_lock);
    list_for_each_entry_safe(rule, tmp, &rules_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }
    spin_unlock(&rules_lock);

    printk(KERN_INFO "Firewall: Rule manager cleaned up\n");
}