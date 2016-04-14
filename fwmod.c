



#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include <linux/list.h>
#include <linux/init.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Pavlo Bilous, Justin, Eric");


#define FILENAME 		 	"fwb"
#define PROCF_MAX_SIZE 		PAGE_SIZE

// variables for /proc usage
static char *procf_buffer = NULL;
struct proc_dir_entry *proc_file = NULL;


// structure for firewall policies
struct rule {
  unsigned char action;
  unsigned char in_out;
  unsigned char proto;
  char* src_ip;
  char* src_netmask;
  char* src_port;
  char* dest_ip;
  char* dest_netmask;
  char* dest_port;
};

// structure for firewall policies to place in the linked list
struct rule_list_item {
  unsigned char action;		// 0: for block, 1: for unblock
  unsigned char in_out; 	// 0: neither in nor out, 1: in, 2: out
  unsigned char proto;        	// 0: all, 1: tcp, 2: udp
  unsigned int src_ip;        	//
  unsigned int src_netmask;     //
  unsigned int src_port;        // 0~2^32
  unsigned int dest_ip;
  unsigned int dest_netmask;
  unsigned int dest_port;
  struct list_head list;
};

// linked list of all the rules
static struct rule_list_item policy_list;

// structures used to register hook functions
static struct nf_hook_ops in;
static struct nf_hook_ops out;
static char * ssrc_ip;
static char * sdest_ip;

// method signatures 
unsigned int ip_str_to_hl(char *ip_str);
unsigned int port_str_to_int(char *port_str);
unsigned int hook_func_in(unsigned int hooknum,
			  struct sk_buff *skb,
			  const struct net_device *in,
			  const struct net_device *out,
			  int (*okfn)(struct sk_buff *));
unsigned int hook_func_out(unsigned int hooknum,
			   struct sk_buff *skb,
			   const struct net_device *in,
			   const struct net_device *out,
			   int (*okfn)(struct sk_buff *));
void iptoa(unsigned int ip, char *str_ip);
bool check_ip(unsigned int ip,
	      unsigned int ip_rule,
	      unsigned int mask);

char * list_to_string ( void );
static ssize_t procfs_read(struct file *filp, char *buffer,	size_t length,
			   loff_t * offset);

static ssize_t procfs_write(struct file *file, const char *buffer, size_t len,
			    loff_t * off);
void port_int_to_str(unsigned int port, char *port_str);
int procfile_init(void);
void procfile_exit(void);
static ssize_t add_rule(void);
static ssize_t remove_rule(void);
void add_rule_to_list(struct rule* a_rule_desp);
void init_rule(struct rule* a_rule);
static ssize_t generate_rule_from_buffer(struct rule* a_rule);
int get_action(struct rule *a_rule, int i);
int get_in_out(struct rule *a_rule, int i);
int get_protocol(struct rule *a_rule, int i);
int get_src_ip(struct rule *a_rule, int i);
int get_src_mask(struct rule *a_rule, int i);
int get_src_port(struct rule *a_rule, int i);
int get_dest_ip(struct rule *a_rule, int i);
int get_dest_mask(struct rule *a_rule, int i);
int get_dest_port(struct rule *a_rule, int i);



// needs to go after method signatures
static struct file_operations proc_file_fops = {
  .owner = THIS_MODULE,
  .read = procfs_read,
  .write = procfs_write,
};


/******************** Initialization routine ******************/

/**
 * Method gets called when lkm is loaded into the kernel:
 *
 * 1) linked list of all the rules gets allocated,
 * 2) proc file is initialized,
 * 3) the hook structure for incoming packets gets filled,
 * 4) register the incoming hook
 * 5) the hook structure for outgoing packets gets filled,
 * 6) register the outgoing hook
 */
int init_module()
{
  int proc_status;
  printk(KERN_INFO "---------------------------------------\n");
  printk(KERN_INFO "MINIFW: initializing kernel module\n");

  INIT_LIST_HEAD(&(policy_list.list));

  proc_status = procfile_init();
  if (proc_status)
    return 1;

  in.hook = hook_func_in;
  in.hooknum = NF_INET_LOCAL_IN;
  in.pf = PF_INET;
  in.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&in);

  out.hook = hook_func_out;
  out.hooknum = NF_INET_LOCAL_OUT;
  out.pf = PF_INET;
  out.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&out);

  ssrc_ip = (char*)kmalloc(16, GFP_KERNEL);
  sdest_ip = (char*)kmalloc(16, GFP_KERNEL);
  
  return 0;
}

/**
 * Method initializes a buffer for the proc file, and
 * creates the file itself
 */
int procfile_init(void)
{
  int ret = 0;

  procf_buffer = (char*)vmalloc(PROCF_MAX_SIZE);

  if (!procf_buffer)
    return -ENOMEM;
  else
    {
      memset(procf_buffer, 0, PROCF_MAX_SIZE);

      proc_file = proc_create(FILENAME, 0666, NULL, &proc_file_fops);

      if(proc_file == NULL)
	{
	  ret = -ENOMEM;
	  vfree(procf_buffer);
	  printk(KERN_ALERT "MINIFW: Can't init /proc/%s \n", FILENAME);
	}
      else
	printk(KERN_INFO "MINIFW: /proc/%s created", FILENAME);
    }

  return ret;
}

/**
 * Method gets called when lkm is UNLOADED from the kernel
 *
 * 1) all the rules from the linked list are stored in file
 * 2) proc file gets removed
 * 3) in and out hooks are unregistered
 * 4) linked list of all the rules is freed
 */
void cleanup_module() {

  struct list_head *p, *q;
  struct rule_list_item *a_rule;

  // remove proc file
  procfile_exit();

  kfree(ssrc_ip);
  kfree(sdest_ip);

  nf_unregister_hook(&in);
  nf_unregister_hook(&out);

  printk(KERN_INFO "MINIFW: free policy list\n");

  list_for_each_safe(p, q, &policy_list.list)
    {
      printk(KERN_INFO "MINIFW: free one\n");
      a_rule = list_entry(p, struct rule_list_item, list);
      list_del(p);
      kfree(a_rule);
    }

  printk(KERN_INFO "MINIFW: kernel module unloaded.\n");

}



/**
 * Method removes proc file and frees proc file buffer
 */
void procfile_exit(void)
{
  remove_proc_entry(FILENAME, NULL);
  vfree(procf_buffer);
  printk(KERN_INFO "MINIFW: /proc/%s removed\n", FILENAME);
}




/*********************** Hook functions ***********************/


/**************************************************************
 * Hook function triggered each time incoming packet comes
 * to the system
 **************************************************************/
unsigned int hook_func_in(unsigned int hooknum,          // one of the 5 hook types
			  struct sk_buff *skb,		 // pointer to the network packet buffer
			  const struct net_device *in,	 // pointer to the net_device structure
			  const struct net_device *out,	 // pointer to the net_device structure
			  int (*okfn)(struct sk_buff *)) // function pointer enables registering of a callback function triggered when all the functions registered with this hook returned NF_ACCEPT
{
  int i = 0;

  // pointers for a linked list
  struct list_head *p;
  struct rule_list_item *a_rule;

  // get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
  struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  // get src and dest ip addresses
  unsigned int src_ip = (unsigned int) ip_header->saddr;
  unsigned int dest_ip = (unsigned int) ip_header->daddr;
  unsigned int src_port = 0;
  unsigned int dest_port = 0;

  
  // get src and dest port number
  if (ip_header->protocol == 17) {
    udp_header = (struct udphdr *) (skb_transport_header(skb) + 20);
    src_port = (unsigned int) ntohs(udp_header->source);
    dest_port = (unsigned int) ntohs(udp_header->dest);
  } else if (ip_header->protocol == 6) {
    tcp_header = (struct tcphdr *) (skb_transport_header(skb) + 20);
    src_port = (unsigned int) ntohs(tcp_header->source);
    dest_port = (unsigned int) ntohs(tcp_header->dest);
  }

  iptoa(src_ip, ssrc_ip);
  iptoa(dest_ip, sdest_ip);	
  
  printk(KERN_INFO "IN packet info: src ip: %s, src port: %u; dest ip: %s, dest port: %u; proto: %u\n",
	 ssrc_ip, src_port, sdest_ip, 
	 dest_port, ip_header->protocol);

  // go through the firewall list and check if there is a match
  // in case there are multiple matches, take the first one
  list_for_each(p, &policy_list.list)
    {
      i++;
      a_rule = list_entry(p, struct rule_list_item, list);

      //printk(KERN_INFO "rule %d: ", i);
      //printk(KERN_INFO "a_rule->action=%u, a_rule->proto=%u, a_rule->in_out=%u\n", a_rule->action, a_rule->proto, a_rule->in_out);
      //printk(KERN_INFO "a_rule->src_ip=%u, a_rule->src_netmask=%u, a_rule->src_port=%u\n", a_rule->src_ip, a_rule->src_netmask, a_rule->src_port);
      //printk(KERN_INFO "a_rule->dest_ip=%u, a_rule->dest_netmask=%u, a_rule->dest_port=%u\n", a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port);
  
      // if a rule doesn't specify as "in", skip it
      if (a_rule->in_out != 1) {
	printk(KERN_INFO "rule %d (a_rule->out:%u) not match: in packet, rule doesn't specify as in\n",
	       i, a_rule->in_out);
	continue;
      } else {
	// check the protocol
	if ((a_rule->proto == 1) && (ip_header->protocol != 6)) {
	  printk(KERN_INFO "rule %d not match: rule-TCP, packet not TCP\n", i);
	  continue;
	} else if ((a_rule->proto == 2) && (ip_header->protocol != 17)) {
	  printk(KERN_INFO "rule %d not match: rule-UDP, packet not UDP\n", i);
	  continue;
	}

	// check the ip address
	if (a_rule->src_ip == 0) {
	  // if IP is NULL, skip it
	} else {
	  if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
	    printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
	    continue;
	  }
	}

	if (a_rule->dest_ip == 0) {
	  // if IP is NULL, skip it
	} else {
	  if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
	    printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
	    continue;
	  }
	}

	// check the port number
	if (a_rule->src_port == 0) {
	  // rule doesn't specify src port: match
	} else if (src_port != a_rule->src_port) {
	  printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
	  continue;
	}

	if (a_rule->dest_port == 0) {
	  //rule doens't specify dest port: match
	}
	else if (dest_port != a_rule->dest_port) {
	  printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
	  continue;
	}

	// a match is found: take action
	if (a_rule->action == 0) {
	  printk(KERN_INFO "A MATCH IS FOUND: %d, DROP THE PACKET\n", i);
	  printk(KERN_INFO "---------------------------------------\n");
	  return NF_DROP;
	} else {
	  printk(KERN_INFO "A MATCH IS FOUND: %d, DROP THE PACKET\n", i);
	  printk(KERN_INFO "---------------------------------------\n");
	  return NF_ACCEPT;
	}
      }
    }

  printk(KERN_INFO "no matching is found, accept the packet\n");
  printk(KERN_INFO "---------------------------------------\n");

  return NF_ACCEPT;
}

/**************************************************************
 * Hook function triggered each time outgoing packet leaves
 * the system
 **************************************************************/
unsigned int hook_func_out(unsigned int hooknum,
			   struct sk_buff *skb,
			   const struct net_device *in,
			   const struct net_device *out,
			   int (*okfn)(struct sk_buff *))
{

  // get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol
  struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;
  struct list_head *p;
  struct rule_list_item *a_rule;

  int i = 0;

  // get src and dest ip addresses
  unsigned int src_ip = (unsigned int) ip_header->saddr;
  unsigned int dest_ip = (unsigned int) ip_header->daddr;
  unsigned int src_port = 0;
  unsigned int dest_port = 0;
 
  // get src and dest port number
  if (ip_header->protocol == 17) {
    udp_header = (struct udphdr *) skb_transport_header(skb);
    src_port = (unsigned int) ntohs(udp_header->source);
    dest_port = (unsigned int) ntohs(udp_header->dest);
  } else if (ip_header->protocol == 6) {
    tcp_header = (struct tcphdr *) skb_transport_header(skb);
    src_port = (unsigned int) ntohs(tcp_header->source);
    dest_port = (unsigned int) ntohs(tcp_header->dest);
  }

  iptoa(src_ip, ssrc_ip);
  iptoa(dest_ip, sdest_ip);

  printk(KERN_INFO "OUT packet info: src ip: %s, src port: %u; dest ip: %s, dest port: %u; proto: %u\n",
	 ssrc_ip, src_port, sdest_ip, 
	 dest_port, ip_header->protocol);

  // go through the firewall list and check if there is a match
  // in case there are multiple matches, take the first one
  list_for_each(p, &policy_list.list)
    {
      i++;
      a_rule = list_entry(p, struct rule_list_item, list);

      //printk(KERN_INFO "rule %d: a_rule->out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; ", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port);
      //printk(KERN_INFO "a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);

      // if a rule doesn't specify as "out", skip it
      if (a_rule->in_out != 2) {
	printk(KERN_INFO "rule %d (a_rule->out: %u) not match: out packet, rule doesn't specify as out\n", 
	       i, a_rule->in_out);
	continue;
      } else {
	// check the protocol
	if ((a_rule->proto == 1) && (ip_header->protocol != 6)) {
	  printk(KERN_INFO "rule %d not match: rule-TCP, packet not TCP\n", i);
	  continue;
	} else if ((a_rule->proto == 2) && (ip_header->protocol != 17)) {
	  printk(KERN_INFO "rule %d not match: rule-UDP, packet not UDP\n", i);
	  continue;
	}

	// check the ip address
	if (a_rule->src_ip == 0) {
	  // rule doesn't specify ip: match
	} else {
	  if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
	    printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
	    continue;
	  }
	}

	if (a_rule->dest_ip == 0) {
	  // rule doesn't specify ip: match
	} else {
	  if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
	    printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
	    continue;
	  }
	}

	// check the port number
	if (a_rule->src_port == 0) {
	  // rule doesn't specify src port: match
	} else if (src_port != a_rule->src_port) {
	  printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
	  continue;
	}

	if (a_rule->dest_port == 0) {
	  // rule doens't specify dest port: match
	}

	else if (dest_port != a_rule->dest_port) {
	  printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
	  continue;
	}

	// a match is found: take action
	if (a_rule->action == 0) {
	  printk(KERN_INFO "A MATCH IS FOUND: %d, DROP THE PACKET\n", i);
	  printk(KERN_INFO "---------------------------------------\n");
	  return NF_DROP;
	} else {
	  printk(KERN_INFO "A MATCH IS FOUND: %d, DROP THE PACKET\n", i);
	  printk(KERN_INFO "---------------------------------------\n");
	  return NF_ACCEPT;
	}
      }
    }

  printk(KERN_INFO "no matching is found, accept the packet\n");
  printk(KERN_INFO "---------------------------------------\n");

  return NF_ACCEPT;
}

/**************************************************************
 * Method converts IP from unsigned int to C string
 **************************************************************/
void iptoa(unsigned int ip, char *str_ip)
{
  unsigned char ip_arr[4];

  ip_arr[0] = ip & 0xFF;
  ip_arr[1] = (ip >> 8) & 0xFF;
  ip_arr[2] = (ip >> 16) & 0xFF;
  ip_arr[3] = (ip >> 24) & 0xFF;
    
  sprintf(str_ip, "%d.%d.%d.%d", ip_arr[3], ip_arr[2], ip_arr[1], ip_arr[0]);        
}

/**************************************************************
 * Method checks two IP addresses to see if they match
 *
 **************************************************************/
bool check_ip(unsigned int ip, unsigned int ip_rule,
	      unsigned int mask)
{
  unsigned int tmp = ntohl(ip);    // network to host long
  int cmp_len = 32;
  int i = 0, j = 0;

  printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);
  if (mask != 0) {
    // printk(KERN_INFO "deal with mask\n");
    // printk(KERN_INFO "mask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);

    cmp_len = 0;
    for (i = 0; i < 32; ++i) {
      if (mask & (1 << (32 - 1 - i)))
	cmp_len++;
      else
	break;
    }
  }

  // compare the two IP addresses for the first cmp_len bits
  for (i = 31, j = 0; j < cmp_len; --i, ++j) {
    if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
      printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
      return false;
    }
  }
  return true;
}




/************************* proc fs stuff **********************/


/**************************************************************
 * Method gets called when someone from userland accesses the
 * proc file and READS from it. Till it returns 0, it will be
 * called infinite amount of times.
 *
 **************************************************************/
static ssize_t procfs_read(struct file *filp, char *buffer, size_t length,
			   loff_t * offset)
{
  static int finished = 0;
  int len;
  char *rules;

  if (finished)
    {
      printk(KERN_INFO "procfs_read: END\n");
      finished = 0;
      return 0; // eof
    }

  finished = 1;

  rules = list_to_string();

  printk(KERN_INFO "procfs_read: rules: %s\n", rules);
  printk(KERN_INFO "procfs_read: len of rules: %zu\n", strlen(rules));

  len = sprintf(buffer, "%s", rules);
  printk(KERN_INFO "procfs_read: returning len: %d\n", len);

  kfree(rules);

  return len;
}

/**
 * Method converts linked list to string. All the information
 * from the rules gets extracted and appended to the resulting
 * string.
 *
 * @return: the string representing all the rules
 */
char * list_to_string ( void )
{
  int count = 0;
  char * s;
  struct list_head * h;
  struct rule_list_item * r;
  
  list_for_each(h, &policy_list.list)
    {
      r = list_entry(h, struct rule_list_item, list);
      count++;
    }
  printk(KERN_INFO "procfs_read: found %d rules.\n", count);

  if (count != 0)
    s = kmalloc((sizeof(char) * count * 110), GFP_KERNEL);
  else
    s = kmalloc(sizeof(char), GFP_KERNEL);
  
  s[0] = '\0';

  list_for_each(h, &policy_list.list)
    {
      r = list_entry(h, struct rule_list_item, list);

      strcat(s, "ADDRULE ");

      //action
      if (r->action == 0) {
	strcat(s, "BLOCK ");
      } else if (r->action == 1) {
	strcat(s, "UNBLOCK ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);

      //in or out
      if (r->in_out == 1) {
	strcat(s, "IN ");
      } else if (r->in_out == 2) {
	strcat(s, "OUT ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //protocol
      if (r->proto == 0) {
	strcat(s, "ALL ");
      } else if (r->proto == 1) {
	strcat(s, "TCP ");
      } else if (r->proto == 2) {
	strcat(s, "UDP ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //src ip
      if (r->src_ip == 0) {
	strcat(s, "NULL ");
      } else {
	iptoa(r->src_ip, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //src netmask
      if (r->src_netmask == 0) {
	strcat(s, "NULL ");
      } else {
	iptoa(r->src_netmask, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //src port
      if (r->src_port == 0) {
	strcat(s, "NULL ");
      } else {
	port_int_to_str(r->src_port, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //dest ip
      if (r->dest_ip == 0) {
	strcat(s, "NULL ");
      } else {
	iptoa(r->dest_ip, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //dest netmask
      if (r->dest_netmask == 0) {
	strcat(s, "NULL ");
      } else {
	iptoa(r->dest_netmask, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      //printk(KERN_INFO "procfs_read: s: %s\n", s);
      
      //dest port
      if (r->src_port == 0) {
	strcat(s, "NULL ");
      } else {
	port_int_to_str(r->src_port, ssrc_ip);
	strcat(s, ssrc_ip);
	strcat(s, " ");
      }
      strcat(s, "\n");
      printk(KERN_INFO "procfs_read: s: %s\n", s);
    }
  return s;
}

/*
 * Method ports ip address from unsigned integer into the
 * C string.
 *
 * @port: integer value to port
 * @port_str: string that is filled with ip address
 */
void port_int_to_str(unsigned int port, char *port_str) {
  sprintf(port_str, "%u", port);
}


/**************************************************************
 * Method gets called when someone from userland accesses the
 * proc file and WRITES into it.
 *
 **************************************************************/
static ssize_t procfs_write(struct file *file, const char *buffer, size_t len,
			    loff_t * off)
{
  int status = 0;
  char c = '\0';

  // put the string passed from user into the buffer
  if (copy_from_user(&procf_buffer[0], buffer, len)) {
    return -EFAULT;
  }
  procf_buffer[len-1] = 0; // null terminate the string
  printk(KERN_INFO "rule from buffer: %s\n", procf_buffer);


  // check if we want to add of remove the rule (ADDRULE, RMRULE)
  c = procf_buffer[0];
  if (c == 'A')
    {
      status = add_rule();
      if (status)
	return status;
    }
  else if (c == 'R')
    {
      status = remove_rule();
      if (status)
	return status;
    }

  printk(KERN_INFO "--------------------\n");

  return len;
}


/**************************** Helper functions *****************************/

/**************************************************************
 * Method gets called if ADDRULE was passed from the user:
 *
 * 1) generate the rule based on the string in the buffer
 * 2) add rule to the linked list
 **************************************************************/
static ssize_t add_rule(void)
{
  ssize_t status;
  struct rule *a_rule;

  a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
  if (a_rule == NULL) {
    printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
    return -ENOMEM;
  }

  status = generate_rule_from_buffer(a_rule);
  if (status)
    return status;

  add_rule_to_list(a_rule);

  kfree(a_rule);

  return 0;
}

static ssize_t remove_rule(void)
{
  // TODO: implement remove rule function
  printk(KERN_INFO "whoops: havent implemented yet!\n");

  return 0;
}



/**************************************************************
 * Method generates the rule based on what is in the buffer.
 *
 **************************************************************/
static ssize_t generate_rule_from_buffer(struct rule *a_rule)
{
  int index = 0;

  // allocates memory for new rule
  init_rule(a_rule);

  // skip the white space
  while (procf_buffer[index] != ' ')
    index++;

  // get all the info from the buffer
  index = get_action(a_rule, index);
  index = get_in_out(a_rule, index);
  index = get_protocol(a_rule, index);
  index = get_src_ip(a_rule, index);
  index = get_src_mask(a_rule, index);
  index = get_src_port(a_rule, index);
  index = get_dest_ip(a_rule, index);
  index = get_dest_mask(a_rule, index);
  index = get_dest_port(a_rule, index);

  return 0;
}

/**************************************************************
 * Method allocates memory for all rule structure variables
 **************************************************************/
void init_rule(struct rule* a_rule) {

  a_rule->action = 0;
  a_rule->in_out = 0;
  a_rule->proto = 0;
  a_rule->src_ip = (char *) kmalloc(16, GFP_KERNEL);
  a_rule->src_netmask = (char *) kmalloc(16, GFP_KERNEL);
  a_rule->src_port = (char *) kmalloc(16, GFP_KERNEL);
  a_rule->dest_ip = (char *) kmalloc(16, GFP_KERNEL);
  a_rule->dest_netmask = (char *) kmalloc(16, GFP_KERNEL);
  a_rule->dest_port = (char *) kmalloc(16, GFP_KERNEL);

}

/**************************************************************
 * Method gets action from the buffer (BLOCK, UNBLOCK)
 **************************************************************/
int get_action(struct rule *a_rule, int i)
{
  char c = '\0';

  while (procf_buffer[i] == ' ')
    i++;

  c = procf_buffer[i];

  if (c == 'B')
    a_rule->action = 0;
  else if (c == 'U')
    a_rule->action = 1;

  while(procf_buffer[i] != ' ') // skip letters
    i++;

  //printk(KERN_INFO "action: %c, ", a_rule->action);

  return i;
}

/**************************************************************
 * Method gets type of the packet from the buffer (IN, OUT)
 **************************************************************/
int get_in_out(struct rule *a_rule, int i)
{
  char c;

  while (procf_buffer[i] == ' ')
    i++;

  c = procf_buffer[i];

  if (c == 'I')
    a_rule->in_out = 1;
  else if (c == 'O')
    a_rule->in_out = 2;

  // skip letters
  while(procf_buffer[i] != ' ')
    i++;

  //printk(KERN_INFO "in or out: %c, ", a_rule->in_out);

  return i;
}

/**************************************************************
 * Method gets protocol from the buffer (ALL, TCP, UDP)
 **************************************************************/
int get_protocol(struct rule *a_rule, int i)
{
  char c;

  while (procf_buffer[i] == ' ')
    i++;

  c = procf_buffer[i];

  if (c == 'A')
    a_rule->proto = 0;
  else if (c == 'T')
    a_rule->proto = 1;
  else if (c == 'U')
    a_rule->proto = 2;

  // skip letters
  while(procf_buffer[i] != ' ')
    i++;
  //printk(KERN_INFO "proto: %c, ", a_rule->proto);

  return i;
}

/**************************************************************
 * Method gets src ip from the buffer (NULL, 198.162.0.1, ...)
 **************************************************************/
int get_src_ip(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->src_ip);
      a_rule->src_ip = NULL;
      while (procf_buffer[i] != ' ')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ')
    a_rule->src_ip[j++] = procf_buffer[i++];

  a_rule->src_ip[j] = '\0';

  //printk(KERN_INFO "src ip: %s, ", a_rule->src_ip);

  return i;
}

/**************************************************************
 * Method gets src mask from the buffer (NULL, 255.255.0.0, ...)
 **************************************************************/
int get_src_mask(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->src_netmask);
      a_rule->src_netmask = NULL;
      while (procf_buffer[i] != ' ')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ')
    a_rule->src_netmask[j++] = procf_buffer[i++];

  a_rule->src_netmask[j] = '\0';

  //printk(KERN_INFO "src netmask: %s, ", a_rule->src_netmask);

  return i;
}

/**************************************************************
 * Method gets src port from the buffer (NULL, 80, ...)
 **************************************************************/
int get_src_port(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->src_port);
      a_rule->src_port = NULL;
      while (procf_buffer[i] != ' ')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ')
    a_rule->src_port[j++] = procf_buffer[i++];

  a_rule->src_port[j] = '\0';

  //printk(KERN_INFO "src_port: %s, ", a_rule->src_port);

  return i;
}

/**************************************************************
 * Method gets dest ip from the buffer (NULL, 198.162.0.1, ...)
 **************************************************************/
int get_dest_ip(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->dest_ip);
      a_rule->dest_ip = NULL;
      while (procf_buffer[i] != ' ')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ')
    a_rule->dest_ip[j++] = procf_buffer[i++];

  a_rule->dest_ip[j] = '\0';

  //printk(KERN_INFO "dest ip: %s, ", a_rule->dest_ip);

  return i;
}

/**************************************************************
 * Method gets dest mask from the buffer (NULL, 255.255.0.0, ...)
 **************************************************************/
int get_dest_mask(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->dest_netmask);
      a_rule->dest_netmask = NULL;
      while (procf_buffer[i] != ' ')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ')
    a_rule->dest_netmask[j++] = procf_buffer[i++];

  a_rule->dest_netmask[j] = '\0';

  //printk(KERN_INFO "dest netmask: %s, ", a_rule->dest_netmask);

  return i;
}

/**************************************************************
 * Method gets dest port from the buffer (NULL, 80, ...)
 **************************************************************/
int get_dest_port(struct rule *a_rule, int i)
{
  int j = 0;

  // skip white space
  while (procf_buffer[i] == ' ')
    i++;

  // check for NULL
  if (procf_buffer[i] == 'N')
    {
      kfree(a_rule->dest_port);
      a_rule->dest_port = NULL;
      while (procf_buffer[i] != '\0')
	i++;
      return i;
    }

  while (procf_buffer[i] != ' ' && procf_buffer[i] != '\0')
    a_rule->dest_port[j++] = procf_buffer[i++];

  a_rule->dest_port[j] = '\0';

  //printk(KERN_INFO "dest_port: %s\n", a_rule->dest_port);

  return i;
}

/**************************************************************
 * Method adds the rule to the linked list
 **************************************************************/
void add_rule_to_list(struct rule* a_rule) {

  struct rule_list_item* ll_rule;

  ll_rule = kmalloc(sizeof(*ll_rule), GFP_KERNEL);
  if (ll_rule == NULL) {
    printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
    return;
  }

  ll_rule->in_out = a_rule->in_out;
  ll_rule->src_ip = ip_str_to_hl(a_rule->src_ip);
  ll_rule->src_netmask = ip_str_to_hl(a_rule->src_netmask);
  ll_rule->src_port = port_str_to_int(a_rule->src_port);
  ll_rule->dest_ip = ip_str_to_hl(a_rule->dest_ip);
  ll_rule->dest_netmask = ip_str_to_hl(a_rule->dest_netmask);
  ll_rule->dest_port = port_str_to_int(a_rule->dest_port);
  ll_rule->proto = a_rule->proto;
  ll_rule->action = a_rule->action;

  printk(KERN_INFO "add_a_rule: action=%u, in_out=%u, proto=%u, src_ip=%u, src_netmask=%u\n",
	 ll_rule->action, ll_rule->in_out, ll_rule->proto, ll_rule->src_ip, ll_rule->src_netmask);
  printk(KERN_INFO "src_port=%u, dest_ip=%u, dest_netmask=%u, dest_port=%u\n",
	 ll_rule->src_port, ll_rule->dest_ip, ll_rule->dest_netmask, ll_rule->dest_port);

  // TODO: check if the rule already in the list

  INIT_LIST_HEAD(&(ll_rule->list));
  list_add_tail(&(ll_rule->list), &(policy_list.list));
}

/**************************************************************
 * Method converts the string with ip to host long integer
 * format
 **************************************************************/
unsigned int ip_str_to_hl(char *ip_str) {

  // convert the string to byte array first, e.g.:
  // from "131.132.162.25" to [131][132][162][25]
  unsigned char ip_array[4];
  int i = 0;
  unsigned int ip = 0;

  if (ip_str == NULL) {
    return 0;
  }

  memset(ip_array, 0, 4);

  while (ip_str[i] != '.') {
    ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
  }
  ++i;

  while (ip_str[i] != '.') {
    ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
  }
  ++i;

  while (ip_str[i] != '.') {
    ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
  }
  ++i;

  while (ip_str[i] != '\0') {
    ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
  }

  // convert from byte array to host long integer format
  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);

  printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
  return ip;

}

/**************************************************************
 * Method converts the string to integer
 **************************************************************/
unsigned int port_str_to_int(char *port_str) {

  unsigned int port = 0;
  int i = 0;

  if (port_str == NULL) {
    return 0;
  }

  while (port_str[i] != '\0') {
    port = port * 10 + (port_str[i] - '0');
    ++i;
  }

  return port;
}

