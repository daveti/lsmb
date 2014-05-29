/*
 * lsmb.c
 * Linux Security Module Basics
 * Some toy example playing with LSM
 * Based on Greg Kroah-Hartman's Root Plug sample LSM module
 * May 19, 2014
 * daveti@cs.uoregon.edu
 * http://davejingtian.org
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>

/* Threshold for counters */
#define COUNTER_THRESHOLD 1

/* flag to keep track of how we were registered */
static int secondary;

/* Counters used to suppress the logging */
static unsigned long ptrace_counter;
static unsigned long capget_counter;
static unsigned long capset_check_counter;
static unsigned long capset_set_counter;
static unsigned long acct_counter;
static unsigned long capable_counter;
static unsigned long sys_security_counter;
static unsigned long quotactl_counter;
static unsigned long quota_on_counter;
/*********************************/
static unsigned long bprm_alloc_security_counter;
static unsigned long bprm_free_security_counter;
static unsigned long bprm_compute_creds_counter;
static unsigned long bprm_set_security_counter;
static unsigned long bprm_check_security_counter;
/*********************************/
static unsigned long sb_alloc_security_counter;
static unsigned long sb_free_security_counter;
static unsigned long sb_statfs_counter;
static unsigned long sb_mount_counter;
static unsigned long sb_check_sb_counter;
static unsigned long sb_umount_counter;
static unsigned long sb_umount_close_counter;
static unsigned long sb_umount_busy_counter;
static unsigned long sb_post_remount_counter;
static unsigned long sb_post_mountroot_counter;
static unsigned long sb_post_addmount_counter;
static unsigned long sb_pivotroot_counter;
static unsigned long sb_post_pivotroot_counter;
/***********************************/
static unsigned long inode_alloc_security_counter;
static unsigned long inode_free_security_counter;
static unsigned long inode_create_counter;
static unsigned long inode_post_create_counter;
static unsigned long inode_link_counter;
static unsigned long inode_post_link_counter;
static unsigned long inode_unlink_counter;
static unsigned long inode_symlink_counter;
static unsigned long inode_post_symlink_counter;
static unsigned long inode_mkdir_counter;
static unsigned long inode_post_mkdir_counter;
static unsigned long inode_rmdir_counter;
static unsigned long inode_mknod_counter;
static unsigned long inode_post_mknod_counter;
static unsigned long inode_rename_counter;
static unsigned long inode_post_rename_counter;
static unsigned long inode_readlink_counter;
static unsigned long inode_follow_link_counter;
static unsigned long inode_permission_counter;
static unsigned long inode_permission_lite_counter;
static unsigned long inode_setattr_counter;
static unsigned long inode_getattr_counter;
static unsigned long inode_post_lookup_counter;
static unsigned long inode_delete_counter;
static unsigned long inode_setxattr_counter;
static unsigned long inode_getxattr_counter;
static unsigned long inode_listxattr_counter;
static unsigned long inode_removexattr_counter;
/*************************************/
static unsigned long file_permission_counter;
static unsigned long file_alloc_security_counter;
static unsigned long file_free_security_counter;
static unsigned long file_llseek_counter;
static unsigned long file_ioctl_counter;
static unsigned long file_mmap_counter;
static unsigned long file_mprotect_counter;
static unsigned long file_lock_counter;
static unsigned long file_fcntl_counter;
static unsigned long file_set_fowner_counter;
static unsigned long file_send_sigiotask_counter;
static unsigned long file_receive_counter;
/**************************************/
static unsigned long task_create_counter;
static unsigned long task_alloc_security_counter;
static unsigned long task_free_security_counter;
static unsigned long task_setuid_counter;
static unsigned long task_post_setuid_counter;
static unsigned long task_setgid_counter;
static unsigned long task_setpgid_counter;
static unsigned long task_getpgid_counter;
static unsigned long task_getsid_counter;
static unsigned long task_setgroups_counter;
static unsigned long task_setnice_counter;
static unsigned long task_setrlimit_counter;
static unsigned long task_setscheduler_counter;
static unsigned long task_getscheduler_counter;
static unsigned long task_wait_counter;
static unsigned long task_kill_counter;
static unsigned long task_prctl_counter;
static unsigned long task_kmod_set_label_counter;
static unsigned long task_reparent_to_init_counter;
static unsigned long register_security_counter;
static unsigned long unregister_security_counter;

/* LSM hook implementations here */
static int lsmb_ptrace (struct task_struct *parent,
			    struct task_struct *child)
{
	return 0;
}

static int lsmb_capget (struct task_struct *target,
			    kernel_cap_t *effective,
			    kernel_cap_t *inheritable,
			    kernel_cap_t *permitted)
{
	return 0;
}

static int lsmb_capset_check (struct task_struct *target,
				  kernel_cap_t *effective,
				  kernel_cap_t *inheritable,
				  kernel_cap_t *permitted)
{
	return 0;
}

static void lsmb_capset_set (struct task_struct *target,
				 kernel_cap_t *effective,
				 kernel_cap_t *inheritable,
				 kernel_cap_t *permitted)
{
	return;
}

static int lsmb_acct (struct file *file)
{
	return 0;
}

static int lsmb_capable (struct task_struct *tsk, int cap)
{
	if (cap_is_fs_cap (cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		/* capability granted */
		return 0;

	/* capability denied */
	return -EPERM;
}

static int lsmb_sys_security (unsigned int id, unsigned int call,
				  unsigned long *args)
{
	return -ENOSYS;
}

static int lsmb_quotactl (int cmds, int type, int id,
			      struct super_block *sb)
{
	return 0;
}

static int lsmb_quota_on (struct file *f)
{
	return 0;
}

static int lsmb_bprm_alloc_security (struct linux_binprm *bprm)
{
	return 0;
}

static void lsmb_bprm_free_security (struct linux_binprm *bprm)
{
	return;
}

static void lsmb_bprm_compute_creds (struct linux_binprm *bprm)
{
	return;
}

static int lsmb_bprm_set_security (struct linux_binprm *bprm)
{
	return 0;
}

static int lsmb_sb_alloc_security (struct super_block *sb)
{
	return 0;
}

static void lsmb_sb_free_security (struct super_block *sb)
{
	return;
}

static int lsmb_sb_statfs (struct super_block *sb)
{
	return 0;
}

static int lsmb_mount (char *dev_name, struct nameidata *nd, char *type,
			   unsigned long flags, void *data)
{
	return 0;
}

static int lsmb_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	return 0;
}

static int lsmb_umount (struct vfsmount *mnt, int flags)
{
	return 0;
}

static void lsmb_umount_close (struct vfsmount *mnt)
{
	return;
}

static void lsmb_umount_busy (struct vfsmount *mnt)
{
	return;
}

static void lsmb_post_remount (struct vfsmount *mnt, unsigned long flags,
				   void *data)
{
	return;
}

static void lsmb_post_mountroot (void)
{
	return;
}

static void lsmb_post_addmount (struct vfsmount *mnt,
				    struct nameidata *nd)
{
	return;
}

static int lsmb_pivotroot (struct nameidata *old_nd,
			       struct nameidata *new_nd)
{
	return 0;
}

static void lsmb_post_pivotroot (struct nameidata *old_nd,
				     struct nameidata *new_nd)
{
	return;
}

static int lsmb_inode_alloc_security (struct inode *inode)
{
	return 0;
}

static void lsmb_inode_free_security (struct inode *inode)
{
	return;
}

static int lsmb_inode_create (struct inode *inode,
				  struct dentry *dentry,
				  int mask)
{
	return 0;
}

static void lsmb_inode_post_create (struct inode *inode,
					struct dentry *dentry,
					int mask)
{
	return;
}

static int lsmb_inode_link (struct dentry *old_dentry,
				struct inode *inode,
				struct dentry *new_dentry)
{
	return 0;
}

static void lsmb_inode_post_link (struct dentry *old_dentry,
				      struct inode *inode,
				      struct dentry *new_dentry)
{
	return;
}

static int lsmb_inode_unlink (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int lsmb_inode_symlink (struct inode *inode, struct dentry *dentry,
				   const char *name)
{
	return 0;
}

static void lsmb_inode_post_symlink (struct inode *inode,
					 struct dentry *dentry,
					 const char *name)
{
	return;
}

static int lsmb_inode_mkdir (struct inode *inode,
				 struct dentry *dentry,
				 int mask)
{
	return 0;
}

static void lsmb_inode_post_mkdir (struct inode *inode,
				       struct dentry *dentry,
				       int mask)
{
	return;
}

static int lsmb_inode_rmdir (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int lsmb_inode_mknod (struct inode *inode, struct dentry *dentry,
				 int major, dev_t minor)
{
	return 0;
}

static void lsmb_inode_post_mknod (struct inode *inode,
				       struct dentry *dentry,
				       int major, dev_t minor)
{
	return;
}

static int lsmb_inode_rename (struct inode *old_inode,
				  struct dentry *old_dentry,
				  struct inode *new_inode,
				  struct dentry *new_dentry)
{
	return 0;
}

static void lsmb_inode_post_rename (struct inode *old_inode,
					struct dentry *old_dentry,
					struct inode *new_inode,
					struct dentry *new_dentry)
{
	return;
}

static int lsmb_inode_readlink (struct dentry *dentry)
{
	return 0;
}

static int lsmb_inode_follow_link (struct dentry *dentry,
				       struct nameidata *nameidata)
{
	return 0;
}

static int lsmb_inode_permission (struct inode *inode, int mask)
{
	return 0;
}

static int lsmb_inode_permission_lite (struct inode *inode, int mask)
{
	return 0;
}

static int lsmb_inode_setattr (struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int lsmb_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void lsmb_post_lookup (struct inode *ino, struct dentry *d)
{
	return;
}

static void lsmb_delete (struct inode *ino)
{
	return;
}

static int lsmb_inode_setxattr (struct dentry *dentry, char *name,
				    void *value, size_t size, int flags)
{
	return 0;
}

static int lsmb_inode_getxattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int lsmb_inode_listxattr (struct dentry *dentry)
{
	return 0;
}

static int lsmb_inode_removexattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int lsmb_file_permission (struct file *file, int mask)
{
	if (file_permission_counter < COUNTER_THRESHOLD) {
		printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
		file_permission_counter++;
	}

	return 0;
}

static int lsmb_file_alloc_security (struct file *file)
{
	if (file_alloc_security_counter < COUNTER_THRESHOLD) {
		printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
		file_alloc_security_counter++;
	}

	return 0;
}

static void lsmb_file_free_security (struct file *file)
{
	if (file_free_security_counter < COUNTER_THRESHODL) {
		printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
		file_free_security_counter++;
	}

	return;
}

static int lsmb_file_llseek (struct file *file)
{
        if (file_llseek_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_llseek_counter++;
        }

	return 0;
}

static int lsmb_file_ioctl (struct file *file, unsigned int command,
				unsigned long arg)
{
        if (file_ioctl_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_ioctl_counter++;
        }

	return 0;
}

static int lsmb_file_mmap (struct file *file, unsigned long prot,
			       unsigned long flags)
{
        if (file_mmap_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_mmap_counter++;
        }

	return 0;
}

static int lsmb_file_mprotect (struct vm_area_struct *vma,
				   unsigned long prot)
{
        if (file_mprotect_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_mprotect_counter++;
        }

	return 0;
}

static int lsmb_file_lock (struct file *file, unsigned int cmd)
{
        if (file_lock_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_lock_counter++;
        }

	return 0;
}

static int lsmb_file_fcntl (struct file *file, unsigned int cmd,
				unsigned long arg)
{
        if (file_fcntl_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_fcntl_counter++;
        }

	return 0;
}

static int lsmb_file_set_fowner (struct file *file)
{
        if (file_set_fowner_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_set_fowner_counter++;
        }

	return 0;
}

static int lsmb_file_send_sigiotask (struct task_struct *tsk,
					 struct fown_struct *fown,
					 int fd, int reason)
{
        if (file_send_sigiotask < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_send_sigiotask++;
        }

	return 0;
}

static int lsmb_file_receive (struct file *file)
{
        if (file_receive_counter < COUNTER_THRESHOLD) {
                printk(KERN_INFO "lsmb: into [%s]\n", __FUNCTION__);
                file_receive_counter++;
        }

	return 0;
}

static int lsmb_task_create (unsigned long clone_flags)
{
	return 0;
}

static int lsmb_task_alloc_security (struct task_struct *p)
{
	return 0;
}

static void lsmb_task_free_security (struct task_struct *p)
{
	return;
}

static int lsmb_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int lsmb_task_post_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int lsmb_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return 0;
}

static int lsmb_task_setpgid (struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int lsmb_task_getpgid (struct task_struct *p)
{
	return 0;
}

static int lsmb_task_getsid (struct task_struct *p)
{
	return 0;
}

static int lsmb_task_setgroups (int gidsetsize, gid_t * grouplist)
{
	return 0;
}

static int lsmb_task_setnice (struct task_struct *p, int nice)
{
	return 0;
}

static int lsmb_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int lsmb_task_setscheduler (struct task_struct *p, int policy,
				       struct sched_param *lp)
{
	return 0;
}

static int lsmb_task_getscheduler (struct task_struct *p)
{
	return 0;
}

static int lsmb_task_wait (struct task_struct *p)
{
	return 0;
}

static int lsmb_task_kill (struct task_struct *p,
			       struct siginfo *info,
			       int sig)
{
	return 0;
}

static int lsmb_task_prctl (int option,
				unsigned long arg2,
				unsigned long arg3,
				unsigned long arg4,
				unsigned long arg5)
{
	return 0;
}

static void lsmb_task_kmod_set_label (void)
{
	return;
}

static void lsmb_task_reparent_to_init (struct task_struct *p)
{
	p->euid = p->fsuid = 0;
	return;
}

static int lsmb_register (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}

static int lsmb_unregister (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}

/* should we print out debug messages */
static int debug = 0;

MODULE_PARM(debug, "i");
MODULE_PARM_DESC(debug, "Debug enabled or not");

#if defined(CONFIG_SECURITY_ROOTPLUG_MODULE)
#define MY_NAME THIS_MODULE->name
#else
#define MY_NAME "lsmb"
#endif

#define dbg(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG "%s: %s: " fmt ,	\
				MY_NAME , __FUNCTION__ , 	\
				## arg);			\
	} while (0)

static int lsmb_bprm_check_security (struct linux_binprm *bprm)
{
	dbg ("file %s, e_uid = %d, e_gid = %d\n",
	     bprm->filename, bprm->e_uid, bprm->e_gid);

	return 0;
}


static struct security_operations lsmb_security_ops = {
       .ptrace =                       lsmb_ptrace,
       .capget =                       lsmb_capget,
       .capset_check =                 lsmb_capset_check,
       .capset_set =                   lsmb_capset_set,
       .acct =                         lsmb_acct,
       .capable =                      lsmb_capable,
       .sys_security =                 lsmb_sys_security,
       .quotactl =                     lsmb_quotactl,
       .quota_on =                     lsmb_quota_on,

       .bprm_alloc_security =          lsmb_bprm_alloc_security,
       .bprm_free_security =           lsmb_bprm_free_security,
       .bprm_compute_creds =           lsmb_bprm_compute_creds,
       .bprm_set_security =            lsmb_bprm_set_security,
       .bprm_check_security =          lsmb_bprm_check_security,

       .sb_alloc_security =            lsmb_sb_alloc_security,
       .sb_free_security =             lsmb_sb_free_security,
       .sb_statfs =                    lsmb_sb_statfs,
       .sb_mount =                     lsmb_mount,
       .sb_check_sb =                  lsmb_check_sb,
       .sb_umount =                    lsmb_umount,
       .sb_umount_close =              lsmb_umount_close,
       .sb_umount_busy =               lsmb_umount_busy,
       .sb_post_remount =              lsmb_post_remount,
       .sb_post_mountroot =            lsmb_post_mountroot,
       .sb_post_addmount =             lsmb_post_addmount,
       .sb_pivotroot =                 lsmb_pivotroot,
       .sb_post_pivotroot =            lsmb_post_pivotroot,
       
       .inode_alloc_security =         lsmb_inode_alloc_security,
       .inode_free_security =          lsmb_inode_free_security,
       .inode_create =                 lsmb_inode_create,
       .inode_post_create =            lsmb_inode_post_create,
       .inode_link =                   lsmb_inode_link,
       .inode_post_link =              lsmb_inode_post_link,
       .inode_unlink =                 lsmb_inode_unlink,
       .inode_symlink =                lsmb_inode_symlink,
       .inode_post_symlink =           lsmb_inode_post_symlink,
       .inode_mkdir =                  lsmb_inode_mkdir,
       .inode_post_mkdir =             lsmb_inode_post_mkdir,
       .inode_rmdir =                  lsmb_inode_rmdir,
       .inode_mknod =                  lsmb_inode_mknod,
       .inode_post_mknod =             lsmb_inode_post_mknod,
       .inode_rename =                 lsmb_inode_rename,
       .inode_post_rename =            lsmb_inode_post_rename,
       .inode_readlink =               lsmb_inode_readlink,
       .inode_follow_link =            lsmb_inode_follow_link,
       .inode_permission =             lsmb_inode_permission,
       .inode_permission_lite =        lsmb_inode_permission_lite,
       .inode_setattr =                lsmb_inode_setattr,
       .inode_getattr =                lsmb_inode_getattr,
       .inode_post_lookup =            lsmb_post_lookup,
       .inode_delete =                 lsmb_delete,
       .inode_setxattr =               lsmb_inode_setxattr,
       .inode_getxattr =               lsmb_inode_getxattr,
       .inode_listxattr =              lsmb_inode_listxattr,
       .inode_removexattr =            lsmb_inode_removexattr,

       .file_permission =              lsmb_file_permission,
       .file_alloc_security =          lsmb_file_alloc_security,
       .file_free_security =           lsmb_file_free_security,
       .file_llseek =                  lsmb_file_llseek,
       .file_ioctl =                   lsmb_file_ioctl,
       .file_mmap =                    lsmb_file_mmap,
       .file_mprotect =                lsmb_file_mprotect,
       .file_lock =                    lsmb_file_lock,
       .file_fcntl =                   lsmb_file_fcntl,
       .file_set_fowner =              lsmb_file_set_fowner,
       .file_send_sigiotask =          lsmb_file_send_sigiotask,
       .file_receive =                 lsmb_file_receive,

       .task_create =                  lsmb_task_create,
       .task_alloc_security =          lsmb_task_alloc_security,
       .task_free_security =           lsmb_task_free_security,
       .task_setuid =                  lsmb_task_setuid,
       .task_post_setuid =             lsmb_task_post_setuid,
       .task_setgid =                  lsmb_task_setgid,
       .task_setpgid =                 lsmb_task_setpgid,
       .task_getpgid =                 lsmb_task_getpgid,
       .task_getsid =                  lsmb_task_getsid,
       .task_setgroups =               lsmb_task_setgroups,
       .task_setnice =                 lsmb_task_setnice,
       .task_setrlimit =               lsmb_task_setrlimit,
       .task_setscheduler =            lsmb_task_setscheduler,
       .task_getscheduler =            lsmb_task_getscheduler,
       .task_wait =                    lsmb_task_wait,
       .task_kill =                    lsmb_task_kill,
       .task_prctl =                   lsmb_task_prctl,
       .task_kmod_set_label =          lsmb_task_kmod_set_label,
       .task_reparent_to_init =        lsmb_task_reparent_to_init,

       .register_security =            lsmb_register,
       .unregister_security =          lsmb_unregister,
};

static int __init lsmb_init(void)
{
       /* register ourselves with the security framework */
       if (register_security (&lsmb_security_ops)) {
               printk (KERN_INFO 
                       "Failure registering lsmb module with the kernel\n");
               /* try registering with primary module */
               if (mod_reg_security (MY_NAME, &lsmb_security_ops)) {
                       printk (KERN_INFO "Failure registering lsmb "
                               " module with primary security module.\n");
                       return -EINVAL;
               }
               secondary = 1;
       }
       printk (KERN_INFO "lsmb module initialized\n");

       return 0;
}

static void __exit lsmb_exit (void)
{
       /* remove ourselves from the security framework */
       if (secondary) {
               if (mod_unreg_security (MY_NAME, &lsmb_security_ops))
                       printk (KERN_INFO "Failure unregistering lsmb "
                               " module with primary module.\n");
       } else { 
               if (unregister_security (&lsmb_security_ops)) {
                       printk (KERN_INFO "Failure unregistering lsmb "
                               "module with the kernel\n");
               }
       }
       printk (KERN_INFO "lsmb module removed\n");
}

module_init(lsmb_init);
module_exit(lsmb_exit);

MODULE_DESCRIPTION("lsmb kernel module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("daveti")
