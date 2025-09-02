/* 1. Every open request on a file containing the extended attribute ```user.secure``` should be denied.
2. If such a request happened, the requesting process should be marked as ```tainted```.
3. All requests to remove extended attributes by a process marked ```tainted``` (or one of its descendants) on a file containing the extended attribute ```user.secure``` should be denied.
4. Your module has to be cleanly unloadable - no memory leaks!
5. Everything has to be appropriately synchronized, your module should not be subject to race-conditions */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/errno.h>

#include <security/mac/mac_policy.h>

#define ATTR_NAMESPACE  EXTATTR_NAMESPACE_USER
#define ATTR_NAME       "secure"

MALLOC_DEFINE(M_TAINT, "mac_secure_taint", "tainted-process list");

/* ---------- taint tracking ---------- */
struct taint_entry {
    LIST_ENTRY(taint_entry) link;
    pid_t pid;
};

static LIST_HEAD(, taint_entry) taint_head = LIST_HEAD_INITIALIZER(taint_head);
static struct rwlock taint_lock;  /* protects taint_head */

/* Check if the given process is tainted  */
static bool
proc_is_tainted(struct proc *p){
    struct taint_entry *te;
    bool tainted = false;

    rw_rlock(&taint_lock);
    LIST_FOREACH(te, &taint_head, link) {
        if (te->pid == p->p_pid) {
            tainted = true;
            break;
        }
    }
    rw_runlock(&taint_lock);
    return (tainted);
}


/* Check whether the process or any of its ancestors is tainted. */
static bool
proc_or_ancestor_is_tainted(struct proc *p) {
    while (p != NULL) {
        if (proc_is_tainted(p))
            return true;
        p = p->p_pptr; //把当前进程 p 替换为它的父进程（parent process），也就是 “往上一层”。
    }
    return false;
}

/* Mark a process as tainted by inserting it into the taint list. */
static void
proc_mark_tainted(struct proc *p){
    struct taint_entry *te;

    if (proc_is_tainted(p)) return;

    te = malloc(sizeof(*te), M_TAINT, M_WAITOK | M_ZERO);
    te->pid = p->p_pid;

    rw_wlock(&taint_lock);
    LIST_INSERT_HEAD(&taint_head, te, link);
    rw_wunlock(&taint_lock);
}

/* Check whether a vnode (file) has the 'user.secure' extended attribute. */
static bool
vnode_has_secure(struct vnode *vp){
    char dummy;
    int buflen = 1;
    int error;

    error = vn_extattr_get(vp,
                           IO_NODELOCKED,
                           ATTR_NAMESPACE,
                           ATTR_NAME,
                           &buflen,
                           &dummy,
                           curthread);

    return (error == 0);
}

/* ---------- MAC hooks ---------- */

/* Deny open on files with 'user.secure' attribute.
Also mark the calling process as tainted. */
static int
secure_vnode_check_open(struct ucred *cred, struct vnode *vp,
                        struct label *vplabel, accmode_t accmode){
    if (vnode_has_secure(vp)) {
        if (!proc_is_tainted(curproc))
            proc_mark_tainted(curproc);
        return (EPERM);
    }
    return (0);
}

/* Deny setting 'user.secure' attribute if the process or ancestors are tainted. */
/* static int
secure_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
                              struct label *vplabel, int attrnamespace,
                              const char *name){
    if (attrnamespace == ATTR_NAMESPACE &&
        name != NULL && strcmp(name, ATTR_NAME) == 0) {
        if (proc_or_ancestor_is_tainted(curproc) && vnode_has_secure(vp)) {
            return (EPERM);
        }
    }
    return (0);
} */

/* Deny deleting 'user.secure' attribute if the process or ancestors are tainted. */
static int
secure_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
                                 struct label *vplabel, int attrnamespace,
                                 const char *name) {
    if (attrnamespace == ATTR_NAMESPACE &&
        name != NULL && strcmp(name, ATTR_NAME) == 0) {
        if (proc_or_ancestor_is_tainted(curproc) && vnode_has_secure(vp)) {
            return (EPERM);
        }
    }
    return (0);
}



static void
secure_policy_init(struct mac_policy_conf *conf){
    rw_init(&taint_lock, "mac_secure taint lock");
}

 
/* MAC policy module cleanup: free all taint entries and destroy lock. */

static void
secure_policy_destroy(struct mac_policy_conf *conf ){
    struct taint_entry *te;

    rw_wlock(&taint_lock);
    while ((te = LIST_FIRST(&taint_head)) != NULL) {
        LIST_REMOVE(te, link);
        free(te, M_TAINT);
    }
    rw_wunlock(&taint_lock);
    rw_destroy(&taint_lock);
}

static struct mac_policy_ops secure_ops = {
    .mpo_init                     = secure_policy_init,
    .mpo_destroy                  = secure_policy_destroy,
    .mpo_vnode_check_open         = secure_vnode_check_open,
    // .mpo_vnode_check_setextattr   = secure_vnode_check_setextattr,
    .mpo_vnode_check_deleteextattr = secure_vnode_check_deleteextattr,
};

MAC_POLICY_SET(&secure_ops, mac_secure, "Deny open/remove user.secure",
               MPC_LOADTIME_FLAG_UNLOADOK, NULL);


