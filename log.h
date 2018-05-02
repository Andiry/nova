#ifndef __LOG_H
#define __LOG_H

#include "balloc.h"
#include "inode.h"

/* ======================= Log entry ========================= */
/* Inode entry in the log */

#define	MAIN_LOG	0
#define	ALTER_LOG	1

#define	PAGE_OFFSET_MASK	4095
#define	BLOCK_OFF(p)	((p) & ~PAGE_OFFSET_MASK)

#define	ENTRY_LOC(p)	((p) & PAGE_OFFSET_MASK)

#define	LOG_BLOCK_TAIL	4064
#define	PAGE_TAIL(p)	(BLOCK_OFF(p) + LOG_BLOCK_TAIL)

/*
 * Log page state and pointers to next page and the replica page
 */
struct nova_inode_page_tail {
	__le32	invalid_entries;
	__le32	num_entries;
	__le64	epoch_id;	/* For snapshot list page */
	__le64	padding;
	__le64	next_page;
} __attribute((__packed__));

/* Fit in PAGE_SIZE */
struct	nova_inode_log_page {
	char padding[LOG_BLOCK_TAIL];
	struct nova_inode_page_tail page_tail;
} __attribute((__packed__));

#define	EXTEND_THRESHOLD	256

enum nova_entry_type {
	FILE_WRITE = 1,
	DIR_LOG,
	SET_ATTR,
	LINK_CHANGE,
	NEXT_PAGE,
};

static inline u8 nova_get_entry_type(void *p)
{
	u8 type;
	int rc;

	rc = memcpy_mcsafe(&type, p, sizeof(u8));
	if (rc)
		return rc;

	return type;
}

static inline void nova_set_entry_type(void *p, enum nova_entry_type type)
{
	*(u8 *)p = type;
}

/*
 * Write log entry.  Records a write to a contiguous range of PMEM pages.
 *
 * Documentation/filesystems/nova.txt contains descriptions of some fields.
 */
struct nova_file_write_entry {
	u8	entry_type;
	u8	reassigned;	/* Data is not latest */
	u8	padding[2];
	__le32	num_pages;
	__le64	block;          /* offset of first block in this write */
	__le64	pgoff;          /* file offset at the beginning of this write */
	__le32	invalid_pages;	/* For GC */
	/* For both ctime and mtime */
	__le32	mtime;
	__le64	size;           /* Write size for non-aligned writes */
	__le64	epoch_id;
	__le64	trans_id;
	__le32	csum;
	__le32	counter;	/* Atomic counter for entry locking */
} __attribute((__packed__));

#define WENTRY(entry)	((struct nova_file_write_entry *) entry)

/* List of file write entries */
struct nova_file_write_item {
	struct nova_file_write_entry	entry;
	struct list_head		list;
	int				need_free; /* On heap or stack? */
};

/*
 * Log entry for adding a file/directory to a directory.
 *
 * Update DIR_LOG_REC_LEN if modify this struct!
 */
struct nova_dentry {
	u8	entry_type;
	u8	name_len;		/* length of the dentry name */
	u8	reassigned;		/* Currently deleted */
	u8	invalid;		/* Invalid now? */
	__le16	de_len;			/* length of this dentry */
	__le16	links_count;
	__le32	mtime;			/* For both mtime and ctime */
	__le32	csum;			/* entry checksum */
	__le64	ino;			/* inode no pointed to by this entry */
	__le64	padding;
	__le64	epoch_id;
	__le64	trans_id;
	char	name[NOVA_NAME_LEN + 1];	/* File name */
} __attribute((__packed__));

#define DENTRY(entry)	((struct nova_dentry *) entry)

#define NOVA_DIR_PAD			8	/* Align to 8 bytes boundary */
#define NOVA_DIR_ROUND			(NOVA_DIR_PAD - 1)
#define NOVA_DENTRY_HEADER_LEN		48
#define NOVA_DIR_LOG_REC_LEN(name_len) \
	(((name_len + 1) + NOVA_DENTRY_HEADER_LEN \
	 + NOVA_DIR_ROUND) & ~NOVA_DIR_ROUND)

#define NOVA_MAX_ENTRY_LEN		NOVA_DIR_LOG_REC_LEN(NOVA_NAME_LEN)

/*
 * Log entry for updating file attributes.
 */
struct nova_setattr_logentry {
	u8	entry_type;
	u8	attr;       /* bitmap of which attributes to update */
	__le16	mode;
	__le32	uid;
	__le32	gid;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
	__le64	size;        /* File size after truncation */
	__le64	epoch_id;
	__le64	trans_id;
	u8	invalid;
	u8	paddings[3];
	__le32	csum;
} __attribute((__packed__));

#define SENTRY(entry)	((struct nova_setattr_logentry *) entry)

/* Link change log entry.
 *
 * TODO: Do we need this to be 32 bytes?
 */
struct nova_link_change_entry {
	u8	entry_type;
	u8	invalid;
	__le16	links;
	__le32	ctime;
	__le32	flags;
	__le32	generation;    /* for NFS handles */
	__le64	epoch_id;
	__le64	trans_id;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define LCENTRY(entry)	((struct nova_link_change_entry *) entry)


/*
 * Transient DRAM structure that describes changes needed to append a log entry
 * to an inode
 */
struct nova_inode_update {
	u64 head;
	u64 tail;
	u64 curr_entry;
	struct nova_dentry *create_dentry;
	struct nova_dentry *delete_dentry;
};


/*
 * Transient DRAM structure to parameterize the creation of a log entry.
 */
struct nova_log_entry_info {
	enum nova_entry_type type;
	struct iattr *attr;
	struct nova_inode_update *update;
	void *data;	/* struct dentry */
	u64 epoch_id;
	u64 trans_id;
	u64 curr_p;	/* output */
	u64 file_size;	/* de_len for dentry */
	u64 ino;
	u32 time;
	int link_change;
	int inplace;	/* For file write entry */
};



static inline size_t nova_get_log_entry_size(struct super_block *sb,
	enum nova_entry_type type)
{
	size_t size = 0;

	switch (type) {
	case FILE_WRITE:
		size = sizeof(struct nova_file_write_entry);
		break;
	case DIR_LOG:
		size = NOVA_DENTRY_HEADER_LEN;
		break;
	case SET_ATTR:
		size = sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		size = sizeof(struct nova_link_change_entry);
		break;
	default:
		break;
	}

	return size;
}

static inline void nova_persist_entry(void *entry)
{
	size_t entry_len = CACHELINE_SIZE;

	nova_flush_buffer(entry, entry_len, 0);
}

static inline u64 next_log_page(struct super_block *sb, u64 curr)
{
	struct nova_inode_log_page *curr_page;
	u64 next = 0;
	int rc;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	rc = memcpy_mcsafe(&next, &curr_page->page_tail.next_page,
				sizeof(u64));
	if (rc)
		return rc;

	return next;
}

static inline void nova_set_next_page_flag(struct super_block *sb, u64 curr_p)
{
	void *p;

	if (ENTRY_LOC(curr_p) >= LOG_BLOCK_TAIL)
		return;

	p = nova_get_block(sb, curr_p);
	nova_set_entry_type(p, NEXT_PAGE);
	nova_flush_buffer(p, CACHELINE_SIZE, 1);
}

static inline void nova_set_next_page_address(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 next_page, int fence)
{
	curr_page->page_tail.next_page = next_page;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
	if (fence)
		PERSISTENT_BARRIER();
}

static inline void nova_set_page_num_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.num_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_set_page_invalid_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.invalid_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_inc_page_num_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.num_entries++;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_inc_page_invalid_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.invalid_entries++;
	if (curr_page->page_tail.invalid_entries >
			curr_page->page_tail.num_entries) {
		nova_dbg("Page 0x%llx has %u entries, %u invalid\n",
				curr,
				curr_page->page_tail.num_entries,
				curr_page->page_tail.invalid_entries);
	}

	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline bool is_last_entry(u64 curr_p, size_t size)
{
	unsigned int entry_end;

	entry_end = ENTRY_LOC(curr_p) + size;

	return entry_end > LOG_BLOCK_TAIL;
}

static inline bool goto_next_page(struct super_block *sb, u64 curr_p)
{
	void *addr;
	u8 type;
	int rc;

	/* Each kind of entry takes at least 32 bytes */
	if (ENTRY_LOC(curr_p) + 32 > LOG_BLOCK_TAIL)
		return true;

	addr = nova_get_block(sb, curr_p);
	rc = memcpy_mcsafe(&type, addr, sizeof(u8));

	if (rc < 0)
		return true;

	if (type == NEXT_PAGE)
		return true;

	return false;
}

static inline int is_dir_init_entry(struct super_block *sb,
	struct nova_dentry *entry)
{
	if (entry->name_len == 1 && strncmp(entry->name, ".", 1) == 0)
		return 1;
	if (entry->name_len == 2 && strncmp(entry->name, "..", 2) == 0)
		return 1;

	return 0;
}

/*
 * counter definition
 * - if == 0 then there are no active readers or writers.
 * - if > 0 then that is the number of active readers.
 * - if == -1 then there is one active writer.
 */
static inline int get_write_entry(struct nova_file_write_entry *entry)
{
	atomic_t *counter = (atomic_t *)&entry->counter;
	int ret = atomic_add_unless(counter, 1, -1);

	return ret;
}

/* Return true if the counter fell to zero */
static inline int put_write_entry(struct nova_file_write_entry *entry)
{
	atomic_t *counter = (atomic_t *)&entry->counter;
	int ret = atomic_dec_and_test(counter);

	return ret;
}

static inline int lock_write_entry(struct nova_file_write_entry *entry)
{
	atomic_t *counter = (atomic_t *)&entry->counter;
	int ret = atomic_cmpxchg(counter, 0, -1);

	return ret;
}

static inline void unlock_write_entry(struct nova_file_write_entry *entry)
{
	atomic_t *counter = (atomic_t *)&entry->counter;
	atomic_inc(counter);
}


unsigned int nova_free_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	unsigned long pgoff, unsigned int num_free,
	bool delete_dead, u64 epoch_id);
struct nova_file_write_entry *nova_find_next_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, pgoff_t pgoff);
int nova_handle_setattr_operation(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, unsigned int ia_valid, struct iattr *attr,
	u64 epoch_id);
int nova_invalidate_link_change_entry(struct super_block *sb,
	u64 old_link_change);
int nova_append_link_change_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_update *update, u64 *old_linkc, u64 epoch_id);
int nova_inplace_update_write_entry(struct super_block *sb,
	struct inode *inode, struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info);
int nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_item *item,
	struct nova_inode_update *update);
int nova_assign_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	bool free);
int nova_invalidate_dentries(struct super_block *sb,
	struct nova_inode_update *update);
int nova_inplace_update_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry, int link_change,
	u64 epoch_id);
int nova_append_dentry(struct super_block *sb, struct nova_inode *pi,
	struct inode *dir, struct dentry *dentry, u64 ino,
	unsigned short de_len, struct nova_inode_update *update,
	int link_change, u64 epoch_id);
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail);
u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended);
int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head);
int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih);

/* stats.c */
void nova_print_curr_log_page(struct super_block *sb, u64 curr);
void nova_print_nova_log(struct super_block *sb,
	struct nova_inode_info_header *sih);
void nova_print_nova_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih);

#endif
